# Production Pipeline Model Store

Fecha: 2026-06-02

## Objetivo

Guardar dentro de `PRODUCTION_PIPELINE` cada modelo candidato junto con sus resultados, umbrales, configuracion y metadatos. Esto permite comparar futuras aplicaciones, calibraciones o reentrenamientos contra una linea base congelada.

La regla principal es:

> Ningun modelo candidato se sobrescribe. Cada mejora se archiva como una version nueva y se compara contra versiones anteriores.

## Estructura

```text
src/models/PRODUCTION_PIPELINE/
  model_store/
    <model_id>/
      <version>/
        manifest.json
        model/
        metadata/
        metrics/
        thresholds/
  comparisons/
    production_model_comparison.csv
    production_model_comparison.md
```

## Manifest

Cada version archivada contiene un `manifest.json` con:

- identificacion: `model_id`, `version`, `domain`, `dataset_key`, `model_type`;
- trazabilidad: ruta original, ruta archivada, fecha de archivado;
- configuracion: `pipeline`, `split_mode`, `fold`, `threshold`, `status`;
- resultados extraidos: precision, recall, F1, accuracy, alert rate;
- advertencias metodologicas, por ejemplo lectura binaria trivial en COWRIE;
- lista de archivos copiados.

Para modelos PyTorch/secuenciales, el store tambien conserva los artefactos necesarios de inferencia, como `best_model.pt`, `x_mean.npy` y `x_std.npy`.

## Comandos

Archivar todos los modelos del registro ejemplo:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\archive_model.py `
  --registry src/models/PRODUCTION_PIPELINE/model_registry.example.json `
  --overwrite
```

Comparar modelos archivados:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\compare_archived_models.py
```

Generar registro activo desde el store:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\build_active_registry.py
```

El generador aplica tambien politicas activas declaradas en:

```text
src/models/PRODUCTION_PIPELINE/policy_registry.active.json
```

Exportar una decision como JSON SIEM:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\siem_export.py `
  --model_id hgb_lab_alerts_binary_date_20260520_181715 `
  --probability_attack 0.93 `
  --entity_id lab-host-01 `
  --ids_severity 0.6 `
  --asset_criticality 0.7 `
  --correlation_score 0.4 `
  --output src/models/PRODUCTION_PIPELINE/examples/lab_alert_siem_event.json
```

Ejecutar inferencia batch HGB/sklearn y exportar JSONL SIEM:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\batch_inference.py `
  --model_id hgb_lab_alerts_binary_date_20260520_181715 `
  --split test `
  --max_rows_per_split 500 `
  --max_events 20 `
  --run_id smoke_lab_hgb
```

Ejecutar baseline HGB completo con modelos activos:

```powershell
$runId = "full_hgb_active_20260602"
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\batch_inference.py --model_id hgb_lab_alerts_binary_date_20260520_181715 --split test --run_id $runId --max_events 5000
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\batch_inference.py --model_id hgb_unsw_binary_groupkfold0_20260520_135042 --split test --run_id $runId --max_events 5000
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\batch_inference.py --model_id hgb_ugr16_binary_date_20260520_151846_sigmoid_calibrated_20260602_ugr16_sigmoid --split test --run_id $runId --max_events 5000
```

Ejecutar adaptador CIC GRU:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\cic_gru_inference.py `
  --split test `
  --max_rows 500 `
  --max_events 20 `
  --run_id smoke_cic_gru `
  --device cpu
```

Optimizar threshold CIC GRU con seleccion en validacion:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\cic_gru_threshold_optimizer.py `
  --max_rows 2000 `
  --threshold_steps 100 `
  --run_id smoke_cic_gru_threshold `
  --device cpu
```

Nota: el smoke detecto pocos positivos en validacion, por lo que el threshold del GRU no debe promoverse sin una politica de validacion mas estable.

Validacion completa CIC GRU con politicas estables:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\cic_gru_threshold_optimizer.py `
  --threshold_steps 199 `
  --run_id full_cic_gru_stable_policy `
  --device cpu `
  --batch_size 8192
```

Resultado: las politicas seleccionadas en `day/val` no alcanzan recall suficiente en test, aunque el oracle de test indique que el modelo tiene senal fuerte. Por tanto, el GRU CIC queda como candidato pendiente de validacion/calibracion mas representativa.

Calibracion representativa CIC GRU desde `train+val` estratificado:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\cic_gru_threshold_optimizer.py `
  --selection_source train_val_stratified `
  --calibration_attack_rows 50000 `
  --calibration_benign_rows 50000 `
  --threshold_steps 199 `
  --run_id full_cic_gru_trainval_calibration `
  --device cpu `
  --batch_size 8192
```

Resultado principal: `precision_at_least_0.90` selecciona threshold `0.0050` sin usar test y obtiene en test P 0.9718, R 0.9221 y F1 0.9463. Advertencia: esta politica usa filas de entrenamiento para calibrar, por lo que debe archivarse como candidato de desarrollo y confirmarse con un split de calibracion independiente.

La politica queda versionada en:

```text
src/models/PRODUCTION_PIPELINE/policies/cic_gru_threshold_policy_development.json
```

Usar la politica desde inferencia CIC:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\cic_gru_inference.py `
  --split test `
  --policy_json src/models/PRODUCTION_PIPELINE/policies/cic_gru_threshold_policy_development.json `
  --run_id smoke_cic_gru_policy_json `
  --device cpu
```

Crear split CIC independiente de calibracion/test:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\create_cic_independent_calibration_split.py `
  --target_mode day_independent_calibration `
  --calibration_ratio 0.30 `
  --file_mode hardlink `
  --overwrite
```

Validar threshold en calibration independiente y test holdout:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\cic_gru_threshold_optimizer.py `
  --selection_source split `
  --selection_split_mode day_independent_calibration `
  --selection_split calibration `
  --test_split_mode day_independent_calibration `
  --test_split test `
  --threshold_steps 199 `
  --run_id full_cic_gru_independent_calibration `
  --device cpu `
  --batch_size 8192
```

Resultado principal: threshold `0.0050` seleccionado en `calibration` obtiene en holdout test P 0.9739, R 0.9383 y F1 0.9558. La politica independiente esta en:

```text
src/models/PRODUCTION_PIPELINE/policies/cic_gru_threshold_policy_independent.json
```

La politica se registra como activa mediante `policy_registry.active.json`. Al regenerar `active_model_registry`, CIC queda con status `production_candidate_independent_threshold`, threshold `0.0050` y `policy_path` trazable.

Ejecutar evaluador CSR entity-day/top-k:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\csr_entity_day_evaluator.py `
  --split test `
  --max_rows 50000 `
  --event_policy daily_budget `
  --event_daily_budget 25 `
  --max_events 50 `
  --run_id smoke_csr_entity_day
```

Ejecutar CSR completo y generar resumen del baseline activo:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\csr_entity_day_evaluator.py `
  --split test `
  --run_id full_csr_active_20260602 `
  --topk 10,25,50,100,500,1000 `
  --daily_budgets 5,10,25,50 `
  --event_policy daily_budget `
  --event_daily_budget 25 `
  --max_events 5000

.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\summarize_production_baseline.py
```

Salidas principales:

```text
src/models/PRODUCTION_PIPELINE/production_baseline_summary.csv
src/models/PRODUCTION_PIPELINE/production_baseline_summary.md
```

Preparar ingesta SIEM JSONL con Filebeat/Elastic:

```text
src/models/PRODUCTION_PIPELINE/siem_ingestion/README.md
src/models/PRODUCTION_PIPELINE/siem_ingestion/filebeat.production_pipeline.example.yml
src/models/PRODUCTION_PIPELINE/siem_ingestion/elastic_index_template.production_pipeline.json
```

Ejecutar inferencia activa mediante router comun:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\run_active_inference.py `
  --model_id hgb_lab_alerts_binary_date_20260520_181715 `
  --split test `
  --run_id router_lab_test

.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\run_active_inference.py `
  --model_id gru_cic_day_20260520_145849 `
  --split test `
  --split_mode day_independent_calibration `
  --run_id router_cic_test `
  --device cpu

.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\run_active_inference.py `
  --model_id isoforest_csr_entity_day_20260531_002323_fold0 `
  --split test `
  --run_id router_csr_test
```

Politica SOC de control de ruido/respuesta:

```text
src/models/PRODUCTION_PIPELINE/policies/soc_alert_policy.production.json
```

Aplicar politica SOC a un JSONL de eventos:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\apply_soc_policy.py `
  --input_jsonl src/models/PRODUCTION_PIPELINE/inference_runs/hgb_ugr16_binary_date_20260520_151846_sigmoid_calibrated_20260602_ugr16_sigmoid/full_hgb_active_20260602/test_events.jsonl
```

Resumen de aplicacion actual:

```text
src/models/PRODUCTION_PIPELINE/soc_policy_application_summary.md
```

Archivar un unico modelo:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\archive_model.py `
  --registry src/models/PRODUCTION_PIPELINE/model_registry.example.json `
  --model_id hgb_ugr16_binary_date_20260520_151846
```

## Politica De Comparacion

Para modelos binarios se comparan principalmente:

- precision;
- recall;
- F1;
- accuracy;
- alert rate;
- threshold elegido en validacion;
- advertencias.

Para modelos que no son binarios clasicos:

- COWRIE_FULL se mantiene como taxonomia multiclass;
- CSR-LANL se evalua por entity-day/top-k, no por F1 fila a fila;
- CIC GRU requiere adaptador especifico para secuencias.

## Uso En Futuras Mejoras

Cada vez que se implemente calibracion, tuning o un modelo nuevo:

1. ejecutar evaluacion/threshold/calibracion;
2. actualizar o crear entrada en un registry;
3. archivar con `archive_model.py`;
4. regenerar comparativa;
5. decidir si mejora, empeora o cambia el trade-off precision/recall.

## Estado Actual

El store contiene 9 manifests archivados:

- 6 modelos base desde `model_registry.example.json`;
- 3 variantes calibradas: LAB isotonic, UNSW sigmoid y UGR16 sigmoid.

La comparativa principal se genera en:

```text
src/models/PRODUCTION_PIPELINE/comparisons/production_model_comparison.md
src/models/PRODUCTION_PIPELINE/comparisons/production_model_comparison.csv
```

El registro activo seleccionado desde el store se genera en:

```text
src/models/PRODUCTION_PIPELINE/active_model_registry.json
src/models/PRODUCTION_PIPELINE/active_model_registry.md
```

Resultado de calibracion inicial:

- LAB isotonic: F1 igual, ECE test peor;
- UNSW sigmoid: F1 practicamente igual, ECE test peor;
- UGR16 sigmoid: F1 sube muy poco y ECE test mejora, pero no llega a +0.90 F1.