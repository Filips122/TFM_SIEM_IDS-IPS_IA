# Production Pipeline Initial Results

Fecha: 2026-06-02

## Estado De Implementacion

Se inicio la arquitectura operacional descrita en `PRODUCTION_PIPELINE_STEPS.md`.

Archivos creados:

```text
src/models/PRODUCTION_PIPELINE/
  schemas.py
  model_registry.py
  router.py
  risk_scoring.py
  threshold_optimizer.py
  archive_model.py
  compare_archived_models.py
  calibrate_model.py
  build_active_registry.py
  siem_export.py
  batch_inference.py
  cic_gru_inference.py
  cic_gru_threshold_optimizer.py
  csr_entity_day_evaluator.py
  model_registry.example.json
```

La primera pieza ejecutable es `threshold_optimizer.py`, que carga artefactos HGB (`model.joblib` + `label_map.json`), reconstruye el split con el `data_loader` del dataset y calcula politicas de umbral para produccion.

Tambien se implemento un model store versionado dentro de `src/models/PRODUCTION_PIPELINE/model_store`. La primera linea base contiene 6 modelos archivados y 3 variantes calibradas, con comparativa generada automaticamente en:

```text
src/models/PRODUCTION_PIPELINE/comparisons/production_model_comparison.md
src/models/PRODUCTION_PIPELINE/comparisons/production_model_comparison.csv
```

El registro activo seleccionado desde el store se genera en:

```text
src/models/PRODUCTION_PIPELINE/active_model_registry.json
src/models/PRODUCTION_PIPELINE/active_model_registry.md
```

## Threshold Sweeps Ejecutados

Los umbrales se seleccionaron en validacion y se aplicaron sobre test.

| Dataset | Modelo | Threshold | Test precision | Test recall | Test F1 | Test accuracy | Alert rate | Decision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| LAB-ALERTS | HGB binario `date` | 0.0743 | 0.9181 | 0.9874 | 0.9515 | 0.9381 | 0.6615 | Candidato claro. |
| UNSW-NB15 | HGB binario `groupkfold/fold_0` | 0.6485 | 0.9698 | 0.8935 | 0.9301 | 0.9957 | 0.0292 | Candidato precision-first; recall queda justo bajo 0.90. |
| UGR16 | HGB binario `date` | 0.5594 | 0.9254 | 0.8649 | 0.8941 | 0.8976 | 0.4673 | Muy cerca, pero no strict +90/+90. |
| COWRIE_FULL | HGB multiclass `date` | 0.0100 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | No valido como detector binario; no hay clase BENIGN. |

## Lectura Operacional

1. LAB-ALERTS ya cumple el objetivo de produccion para el laboratorio SIEM: precision, recall y F1 superan 0.90 en test.
2. UNSW-NB15 tiene F1 alto y precision muy alta, pero el umbral elegido por validacion deja recall en 0.8935. Es aceptable como politica precision-first, pero no cumple estrictamente `precision >= 0.90` y `recall >= 0.90` a la vez con ese threshold.
3. UGR16 confirma que el reto no es solo threshold: el mejor umbral validado queda en F1 0.8941. Para pasar +90 necesita tuning, calibracion, features temporales adicionales o politica por subdominio.
4. COWRIE_FULL debe mantenerse como modelo multiclass de taxonomia, no como detector binario de benigno/ataque en esta version, porque el split multiclass no contiene BENIGN.

## Model Store Y Comparacion Base

Modelos base archivados:

| Modelo archivado | Rol | Estado |
| --- | --- | --- |
| `hgb_lab_alerts_binary_date_20260520_181715` | SIEM lab binario | Candidato claro. |
| `hgb_unsw_binary_groupkfold0_20260520_135042` | Tabular robusto | Candidato precision-first. |
| `hgb_ugr16_binary_date_20260520_151846` | Temporal/drift | Cerca, necesita mejora. |
| `hgb_cowrie_multiclass_date_20260520_182459` | Honeypot multiclass | Taxonomia, no detector binario. |
| `gru_cic_day_20260520_145849` | CIC secuencial | Pendiente adaptador especifico. |
| `isoforest_csr_entity_day_20260531_002323_fold0` | CSR triage SOC | Evaluacion entity-day/top-k. |

Variantes calibradas archivadas:

| Modelo base | Metodo | Precision | Recall | F1 | Raw test ECE | Calibrated test ECE | Decision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| LAB-ALERTS HGB | isotonic | 0.9181 | 0.9874 | 0.9515 | 0.0213 | 0.0413 | No mejora test ECE ni F1. |
| UNSW-NB15 HGB | sigmoid | 0.9703 | 0.8930 | 0.9300 | 0.0007 | 0.0017 | No mejora; base queda mejor. |
| UGR16 HGB | sigmoid | 0.9241 | 0.8672 | 0.8948 | 0.0864 | 0.0613 | Mejora ECE y F1 levemente, pero sigue bajo +0.90 F1. |

Lectura: calibracion mejora la interpretabilidad en UGR16, pero no resuelve por si sola el objetivo `F1 >= 0.90`. Para LAB y UNSW la calibracion probada no debe sustituir al modelo base.

## Registro Activo Actual

| Dominio | Modelo activo | Razon |
| --- | --- | --- |
| `siem_lab_alerts` | LAB HGB base `20260520_181715` | La calibracion isotonic no mejora F1 y empeora ECE test. |
| `network_tabular` | UNSW HGB base `20260520_135042/fold_0` | El sigmoid calibrado no mejora F1 ni ECE test. |
| `network_temporal` | UGR16 HGB sigmoid calibrado `20260602_ugr16_sigmoid` | Mejora ligeramente F1 y ECE test, aunque sigue bajo +0.90 F1. |
| `network_sequence` | CIC GRU day `20260520_145849` + politica independiente threshold `0.005` | Candidato activo con P 0.9739, R 0.9383, F1 0.9558 en holdout. |
| `entity_day_triage` | CSR IsolationForest `20260531_002323/fold_0` | Mantener evaluacion SOC entity-day/top-k. |
| `honeypot` | COWRIE HGB multiclass `20260520_182459` | Usar como taxonomia, no como detector binario. |

## Exportacion SIEM Inicial

Se implemento `siem_export.py` para transformar una decision de modelo en JSON orientado a SIEM. Usa el `active_model_registry`, aplica `risk_score` y genera campos como:

- `event.kind`, `event.category`, `event.dataset`;
- `ml.model_id`, `ml.score`, `ml.threshold`, `ml.prediction`, `ml.risk_score`, `ml.severity`;
- `rule.name`, `labels.pipeline`, `related.hosts` y `entity.id`.

Ejemplo generado:

```text
src/models/PRODUCTION_PIPELINE/examples/lab_alert_siem_event.json
```

## Inferencia Batch Y Adaptadores

Se añadieron tres piezas para pasar de resultados archivados a inferencia reutilizable:

| Script | Dominio | Funcion |
| --- | --- | --- |
| `batch_inference.py` | HGB/sklearn LAB, UNSW, UGR16, COWRIE | Carga modelo activo, aplica calibrador si existe, puntua un split y exporta JSONL SIEM. |
| `cic_gru_inference.py` | CIC-IDS2017 secuencial | Carga `best_model.pt`, `x_mean.npy`, `x_std.npy`, reconstruye GRU y exporta JSONL SIEM. |
| `cic_gru_threshold_optimizer.py` | CIC-IDS2017 secuencial | Barre thresholds con seleccion en validacion y evaluacion en test. |
| `csr_entity_day_evaluator.py` | CSR-LANL SOC triage | Puntua ventanas con IsolationForest, agrega por `(entity, day)`, calcula top-k/daily-budget y exporta entity-days SIEM. |

Validaciones ejecutadas:

| Script | Muestra | Resultado principal | Lectura |
| --- | ---: | --- | --- |
| LAB `batch_inference.py` | 500 filas test | P 0.9187, R 0.9871, F1 0.9516 | Reproduce el comportamiento esperado del candidato LAB. |
| CIC `cic_gru_inference.py` | 500 secuencias test | P 0.9520, R 0.5484, F1 0.6959 con threshold 0.5 | El modelo tiene ROC-AUC alto, pero necesita threshold tuning especifico. |
| CIC `cic_gru_threshold_optimizer.py` | 2,000 val / 2,000 test | Val contiene solo 7 positivos; seleccion por validacion inestable | El day split no es suficiente para fijar umbral robusto del GRU sin politica adicional. |
| CSR `csr_entity_day_evaluator.py` | 50,000 ventanas test | 2,208 entity-days; first attack rank 9; top-10 cubre 3/3 ventanas de ataque en la muestra | Validado como evaluacion SOC entity-day/top-k, no F1 fila a fila. |
| HGB `batch_inference.py` | Test completo | LAB P 0.9181/R 0.9874/F1 0.9515; UNSW P 0.9698/R 0.8935/F1 0.9301; UGR16 P 0.9241/R 0.8672/F1 0.8948 | Baseline completo `full_hgb_active_20260602`. |
| CSR `csr_entity_day_evaluator.py` | 400,000 ventanas test | 2,308 entity-days; first attack rank 3; top-10 cubre 32/34 ventanas de ataque (0.9412) | Baseline completo `full_csr_active_20260602`. |
| `summarize_production_baseline.py` | Registry activo + summaries | Genera `production_baseline_summary.csv` y `.md` | Tabla unica para comparar mejoras futuras. |
| Artefactos SIEM | JSONL -> Filebeat/Elastic | `siem_ingestion/README.md`, config Filebeat y template Elastic | Ingesta preparada; pendiente validacion contra SIEM real. |
| `run_active_inference.py` | Router operativo | Valida rutas HGB, CIC GRU y CSR desde `active_model_registry.json` | Punto de entrada comun para inferencia activa. |
| `soc_alert_policy.production.json` | Politica SOC | Deduplicacion 15 min, budgets por dominio y respuesta automatica deshabilitada por defecto | Control de ruido y respuesta segura. |
| `apply_soc_policy.py` | Post-procesado SOC | Aplica politica a JSONL y genera `*_soc_filtered.jsonl` + `*_soc_summary.json` | UGR/UNSW bajan de 5,000 a 500 eventos exportados por rate limit de modelo. |

Validacion completa CIC GRU (`full_cic_gru_stable_policy`):

| Politica | Seleccion en validacion | Resultado en test | Lectura |
| --- | --- | --- | --- |
| `best_f1` en `day/val` | threshold 0.0000; F1 val 0.0105 | P 0.4377, R 1.0000, F1 0.6089 | No operativo: equivale a alertar todo. |
| `benign_fpr_0.005` | threshold 0.9997; FPR benigno val 0.0050 | P 0.9958, R 0.4403, F1 0.6106 | Precision muy alta, recall insuficiente. |
| `benign_fpr_0.05` | threshold 0.9758; FPR benigno val 0.0500 | P 0.9891, R 0.4644, F1 0.6320 | Sigue recall bajo. |
| `alert_rate_0.10` | threshold 0.5566; alert rate val 0.1000 | P 0.9840, R 0.5459, F1 0.7022 | Mejora recall, pero no llega a objetivo. |
| Oracle test `best_f1` | threshold 0.0050 | P 0.9718, R 0.9221, F1 0.9463 | Diagnostico solamente; no se puede usar como politica de produccion. |

Conclusion CIC: el GRU contiene senal predictiva fuerte, pero el split `day/val` no permite seleccionar un threshold transferible al test. Para produccion no se debe promover el umbral oracle; hay que crear una validacion temporal mas representativa o una calibracion por dia/escenario.

Validacion representativa CIC GRU (`full_cic_gru_trainval_calibration`):

| Politica | Seleccion en `train+val` estratificado | Resultado en test | Lectura |
| --- | --- | --- | --- |
| `precision_at_least_0.90` | threshold 0.0050; P 0.9607, R 0.9909, F1 0.9756 | P 0.9718, R 0.9221, F1 0.9463 | Candidato provisional: cumple +90/+90/+90. |
| `benign_fpr_0.05` | threshold 0.000032; P 0.9520, R 0.9918, F1 0.9715 | P 0.9392, R 0.9901, F1 0.9640 | Recall-first, mas alertas: alert rate test 0.4614. |
| `benign_fpr_0.005` | threshold 0.9973; P 0.9949, R 0.9850, F1 0.9899 | P 0.9923, R 0.4454, F1 0.6149 | Demasiado conservador para Friday-test. |

Lectura metodologica: esta calibracion no usa test para seleccionar threshold, pero incluye filas de `train`, que ya participaron en entrenamiento del GRU. Por tanto, el threshold 0.005 queda como politica de desarrollo prometedora, no como evidencia final independiente. La siguiente validacion defendible es crear un split de calibracion independiente o reentrenar CIC con `train/calibration/test` mas representativo.

Politica versionada creada:

```text
src/models/PRODUCTION_PIPELINE/policies/cic_gru_threshold_policy_development.json
```

El adaptador `cic_gru_inference.py` acepta `--policy_json` para usar esta politica sin pasar el umbral manualmente. Smoke con 2,000 secuencias test: P 0.9741, R 0.9219, F1 0.9473.

Split CIC independiente creado (`day_independent_calibration`):

```text
src/models/CIC-IDS2017/datasets/sequence/day_independent_calibration/TrafficLabelling/binary/
```

El split mantiene `train` y `val` originales mediante hardlinks y divide el Friday original en shards completos disjuntos:

| Split | BENIGN | ATTACK | Uso |
| --- | ---: | ---: | --- |
| `train` | 1,272,276 | 266,469 | Entrenamiento futuro. |
| `val` | 414,890 | 2,197 | Early stopping/validacion auxiliar. |
| `calibration` | 131,801 | 86,224 | Seleccion independiente de threshold. |
| `test` | 239,333 | 202,642 | Holdout independiente. |

Validacion independiente CIC GRU (`full_cic_gru_independent_calibration`):

| Politica | Seleccion en calibration | Resultado en test holdout | Lectura |
| --- | --- | --- | --- |
| `precision_at_least_0.90` | threshold 0.0050; P 0.9665, R 0.8839, F1 0.9233 | P 0.9739, R 0.9383, F1 0.9558 | Candidato independiente principal. |
| `benign_fpr_0.05` | threshold 0.000021; P 0.9283, R 0.9896, F1 0.9580 | P 0.9365, R 0.9912, F1 0.9631 | Recall-first, mayor alert rate 0.4853. |
| `benign_fpr_0.01` | threshold 0.1603; P 0.9701, R 0.4957, F1 0.6561 | P 0.9843, R 0.7252, F1 0.8351 | Precision alta, recall insuficiente. |

Politica independiente versionada:

```text
src/models/PRODUCTION_PIPELINE/policies/cic_gru_threshold_policy_independent.json
```

Smoke con `--policy_json` sobre `day_independent_calibration/test` y 2,000 secuencias: P 0.9694, R 0.9538, F1 0.9616.

Registro activo actualizado:

```text
src/models/PRODUCTION_PIPELINE/policy_registry.active.json
src/models/PRODUCTION_PIPELINE/active_model_registry.json
src/models/PRODUCTION_PIPELINE/active_model_registry.md
```

La entrada activa CIC queda con status `production_candidate_independent_threshold`, threshold `0.005` y `policy_path` apuntando a `cic_gru_threshold_policy_independent.json`. Smoke usando solo `active_model_registry` sin pasar `--policy_json`: P 0.9694, R 0.9538, F1 0.9616 sobre 2,000 secuencias del holdout.

Archivos de inferencia y resumen generados bajo:

```text
src/models/PRODUCTION_PIPELINE/inference_runs/
src/models/PRODUCTION_PIPELINE/threshold_runs/
src/models/PRODUCTION_PIPELINE/production_baseline_summary.csv
src/models/PRODUCTION_PIPELINE/production_baseline_summary.md
src/models/PRODUCTION_PIPELINE/siem_ingestion/
src/models/PRODUCTION_PIPELINE/run_active_inference.py
src/models/PRODUCTION_PIPELINE/policies/soc_alert_policy.production.json
src/models/PRODUCTION_PIPELINE/apply_soc_policy.py
src/models/PRODUCTION_PIPELINE/soc_policy_application_summary.md
```

## Comandos Ejecutados

LAB-ALERTS:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\threshold_optimizer.py `
  --artifact_dir src/models/LAB-ALERTS/artifacts/offline_LAB_ALERTS_binary_hgb/date/20260520_181715 `
  --dataset_key LAB-ALERTS `
  --min_precision 0.90 `
  --min_recall 0.90 `
  --threshold_steps 199
```

UGR16:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\threshold_optimizer.py `
  --artifact_dir src/models/UGR16/artifacts/offline_UGR16_binary_hgb/UGR16_MARAPR_HYBRID/date/20260520_151846 `
  --dataset_key UGR16 `
  --min_precision 0.90 `
  --min_recall 0.90 `
  --threshold_steps 199
```

UNSW-NB15:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\threshold_optimizer.py `
  --artifact_dir src/models/UNSW-NB15/artifacts/offline_NUSW_binary_hgb/groupkfold/20260520_135042/fold_0 `
  --dataset_key UNSW-NB15 `
  --split_mode groupkfold `
  --fold 0 `
  --min_precision 0.90 `
  --min_recall 0.90 `
  --threshold_steps 199
```

COWRIE_FULL:

```powershell
.\.venv\Scripts\python.exe src\models\PRODUCTION_PIPELINE\threshold_optimizer.py `
  --artifact_dir src/models/COWRIE_FULL/artifacts/offline_COWRIE_FULL_multiclass_hgb/date/20260520_182459 `
  --dataset_key COWRIE_FULL `
  --pipeline multiclass `
  --min_precision 0.90 `
  --min_recall 0.90 `
  --threshold_steps 199
```

## Siguientes Pasos Practicos

1. Probar la ingesta JSONL contra Elastic/Wazuh en laboratorio usando `siem_ingestion/`.
2. Validar el router comun con ejecuciones completas orquestadas desde `run_active_inference.py`.
3. Probar en Elastic/Wazuh los JSONL filtrados `*_soc_filtered.jsonl` y validar reglas de correlacion/dashboards.
4. Para evidencia final, reentrenar GRU con el split `day_independent_calibration` y comparar contra el modelo actual.
5. Comparar el baseline especialista contra GLOBAL_TRANSFORMER como experimento auxiliar.