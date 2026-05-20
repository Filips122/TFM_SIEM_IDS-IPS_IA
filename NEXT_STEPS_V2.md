# NEXT STEPS V2 - CSR-LANL

Este documento define las implementaciones necesarias para convertir CSR-LANL en un experimento defendible para la tesis. El problema principal ya no es preparar el dataset ni entrenar modelos basicos: el problema es que la evaluacion fila-a-fila no representa bien el objetivo operacional de deteccion red-team.

## Diagnostico actual

El flujo CSR-LANL ya dispone de un dataset `redteam_centered`, metadata de preparacion, validacion previa y comparativas latest-only. Sin embargo, los resultados actuales indican que el planteamiento de clasificacion tradicional no es suficiente.

Resultado observado en `date` sobre `datasets_redteam` con `source_set=auth_flow`:

- Test: 2,575,431 ventanas.
- Ataques en test: 38 ventanas red-team.
- HGB binario: accuracy cercana a 1.0, `macro_f1=0.499996`, recall ATTACK igual a 0.0.
- HGB multiclass: detecta 2 de 38 ventanas `RedTeamAuth`, con muchos falsos positivos.
- Isolation Forest: PR-AUC extremadamente baja, alrededor de 0.000677.
- `groupkfold` no es defendible en su forma actual porque algunos folds tienen 1 ataque en test.

Conclusion: CSR-LANL no debe evaluarse como un benchmark clasico de clasificacion por fila. Debe evaluarse como un sistema de priorizacion operacional: dado un presupuesto limitado de alertas, debe responder si las ventanas o entidades red-team aparecen entre los elementos mas sospechosos.

## Objetivo de la siguiente fase

Implementar una evaluacion SOC-oriented para CSR-LANL basada en ranking de riesgo, top-k, presupuesto de alertas y recall red-team por entidad/ventana/dia.

La pregunta principal pasa a ser:

```text
Si el analista solo puede revisar las N ventanas o entidades mas sospechosas por dia, aparece actividad red-team?
```

## P0 - Congelar la lectura actual

Estado: pendiente.

Implementaciones:

- Actualizar `NEXT_STEPS.md` o el informe final con la lectura actual de CSR-LANL.
- Marcar las metricas de accuracy de CSR-LANL como no defendibles para decision final.
- Mantener las comparativas latest-only como soporte, pero no usar `accuracy` como metrica principal.
- Documentar que `groupkfold` actual tiene soporte insuficiente de positivos y se considera no concluyente.

Artefactos esperados:

- Tabla de resultados CSR-LANL con columnas `split`, `sampling_profile`, `source_set`, `attack_windows_test`, `macro_f1`, `pr_auc`, `attack_recall` y `metric_warning`.
- Nota metodologica indicando que CSR-LANL requiere evaluacion operacional.

Criterio de aceptacion:

- Ninguna conclusion de CSR-LANL se basa solo en accuracy.

## P1 - Cargar metadata junto con features

Estado: pendiente.

Archivos a modificar:

- `src/models/CSR-LANL/data_loader.py`

Implementaciones:

- Anadir una funcion nueva, sin romper los trainers existentes:

```python
def load_split_frame(...):
    """Load the full parquet split with features, target and metadata."""
```

- La funcion debe devolver un `DataFrame` completo con:
  - `target`,
  - `window_start`,
  - `window_end`,
  - `entity`,
  - `redteam_exact`,
  - `redteam_near`,
  - `redteam_roles`,
  - `source_families`,
  - todas las `feature_columns`.
- Anadir una funcion auxiliar:

```python
def frame_to_xy_meta(df, feature_cols):
    return X, y, meta
```

- Mantener `load_splits()` compatible con el codigo actual.

Artefactos esperados:

- Tests manuales o smoke checks que carguen `train`, `val` y `test` sin perder metadata.

Criterio de aceptacion:

- Los trainers existentes siguen funcionando sin cambios.
- El nuevo evaluador puede acceder a `entity` y `window_start` para cada score.

## P2 - Evaluador operacional CSR-LANL

Estado: pendiente.

Archivo nuevo:

- `src/models/CSR-LANL/evaluate_operational.py`

Implementaciones:

- Cargar un artefacto entrenado y su modelo `joblib`.
- Cargar `val` y `test` desde `datasets_redteam`.
- Calcular un score de riesgo por ventana:
  - HGB binario: probabilidad de `ATTACK`.
  - HGB multiclass: suma de probabilidades de clases distintas de `BENIGN`.
  - Isolation Forest: `-model.score_samples(X)`.
- Calibrar la politica de seleccion usando `val`, no `test`.
- Aplicar la politica seleccionada a `test`.

Argumentos recomendados:

```text
--artifact_dir
--datasets_base
--dataset
--split_mode
--fold
--pipeline binary|multiclass|anomaly
--model_kind hgb|isoforest
--budgets 10 25 50 100 250 500
--daily_budgets 5 10 25 50
--positive_label ATTACK
```

Metricas a generar:

- `precision_at_k`.
- `recall_at_k` sobre ventanas red-team.
- `f1_at_k`.
- `alerts_at_k`.
- `attack_windows_found_at_k`.
- `first_attack_rank`.
- `median_attack_rank`.
- `mean_attack_rank`.
- `precision_at_daily_k`.
- `recall_at_daily_k`.
- `alerts_per_day`.
- `attack_days_found`.
- `redteam_entities_found`.
- `top_entity_hit_rate`.
- `score_threshold_from_val` cuando aplique.

Archivos de salida:

```text
operational_metrics.json
alerts_val.csv
alerts_test.csv
top_entities_test.csv
top_days_test.csv
score_distribution_test.csv
```

Columnas minimas de `alerts_test.csv`:

```text
rank, window_start, window_end, day_index, entity, score, target,
redteam_exact, redteam_near, redteam_roles, source_families
```

Criterio de aceptacion:

- El evaluador se puede ejecutar sobre el HGB binario actual sin reentrenar.
- El resultado permite responder si alguna de las 38 ventanas red-team aparece en top-k.

## P3 - Ranking por entidad y deduplicacion

Estado: pendiente.

Archivo a modificar o extender:

- `src/models/CSR-LANL/evaluate_operational.py`

Implementaciones:

- Crear una vista por entidad agregando scores de ventana:
  - `max_score`,
  - `mean_top5_score`,
  - `n_alert_windows`,
  - `first_alert_window`,
  - `has_redteam_exact`,
  - `redteam_window_count`.
- Generar `top_entities_test.csv` ordenado por riesgo.
- Medir recall red-team por entidad:

```text
redteam_entity_recall_at_10
redteam_entity_recall_at_25
redteam_entity_recall_at_50
```

Motivo:

En CSR-LANL una misma entidad puede generar muchas ventanas. La deduplicacion por entidad reduce alert fatigue y se alinea mejor con una investigacion SOC.

Criterio de aceptacion:

- El informe puede decir que entidades aparecen como prioritarias, no solo que ventanas aisladas fueron puntuadas alto.

## P4 - Integrar metricas operacionales en comparativas

Estado: pendiente.

Archivo a modificar:

- `src/models/CSR-LANL/compare_models.py`

Implementaciones:

- Leer `operational_metrics.json` si existe en cada artefacto.
- Anadir columnas como:

```text
test_precision_at_50
test_recall_at_50
test_precision_at_100
test_recall_at_100
test_first_attack_rank
test_redteam_entity_recall_at_25
test_alerts_per_day_at_25
```

- Cambiar el ranking CSR-LANL para priorizar metricas operacionales antes que `macro_f1`:

```text
test_recall_at_100
test_redteam_entity_recall_at_25
test_precision_at_100
test_pr_auc
test_macro_f1
```

- Mantener `macro_f1` y `accuracy` como diagnostico secundario.

Criterio de aceptacion:

- `compare_models.py` permite identificar el mejor modelo CSR-LANL por capacidad de priorizacion, no por accuracy.

## P5 - Ejecutar evaluacion operacional desde los runners

Estado: pendiente.

Archivos a modificar:

- `src/scripts/csr_lanl_run_all_models.ps1`
- `src/scripts/csr_lanl_run_redteam_models.ps1`

Implementaciones:

- Anadir parametros:

```powershell
[switch]$SkipOperationalEval
[int[]]$OperationalBudgets = @(10, 25, 50, 100, 250, 500)
[int[]]$OperationalDailyBudgets = @(5, 10, 25, 50)
```

- Despues de cada entrenamiento, ejecutar `evaluate_operational.py` sobre el artefacto recien creado.
- Para no depender de busquedas fragiles, los trainers pueden imprimir o guardar el path del artefacto y el runner puede capturarlo mas adelante. Si eso complica el script, alternativa inicial:
  - ejecutar un evaluador standalone que detecte el ultimo run por modelo/split.

Criterio de aceptacion:

- Un run completo CSR-LANL produce automaticamente `operational_metrics.json` junto al modelo.

## P6 - HGB binario con pesos de clase

Estado: pendiente, despues de P2.

Archivo a modificar:

- `src/models/CSR-LANL/train_ml_binary_hgb.py`

Implementaciones:

- Anadir argumento:

```text
--class_weight none|balanced
```

- Si `balanced`, calcular pesos solo sobre train:

```python
from sklearn.utils.class_weight import compute_sample_weight
sample_weight = compute_sample_weight(class_weight="balanced", y=y_train)
model.fit(X_train, y_train, sample_weight=sample_weight)
```

- Guardar `class_weight` en `run_config`.
- Comparar el modelo balanceado con el modelo actual usando metricas operacionales, no solo `macro_f1`.

Criterio de aceptacion:

- El modelo balanceado aumenta recall/top-k de red-team sin disparar de forma inaceptable las alertas por dia.

## P7 - Politicas de threshold calibradas en validacion

Estado: pendiente.

Archivo recomendado:

- `src/models/CSR-LANL/evaluate_operational.py`

Implementaciones:

- Implementar politicas:

```text
top_k_global
top_k_per_day
threshold_max_f2_on_val
threshold_budget_on_val
```

- La politica se ajusta en `val` y se aplica a `test`.
- Guardar el umbral/presupuesto elegido en `operational_metrics.json`.

Criterio de aceptacion:

- No se usa `test` para escoger umbral.
- El informe puede justificar el presupuesto de alertas elegido.

## P8 - Redisenar `groupkfold` para CSR-LANL

Estado: pendiente, no bloquear P2-P7.

Archivo a modificar:

- `src/models/CSR-LANL/prepare_dataset.py`

Implementacion recomendada:

- Anadir un split nuevo:

```text
redteam_event_kfold
```

o:

```text
redteam_stratified_groupkfold
```

Objetivo:

- Evitar folds con 1 ataque en test.
- Repartir eventos red-team entre folds.
- Mantener separacion por entidad o por bloque temporal cuando sea posible.
- Guardar en metadata el numero de eventos y ventanas red-team por fold.

Regla minima:

```text
Cada fold evaluable debe tener al menos 30 ventanas red-team en test o quedar marcado como no defendible.
```

Criterio de aceptacion:

- Ninguna comparativa principal de CSR-LANL usa folds con soporte insuficiente sin advertencia visible.

## P9 - Endurecer validacion de datasets CSR-LANL

Estado: pendiente.

Archivo a modificar:

- `src/models/CSR-LANL/validate_datasets.py`

Implementaciones:

- Subir el umbral recomendado de positivos en evaluacion para CSR:

```text
--min_positive_eval 30
```

- Si el modo es `groupkfold` y test tiene menos positivos, no necesariamente fallar siempre, pero marcar:

```text
not_defensible_low_attack_support
```

- Incluir en el reporte:
  - ataques en train/val/test,
  - entidades red-team en train/val/test,
  - dias con red-team en test,
  - si el split es apto para metricas PR-AUC/top-k.

Criterio de aceptacion:

- El pipeline avisa antes de entrenar cuando el split no puede sostener conclusiones de tesis.

## P10 - Actualizar documentacion y narrativa de tesis

Estado: pendiente.

Archivos a actualizar:

- `NEXT_STEPS.md`
- `REFACTOR_MODELS.md`
- `STRATEGY_CSR-LANL.md`
- Opcionalmente un nuevo `RESULTS_CSR-LANL.md`

Contenido a documentar:

- CSR-LANL se evalua como deteccion y priorizacion operacional.
- Accuracy no es metrica principal.
- Resultados por top-k y presupuesto de alertas.
- Limitaciones del dataset:
  - red-team escaso,
  - etiquetas parciales,
  - fuerte desbalance,
  - posible separacion temporal dificil.
- Justificacion de que CSR-LANL aporta valor aunque el clasificador tradicional falle.

Criterio de aceptacion:

- La lectura de CSR-LANL queda alineada con el objetivo SIEM/SOC de la tesis.

## Orden de implementacion recomendado

1. P1: cargar metadata completa desde Parquet.
2. P2: crear `evaluate_operational.py`.
3. Ejecutar el evaluador sobre el HGB binario actual sin reentrenar.
4. P4: integrar `operational_metrics.json` en `compare_models.py`.
5. P5: conectar evaluacion operacional al runner CSR.
6. P6: probar HGB binario con `--class_weight balanced`.
7. P7: anadir politicas de threshold calibradas en validacion.
8. P9: endurecer validacion de splits.
9. P8: redisenar `groupkfold` si CSR va a tener comparativa robusta por entidad.
10. P10: actualizar documentacion final.

## Primer experimento recomendado

Antes de reentrenar nada, ejecutar evaluacion operacional sobre el ultimo HGB binario `date` existente.

Comando objetivo tras implementar P1-P2:

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\evaluate_operational.py `
  --artifact_dir src\models\CSR-LANL\artifacts\offline_CSR_LANL_binary_hgb\date\20260520_154336 `
  --datasets_base src\models\CSR-LANL\datasets_redteam `
  --dataset CSR-LANL `
  --split_mode date `
  --pipeline binary `
  --model_kind hgb `
  --budgets 10 25 50 100 250 500 `
  --daily_budgets 5 10 25 50
```

Resultado esperado:

- Si aparece red-team en top-k, el modelo actual no sirve como clasificador con threshold 0.5, pero podria servir como ranking de riesgo.
- Si no aparece red-team en top-k, entonces hay que pasar a P6 y posiblemente redisenar features/ventanas.

## Criterios finales de exito para CSR-LANL

CSR-LANL se considerara mejorado cuando cumpla al menos estos puntos:

- Hay `operational_metrics.json` para los modelos principales.
- La comparativa muestra metricas top-k y alertas por dia.
- El ranking principal no depende de accuracy.
- El informe identifica si red-team aparece en top-k global o diario.
- Los splits con pocos positivos quedan marcados como no defendibles.
- Existe al menos una politica calibrada en validacion y aplicada a test.
- El resultado puede explicarse como una herramienta de priorizacion SOC, incluso si la clasificacion fila-a-fila sigue siendo debil.