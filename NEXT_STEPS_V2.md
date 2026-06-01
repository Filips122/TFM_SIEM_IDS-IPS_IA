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

Estado: completado parcialmente.

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

Primer resultado aplicado:

- Se genero una comparativa operacional en `src/models/CSR-LANL/artifacts/compare_models/_validation_operational_date_balanced`.
- La lectura actual ya separa accuracy/macro-F1 de top-k, entidades y alertas por dia.

## P1 - Cargar metadata junto con features

Estado: completado.

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

Implementado:

- `src/models/CSR-LANL/data_loader.py` incorpora `LoadedFrameSplit`, `META_COLUMNS`, `frame_to_xy_meta()` y `load_split_frame()`.
- Los trainers existentes siguen usando `load_splits()` sin cambiar su interfaz.

## P2 - Evaluador operacional CSR-LANL

Estado: completado y ampliado con politicas por entidad.

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
top_entity_days_test.csv
```

Columnas minimas de `alerts_test.csv`:

```text
rank, window_start, window_end, day_index, entity, score, target,
redteam_exact, redteam_near, redteam_roles, source_families
```

Criterio de aceptacion:

- El evaluador se puede ejecutar sobre el HGB binario actual sin reentrenar.
- El resultado permite responder si alguna de las 38 ventanas red-team aparece en top-k.

Implementado:

- Nuevo `src/models/CSR-LANL/evaluate_operational.py`.
- Genera `operational_metrics.json`, `alerts_val.csv`, `alerts_test.csv`, `top_entities_test.csv`, `top_days_test.csv` y `score_distribution_test.csv`.
- Evaluado sobre HGB binario, HGB multiclass e IsolationForest en split `date`.
- Ampliado con politicas calibradas por entidad: `entity_max_f2_on_val`, `entity_budget_<N>_on_val` y `entity_budget_daily_<N>_on_val`.
- Genera `top_entity_days_test.csv` y reporta entidades red-team, ventanas red-team y dias de ataque cubiertos por entidades/entidad-dia seleccionadas.

## P3 - Ranking por entidad y deduplicacion

Estado: completado en version inicial.

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

Implementado:

- `evaluate_operational.py` genera ranking por entidad con `max_score`, `mean_top5_score`, `n_windows`, `redteam_window_count` y recall de entidades red-team en top-k.

## P4 - Integrar metricas operacionales en comparativas

Estado: completado y ampliado con politicas por entidad.

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

Implementado:

- `src/models/CSR-LANL/compare_models.py` lee `operational_metrics.json` si existe.
- La comparativa incluye top-k, daily top-k, entidades red-team y `first_attack_rank`.
- El ranking CSR-LANL prioriza metricas operacionales antes que `macro_f1`.
- La comparativa incluye columnas `test_entity_policy_*`, rankings de entidad y metricas entidad-dia.

## P5 - Ejecutar evaluacion operacional desde los runners

Estado: completado en version inicial.

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

Implementado:

- `src/scripts/csr_lanl_run_all_models.ps1` ejecuta `evaluate_operational.py` tras entrenar cada modelo CSR.
- Localiza el ultimo artefacto del modelo/split y evalua:
  - HGB binario como `pipeline=binary`, `model_kind=hgb`.
  - HGB multiclass como `pipeline=multiclass`, `model_kind=hgb`.
  - IsolationForest como `pipeline=anomaly`, `model_kind=isoforest`.
- Soporta `groupkfold` evaluando el `fold_*` correspondiente.
- Nuevo parametro para desactivarlo cuando convenga:

```powershell
-SkipOperationalEval
```

- Nuevos parametros de presupuesto:

```powershell
-OperationalBudgets 10 25 50 100 250 500
-OperationalDailyBudgets 5 10 25 50
```

- `src/scripts/csr_lanl_run_redteam_models.ps1` propaga esos parametros al runner principal.

Validacion:

- Dry-run correcto para `csr_lanl_run_all_models.ps1` con evaluacion operacional automatica.
- Dry-run correcto para `csr_lanl_run_redteam_models.ps1` propagando presupuestos operacionales.

## P6 - HGB binario con pesos de clase

Estado: completado en version inicial.

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

Implementado:

- `src/models/CSR-LANL/train_ml_binary_hgb.py` acepta `--class_weight none|balanced`.
- `src/scripts/csr_lanl_run_all_models.ps1` y `src/scripts/csr_lanl_run_redteam_models.ps1` exponen `-BinaryClassWeight`.
- Primer run balanceado: `src/models/CSR-LANL/artifacts/offline_CSR_LANL_binary_hgb/date/20260520_225134`.

Resultado inicial:

- HGB binario balanceado mejora el recall ATTACK fila-a-fila: detecta 8 de 38 ventanas red-team en test.
- Mantiene un coste alto: 15,242 falsos positivos en test con decision argmax.
- En ranking operacional, no encuentra ataques en top-100 ventanas, pero encuentra 1 ataque en top-250/top-500 ventanas.
- Por entidad mejora claramente: encuentra 3 de 15 entidades red-team en top-100 y 8 de 15 en top-500.
- Conclusion: `balanced` mejora la senal de ranking por entidad, pero aun no basta como detector de ventanas con bajo presupuesto.

## Resultado operacional inicial - 2026-05-20

Comparativa generada en:

```text
src/models/CSR-LANL/artifacts/compare_models/_validation_operational_date_balanced
```

| Modelo | Ventanas red-team top-100 | Ventanas red-team top-500 | Entidades red-team top-100 | Entidades red-team top-500 | Lectura |
| --- | ---: | ---: | ---: | ---: | --- |
| IsolationForest | 1/38 | 1/38 | 3/15 | 5/15 | Mejor top-100 de ventanas, pero PR-AUC global sigue muy baja. |
| HGB binario balanceado | 0/38 | 1/38 | 3/15 | 8/15 | Mejor ranking por entidad; threshold directo genera demasiados falsos positivos. |
| HGB multiclass | 0/38 | 2/38 | 0/15 | 2/15 | Captura algunas ventanas a presupuesto alto, pero ranking por entidad es flojo. |

Lectura:

- CSR-LANL ya puede evaluarse como priorizacion operacional.
- Ningun modelo actual es suficiente como detector directo de bajo presupuesto.
- El siguiente cambio tecnico deberia combinar scoring por entidad con una politica calibrada en validacion o redisenar features temporales/ventanas.

## P7 - Politicas de threshold calibradas en validacion

Estado: completado en version inicial.

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

Implementado:

- `evaluate_operational.py` genera politicas calibradas en validacion:
  - `max_f2_on_val`.
  - `budget_daily_5_on_val`.
  - `budget_daily_10_on_val`.
  - `budget_daily_25_on_val`.
  - `budget_daily_50_on_val`.
- `compare_models.py` incorpora columnas `test_policy_*` para comparar estas politicas.

Resultado inicial:

- HGB binario balanceado con `budget_daily_50_on_val` produce unas 52 alertas/dia en test, encuentra 1 de 38 ventanas red-team y 3 de 15 entidades red-team.
- IsolationForest con `max_f2_on_val` produce unas 28 alertas/dia en test, encuentra 1 de 38 ventanas red-team y 3 de 15 entidades red-team.
- Multiclass con `max_f2_on_val` encuentra 2 de 38 ventanas y 6 de 15 entidades, pero con unas 770 alertas/dia; no es operativo con ese threshold.

## P7B - Ensemble operacional de scores

Estado: completado en version inicial.

Archivo nuevo:

- `src/models/CSR-LANL/evaluate_operational_ensemble.py`

Implementacion:

- Combina varios artefactos mediante percentiles empiricos calculados sobre validacion.
- Soporta pesos por fuente.
- Genera los mismos artefactos que `evaluate_operational.py`:
  - `operational_metrics.json`,
  - `alerts_test.csv`,
  - `top_entities_test.csv`,
  - `top_days_test.csv`,
  - `score_distribution_test.csv`.
- El artefacto queda integrado en `compare_models.py` como `operational_ensemble_CSR_LANL`.

Primer ensemble probado:

```text
0.45 * HGB binario balanceado
0.35 * IsolationForest
0.20 * HGB multiclass
```

Artefacto:

```text
src/models/CSR-LANL/artifacts/operational_ensemble_CSR_LANL/date/20260521_002103
```

Resultado:

- No mejora el top-k de ventanas: 0 de 38 ventanas red-team en top-500.
- Mantiene buena senal por entidad: 3 de 15 entidades red-team en top-100 y 5 de 15 en top-500.
- No supera al HGB binario balanceado en ranking por entidad ni a IsolationForest en top-100 ventanas.

Conclusion:

- El ensemble simple por percentiles no resuelve CSR-LANL.
- La siguiente mejora debe ir a features temporales/entidad o a un split/event scoring mas alineado con red-team, no solo a combinar scores actuales.

## P8 - Redisenar `groupkfold` para CSR-LANL

Estado: completado y validado para `fold_0`.

Archivos modificados:

- `src/models/CSR-LANL/prepare_dataset.py`
- `src/models/CSR-LANL/redteam_sample_prepare_dataset.py`
- `src/models/CSR-LANL/data_loader.py`
- `src/models/CSR-LANL/train_ml_binary_hgb.py`
- `src/models/CSR-LANL/train_ml_multiclass_hgb.py`
- `src/models/CSR-LANL/train_anomaly_isoforest.py`
- `src/models/CSR-LANL/evaluate_operational.py`
- `src/models/CSR-LANL/evaluate_operational_ensemble.py`
- `src/scripts/csr_lanl_run_all_models.ps1`
- `src/scripts/csr_lanl_run_redteam_models.ps1`

Implementacion:

- Se anadio el split nuevo:

```text
redteam_stratified_groupkfold
```

- Este modo mantiene separacion por entidad, pero reparte primero las entidades red-team de forma balanceada por numero de ventanas de ataque.
- Las entidades benignas se distribuyen despues para equilibrar el volumen de filas por fold.
- Para cada fold:
  - `test` usa las entidades del fold seleccionado,
  - `val` usa el fold siguiente,
  - `train` usa el resto.
- `split_policy.json` ahora registra tambien `redteam_entities` y `redteam_days` por split.
- Los trainers, loaders, evaluadores y runners ya tratan `redteam_stratified_groupkfold` como modo con `fold_*`.
- Se anadio `src/models/CSR-LANL/derive_redteam_stratified_groupkfold.py` para derivar este split desde los Parquet ya materializados del split `date`, evitando volver a escanear `auth.txt.gz` y `flows.txt.gz`.
- El reparto se ajusto para evitar folds dominados por una sola entidad red-team: cada fold intenta mantener al menos 5 entidades red-team cuando el soporte disponible lo permite.

El intento inicial desde logs crudos se descarto por coste: el proceso seguia escaneando decenas de millones de filas de `auth.txt.gz`. El comando recomendado para generar el primer fold real es ahora:

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\derive_redteam_stratified_groupkfold.py `
  --datasets_base src/models/CSR-LANL/datasets_redteam `
  --dataset CSR-LANL `
  --source_split_mode date `
  --target_split_mode redteam_stratified_groupkfold `
  --n_folds 5 `
  --fold 0 `
  --batch_size 500000
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

Validacion obtenida para `redteam_stratified_groupkfold/fold_0`:

| Split | Estado | Filas test | Ventanas red-team test | Entidades red-team test | Dias en split test |
| --- | ---: | ---: | ---: | ---: | ---: |
| `redteam_stratified_groupkfold/fold_0` | ok | 4,428,898 | 522 | 5 | 14 |

Resultado inicial en `fold_0`:

| Modelo | Top-100 ventanas | Top-500 ventanas | Top-50 entidades | Politica destacada | Lectura |
| --- | ---: | ---: | ---: | --- | --- |
| HGB binario balanceado | 3/522 | 3/522 | 3/5 | `budget_daily_5_on_val`: 3/522 ventanas, 3/5 entidades, 3.89 alertas/dia | Mejor senal operacional de bajo presupuesto. |
| HGB multiclass | 0/522 | 0/522 | 0/5 | `max_f2_on_val`: 49/522 ventanas, 2/5 entidades, 941.72 alertas/dia | Recall alto solo con volumen no operativo. |
| IsolationForest | 0/522 | 0/522 | 0/5 | Sin deteccion calibrada util | No aporta en este fold. |

Pendiente operativo:

- Preparar los folds restantes con `--all_folds` solo si hay espacio/tiempo suficiente, porque cada fold materializa una copia completa train/val/test del dataset agregado.
- El primer experimento temporal ya esta materializado y evaluado. Antes de generar todos los folds, conviene refinar features/scoring porque el fold temporal no mejora el recall de ventanas frente al baseline no temporal.

## P8B - Features temporales e historial por entidad

Estado: completado en version inicial para `date` y `redteam_stratified_groupkfold/fold_0`.

Archivo nuevo:

- `src/models/CSR-LANL/enrich_temporal_features.py`

Datasets generados:

```text
src/models/CSR-LANL/datasets_redteam_temporal/date/CSR-LANL
src/models/CSR-LANL/datasets_redteam_temporal/redteam_stratified_groupkfold/CSR-LANL/fold_0
```

Implementacion:

- Deriva un dataset nuevo desde Parquet ya materializado, sin reescanear logs crudos.
- Mantiene intacto `datasets_redteam` como baseline validado.
- Anade 31 features causales sobre las 51 originales:
  - codificacion ciclica de hora/minuto,
  - flag `is_off_hours`,
  - historial de entidad (`entity_seen_window_count`, `entity_window_gap_seconds`),
  - medias y deltas rolling por entidad sobre ventanas anteriores de 5 y 30 observaciones.
- Los rolling features usan `shift(1)` antes de calcular medias, evitando leakage de la ventana actual.
- Escribe los tres pipelines (`binary`, `multiclass`, `anomaly`) y metadata estandar compatible con trainers/evaluadores existentes.

Comando de materializacion `date`:

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\enrich_temporal_features.py `
  --source_datasets_base src/models/CSR-LANL/datasets_redteam `
  --target_datasets_base src/models/CSR-LANL/datasets_redteam_temporal `
  --dataset CSR-LANL `
  --split_mode date `
  --batch_size 500000
```

Validacion temporal `date`:

| Split | Estado | Filas test | Ventanas red-team test | Entidades red-team test | Dias en split test |
| --- | ---: | ---: | ---: | ---: | ---: |
| `date` temporal | ok | 2,575,431 | 38 | 15 | 4 |

Nota: `validate_splits.py` cuenta dias por presencia en metadata del split y reporta 4 dias en test; las ventanas exactas red-team siguen concentradas en 3 dias de ataque en la evaluacion operacional.

Resultado HGB binario balanceado en `date`:

| Dataset | Run | First rank | Top-100 ventanas | Top-500 ventanas | Top-100 entidades | Top-500 entidades | Lectura |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Baseline `datasets_redteam` | `20260520_225134` | 121 | 0/38 | 1/38 | 3/15 | 8/15 | Baseline anterior. |
| Temporal `datasets_redteam_temporal` | `20260526_145328` | 22 | 4/38 | 7/38 | 4/15 | 8/15 | Mejora clara en ranking de ventanas del split principal. |

Derivacion y validacion temporal de `fold_0`:

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\derive_redteam_stratified_groupkfold.py `
  --datasets_base src/models/CSR-LANL/datasets_redteam_temporal `
  --dataset CSR-LANL `
  --source_split_mode date `
  --target_split_mode redteam_stratified_groupkfold `
  --fold 0 `
  --n_folds 5 `
  --batch_size 500000
```

| Split | Estado | Filas test | Ventanas red-team test | Entidades red-team test | Dias ataque test |
| --- | ---: | ---: | ---: | ---: | ---: |
| `redteam_stratified_groupkfold/fold_0` temporal | ok | 4,428,898 | 522 | 5 | 14 |

Resultado HGB binario balanceado en `fold_0`:

| Dataset | Run | First rank | Top-100 ventanas | Top-500 ventanas | Top-50 entidades | Top-500 entidades | Lectura |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Baseline `datasets_redteam` | `20260526_140337` | 8 | 3/522 | 3/522 | 3/5 | 4/5 | Mejor baseline del fold para ventanas y entidades. |
| Temporal `datasets_redteam_temporal` | `20260526_150731` | 7 | 2/522 | 3/522 | 2/5 | 4/5 | Primer hit algo mejor, pero no mejora el recall global del fold. |

Lectura:

- Las features temporales mejoran claramente el split `date`, por lo que son utiles como evidencia de mejora de feature engineering.
- En `fold_0`, la transferencia a entidades red-team no vistas es peor o equivalente: top-100 ventanas baja de 3/522 a 2/522 y top-500 queda en 3/522.
- La validacion tiene senal fuerte, pero el test del fold no acompana; esto apunta a drift entre entidades red-team y a que falta una estrategia de scoring mas robusta, no solo mas features rolling.
- Las politicas por entidad mejoran la lectura SOC: en `date` temporal, `entity_budget_daily_25_on_val` cubre 9/38 ventanas y 2/15 entidades con 47 entidad-dias seleccionados; en `fold_0` temporal, `entity_budget_daily_25_on_val` cubre 4/5 entidades y 4/522 ventanas con 341 entidad-dias.
- El dataset temporal debe conservarse, pero no justifica todavia generar todos los folds temporales.

Siguiente mejora recomendada:

- Anadir features de rareza historica por entidad y par origen-destino, no solo medias rolling.
- Probar scoring por entidad como objetivo principal, calibrando politicas sobre entidades antes de convertirlas a alertas de ventanas.
- Evaluar ventanas de 5 minutos o agregacion multi-escala para reducir sparsity minuto-a-minuto.
- Solo despues de una mejora estable en `date` y `fold_0`, materializar los folds restantes.

## P8C - Features de rareza causal y multi-escala

Estado: implementado, materializado en `date`, derivado para `fold_0`, validado y evaluado con HGB binario balanceado.

Archivo nuevo:

- `src/models/CSR-LANL/enrich_rarity_features.py`

Dataset objetivo:

```text
src/models/CSR-LANL/datasets_redteam_temporal_rarity/date/CSR-LANL
```

Implementacion:

- Deriva un nuevo dataset desde `datasets_redteam_temporal`, sin reescanear logs crudos.
- Mantiene intactos `datasets_redteam` y `datasets_redteam_temporal` para comparacion limpia.
- Anade 49 features sobre las 82 del perfil temporal, totalizando 131 columnas de entrada.
- Usa estadisticas causales por entidad:
  - medias historicas previas,
  - z-scores historicos previos,
  - medias rolling de 15 y 60 observaciones anteriores,
  - ratios contra el comportamiento reciente previo,
  - edad/densidad historica de la entidad,
  - senales compuestas de novedad, amplitud de destinos, presion de puertos, fallos de autenticacion y procesos.
- Evita leakage usando solo historial anterior de la entidad para medias, z-scores y rolling features.

Limitacion importante:

- El Parquet preparado no conserva identificadores concretos de `dst_computer`, `dst_port` o pares origen-destino por evento. Por eso esta primera version implementa rareza causal sobre agregados ya materializados. La rareza exacta por par origen-destino requeriria re-materializar desde logs crudos o conservar sketches/listas en `prepare_dataset.py`.

Comando de materializacion `date`:

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\enrich_rarity_features.py `
  --source_datasets_base src/models/CSR-LANL/datasets_redteam_temporal `
  --target_datasets_base src/models/CSR-LANL/datasets_redteam_temporal_rarity `
  --dataset CSR-LANL `
  --split_mode date `
  --batch_size 500000
```

Validacion smoke realizada:

- `--max_rows_per_split 1000` genera train/val/test correctamente.
- `validate_splits.py` carga el dataset derivado.
- `feature_columns.json` contiene 131 features y columnas como `entity_total_event_count_prior_zscore` y `entity_flow_unique_dst_port_count_roll60_ratio`.

Validacion `date` completa:

| Split | Estado | Filas test | Ventanas red-team test | Entidades red-team test | Dias en split test |
| --- | ---: | ---: | ---: | ---: | ---: |
| `date` temporal+rareza | ok | 2,575,431 | 38 | 15 | 4 |

Validacion `redteam_stratified_groupkfold/fold_0` completa:

| Split | Estado | Filas test | Ventanas red-team test | Entidades red-team test | Dias en split test |
| --- | ---: | ---: | ---: | ---: | ---: |
| `fold_0` temporal+rareza | ok | 4,428,898 | 522 | 5 | 29 |

Resultado HGB binario balanceado en `date`:

| Dataset | Run | First rank | Top-100 ventanas | Top-500 ventanas | Top-100 entidades | Top-500 entidades | Lectura |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Temporal `datasets_redteam_temporal` | `20260526_145328` | 22 | 4/38 | 7/38 | 4/15 | 8/15 | Mejor ranking directo de ventanas. |
| Temporal+rareza `datasets_redteam_temporal_rarity` | `20260527_144125` | 72 | 2/38 | 3/38 | 5/15 | 7/15 | Peor top-k de ventanas; mejor senal en politica entidad-dia. |

Politicas entidad-dia `date`:

| Dataset | Policy | Entity-days | Entidades red-team | Ventanas red-team | Dias ataque | Lectura |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Temporal | `entity_budget_daily_25_on_val` | 47 | 2/15 | 9/38 | 1/3 | Mejor resultado anterior con volumen moderado. |
| Temporal+rareza | `entity_budget_daily_25_on_val` | 92 | 3/15 | 15/38 | 2/3 | Mejor cobertura SOC, pero casi duplica entity-days. |

Resultado HGB binario balanceado en `redteam_stratified_groupkfold/fold_0`:

| Dataset | Run | First rank | Top-100 ventanas | Top-500 ventanas | Top-50 entidades | Top-500 entidades | Lectura |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Baseline `datasets_redteam` | `20260526_140337` | 8 | 3/522 | 3/522 | 3/5 | 4/5 | Mejor baseline del fold para recall de ventanas. |
| Temporal `datasets_redteam_temporal` | `20260526_150731` | 7 | 2/522 | 3/522 | 2/5 | 4/5 | Primer hit algo mejor, sin mejora global. |
| Temporal+rareza `datasets_redteam_temporal_rarity` | `20260527_151925` | 4 | 3/522 | 3/522 | 3/5 | 4/5 | Mejor primer hit; iguala al baseline en top-k y entidades. |

Politicas entidad-dia `fold_0`:

| Dataset | Policy | Entity-days | Entidades red-team | Ventanas red-team | Dias ataque | Lectura |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Baseline | `entity_budget_daily_5_on_val` | 50 | 3/5 | 3/522 | 2/14 | Mejor politica de bajo volumen anterior. |
| Temporal | `entity_budget_daily_25_on_val` | 341 | 4/5 | 4/522 | 2/14 | Mejor cobertura anterior, con alto volumen de triage. |
| Temporal+rareza | `entity_budget_daily_5_on_val` | 45 | 3/5 | 3/522 | 2/14 | Igual cobertura que baseline con menos entity-days. |
| Temporal+rareza | `entity_budget_daily_25_on_val` | 316 | 4/5 | 4/522 | 2/14 | Igual cobertura que temporal con menos entity-days. |

Lectura final de P8C:

- En `date`, temporal+rareza empeora el ranking directo de ventanas frente a temporal-only, pero mejora la politica SOC por entidad-dia: 15/38 ventanas y 3/15 entidades.
- En `fold_0`, temporal+rareza mejora el primer hit de rank 8 a rank 4 y mantiene la cobertura de entidades, pero no sube el top-500 de ventanas por encima de 3/522.
- Las features de rareza causal sobre agregados son utiles para priorizacion de entidades, no suficientes para resolver localizacion exacta de ventanas red-team.
- No conviene materializar todos los folds todavia. Antes hay que probar una de dos mejoras: preservar identidades concretas de destino/par origen-destino en un preparador separado, o entrenar una politica entity-first como objetivo principal.

Experimento recomendado siguiente:

- P8D: re-materializacion parcial o enrichment raw-light que conserve `dst_computer`, `dst_port` y pares origen-destino agregados como sketches/counters por ventana.
- Alternativa de menor coste: entrenar/evaluar directamente un scorer por entidad-dia, usando las politicas de `evaluate_operational.py` como metrica principal.

## P8D - Scorer entity-day derivado

Estado: implementado y evaluado en `date` y `redteam_stratified_groupkfold/fold_0`.

Archivos nuevos:

- `src/models/CSR-LANL/prepare_entity_day_dataset.py`
- `src/models/CSR-LANL/train_entity_day_hgb.py`

Datasets derivados:

```text
src/models/CSR-LANL/datasets_redteam_temporal_rarity_entity_day
src/models/CSR-LANL/datasets_redteam_temporal_rarity_entity_day_scored
```

Implementacion:

- Agrupa ventanas ya materializadas por `(entity, day_index)`.
- No modifica `datasets_redteam`, `datasets_redteam_temporal` ni `datasets_redteam_temporal_rarity`.
- Genera una etiqueta positiva cuando la entidad-dia contiene al menos una ventana red-team.
- Crea 360 features entity-day en modo `soc` a partir de medias, maximos y sumas de features temporales/rareza.
- La variante `entity_day_scored` anade el score del HGB de ventanas temporal+rareza como `window_model_score` agregado.
- Entrena `HistGradientBoostingClassifier` balanceado y evalua ranking/top-k/politicas calibradas por entidad-dia.

Soporte `date` entity-day:

| Split | Entity-days | Entity-days red-team | Ventanas red-team | Entidades red-team | Dias |
| --- | ---: | ---: | ---: | ---: | ---: |
| Train | 122,826 | 371 | 1,064 | 292 | 11 |
| Val | 55,117 | 43 | 96 | 40 | 5 |
| Test | 43,510 | 19 | 38 | 15 | 4 |

Resultados principales:

| Split | Variante | Run | First entity-day rank | Top-50 ventanas | Top-500 ventanas | Politica daily-25 calibrada | Lectura |
| --- | --- | --- | ---: | ---: | ---: | --- | --- |
| `date` | Raw entity-day | `20260529_164015` | 9 | 3/38 | 6/38 | 105 entity-days, 3/15 entidades, 3/38 ventanas | Buen primer hit, cobertura inferior a la politica previa. |
| `date` | Scored entity-day | `20260529_164752` | 87 | 0/38 | 20/38 | 149 entity-days, 4/15 entidades, 9/38 ventanas | Mejor top-500 global, pero no supera daily-25 temporal+rareza. |
| `fold_0` | Raw entity-day | `20260529_164128` | 99 | 0/522 | 2/522 | 391 entity-days, 2/5 entidades, 2/522 ventanas | Transferencia debil a entidades no vistas. |
| `fold_0` | Scored entity-day | `20260529_165022` | 33 | 2/522 | 3/522 | 364 entity-days, 3/5 entidades, 3/522 ventanas | Mejora la variante raw, pero no supera la politica previa del fold. |

Lectura final de P8D:

- El scorer entity-day es reproducible y barato una vez materializada la vista derivada.
- La variante con `window_model_score` aporta senal, especialmente en `date` top-500 global: 20/38 ventanas.
- Aun asi, no supera las politicas entity-day ya calibradas desde el score de ventanas: `date` temporal+rareza daily-25 sigue en 15/38 ventanas y `fold_0` temporal+rareza daily-25 sigue en 4/522 ventanas.
- Por tanto, P8D queda como ablation/experimento negativo util: confirma que el cuello de botella no es solo el objetivo entity-day, sino la falta de identidad concreta de destino/par en las features.

Siguiente paso recomendado tras P8D:

- Implementar P8E: conservar `prepare_dataset.py` como base original y crear un preparador separado para senales de `dst_computer`, `dst_port` y pares origen-destino a nivel ventana mediante contadores/sketches reproducibles.
- No materializar todos los folds todavia; hacerlo solo despues de comprobar que P8E mejora `date` y `fold_0`.

## P8E - Preparador con identidad destino/par

Estado: implementado en version inicial y validado con smoke test.

Archivo nuevo:

- `src/models/CSR-LANL/prepare_dataset_identity.py`

Principios de implementacion:

- `src/models/CSR-LANL/prepare_dataset.py` queda restaurado como preparador base/original.
- El perfil P8E escribe por defecto en `src/models/CSR-LANL/datasets_redteam_identity`, para no pisar datasets previos.
- Conserva el soporte de `redteam_stratified_groupkfold` y metadata adicional de entidades/dias red-team en el archivo nuevo.
- Anade 128 features de sketches hash estables para destinos, puertos y pares origen-destino.
- Anade 30 features resumen/novedad causal por entidad para destinos, puertos, pares origen-destino y pares origen-destino-puerto.
- Los acumuladores internos solo inicializan las features base; las features P8E se calculan al finalizar cada ventana para controlar memoria en la materializacion completa.

Smoke validado:

```text
src/models/CSR-LANL/datasets_redteam_identity_smoke/date/CSR-LANL
```

- `source_set=auth_flow_dns`, ventana +/-0.25h alrededor del primer evento red-team.
- 88,487 ventanas, 6/6 entity-windows red-team emparejadas.
- 209 features: 51 base, 128 sketches de identidad y 30 resumen/novedad.
- `validate_splits.py` compatible en `date`.

Siguiente evaluacion recomendada:

- Materializar solo `date` y `redteam_stratified_groupkfold/fold_0` con `source_set=auth_flow`, `redteam_window_hours=1.0`, `redteam_window_limit=0`.
- Entrenar HGB binario balanceado en ambos splits.
- Ejecutar `evaluate_operational.py` y comparar contra temporal+rareza, especialmente top-k ventanas, top-k entidades y politicas entity-day calibradas.

## P9 - Endurecer validacion de datasets CSR-LANL

Estado: completado en version inicial.

Archivo nuevo:

- `src/models/CSR-LANL/validate_splits.py`

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

Implementado:

- Valida `date`, `random`, `groupkfold` y `redteam_stratified_groupkfold` sobre los pipelines `binary`, `multiclass` y `anomaly`.
- Cuenta filas, ventanas red-team, entidades red-team, dias y rangos temporales.
- Marca `random` como split no operacional para evidencia principal.
- Marca los modos con folds cuando el soporte red-team de test es insuficiente.
- En modos con folds, comprueba solape de entidades entre train/val/test.
- `src/scripts/csr_lanl_run_all_models.ps1` ejecuta `validate_splits.py` como precheck antes de entrenar.
- `src/scripts/csr_lanl_run_redteam_models.ps1` ejecuta `validate_datasets.py` y `validate_splits.py` tras preparar datasets.

Artefactos generados:

```text
src/models/CSR-LANL/artifacts/split_validation/redteam_current/split_validation.json
src/models/CSR-LANL/artifacts/split_validation/redteam_current/split_validation_summary.csv
```

Resultado actual:

| Split | Estado | Ventanas red-team test | Entidades red-team test | Lectura |
| --- | ---: | ---: | ---: | --- |
| `date` | ok | 38 | 15 | Split principal defendible para CSR-LANL. |
| `random` | warn | 3 | 3 | Solo sanity check; no debe sostener conclusiones principales. |
| `groupkfold/fold_0` | warn | 1 | 1 | No defendible como comparativa final sin rediseno. |
| `redteam_stratified_groupkfold/fold_0` | ok | 522 | 5 | Split secundario defendible para generalizacion por entidad. |

Conclusion:

- `date` debe ser el split principal para resultados CSR-LANL.
- `redteam_stratified_groupkfold/fold_0` queda como evidencia secundaria defendible de generalizacion por entidad.
- `random` y `groupkfold/fold_0` deben aparecer como no concluyentes o auxiliares.
- Los folds restantes son opcionales hasta que haya mejoras de features que justifiquen una tabla cross-fold.

## P10 - Actualizar documentacion y narrativa de tesis

Estado: completado parcialmente.

Archivos a actualizar:

- `NEXT_STEPS.md`
- `REFACTOR_MODELS.md`
- `STRATEGY_CSR-LANL.md`
- `RESULTS_CSR-LANL.md`

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

Implementado en esta fase:

- `NEXT_STEPS_V2.md` documenta el nuevo split y la lectura operacional actual.
- `STRATEGY_CSR-LANL.md` queda alineado con `redteam_stratified_groupkfold` como alternativa al `groupkfold` original.
- `RESULTS_CSR-LANL.md` resume resultados, limitaciones y siguiente experimento defendible.
- `redteam_stratified_groupkfold/fold_0` ya cuenta con resultados de HGB binario balanceado, HGB multiclass e IsolationForest.
- `datasets_redteam_temporal` documenta el primer experimento de features temporales, con mejora clara en `date` pero resultado mixto en `fold_0`.

## Orden de implementacion recomendado

1. P1: cargar metadata completa desde Parquet.
2. P2: crear `evaluate_operational.py`.
3. Ejecutar el evaluador sobre el HGB binario actual sin reentrenar.
4. P4: integrar `operational_metrics.json` en `compare_models.py`.
5. P6: probar HGB binario con `--class_weight balanced`. Completado inicialmente.
6. P7: anadir politicas de threshold calibradas en validacion. Completado inicialmente.
7. P7B: probar ensemble operacional de scores. Completado inicialmente.
8. P9: endurecer validacion de splits. Completado inicialmente.
9. P5: conectar evaluacion operacional al runner CSR. Completado inicialmente.
10. P8: redisenar `groupkfold` si CSR va a tener comparativa robusta por entidad. Completado y validado para `fold_0`.
11. P8B: anadir features temporales e historial por entidad. Completado inicialmente; mejora `date`, no supera el baseline en `fold_0`.
12. P8C: anadir rareza causal y multi-escala desde el dataset temporal. Completado para `date` y `fold_0`; mejora SOC/entity-day, no resuelve recall de ventanas.
13. P8D: scorer entity-day derivado. Completado; aporta ablation util, pero no supera las politicas entity-day previas.
14. P8E recomendado: preservar identidades concretas de destino/par origen-destino antes de materializar todos los folds.
15. P10: actualizar documentacion final. Completado parcialmente con resultados de `fold_0`, temporal, temporal+rareza, entity-day y politicas por entidad.

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