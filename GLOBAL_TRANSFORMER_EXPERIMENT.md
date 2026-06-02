# Global Transformer Experiment

Fecha de inicio: 2026-06-02

## Objetivo

Este experimento busca evaluar si un modelo global basado en Transformer puede aprender patrones de actividad maliciosa que generalicen entre varias fuentes de telemetria de seguridad, en lugar de entrenar exclusivamente un modelo aislado por dataset.

La pregunta principal es:

> Puede un modelo global multi-dataset mantener una deteccion razonable frente a ataques y comportamientos maliciosos procedentes de dominios distintos como trafico de red, alertas de laboratorio SIEM y actividad de honeypot?

Este experimento no sustituye a los mejores modelos especificos por dataset. Se plantea como una linea adicional de investigacion para medir transferencia, robustez y generalizacion cross-dataset.

## Motivacion

Los resultados actuales muestran que algunos modelos funcionan muy bien dentro de su propio dataset, por ejemplo HGB en UNSW-NB15, UGR16 y LAB-ALERTS, o HGB multiclass en COWRIE_FULL. Sin embargo, en un entorno SOC real las amenazas no llegan con la misma distribucion, el mismo esquema de features ni el mismo tipo de etiquetado que un benchmark concreto.

Por ese motivo, un modelo global puede aportar valor si:

- aprende senales comunes de comportamiento malicioso,
- reduce dependencia de un unico dataset,
- mejora la robustez frente a cambio de dominio,
- sirve como preentrenamiento para fine-tuning por dataset,
- permite comparar modelos especificos contra un modelo comun.

Tambien puede aportar valor si no supera a los modelos especificos, porque demostraria empiricamente que la generalizacion cross-dataset en ciberseguridad es dificil por sesgo de dataset, drift y diferencias de instrumentacion.

## Datasets Incluidos En V1

La primera version se centrara en una tarea binaria comun: `BENIGN` frente a `ATTACK`.

| Dataset | Rol en el experimento | Split recomendado | Observaciones |
| --- | --- | --- | --- |
| CIC-IDS2017 | Trafico de red/flows | `day` | Dataset de referencia para ataques de red. |
| UNSW-NB15 | Trafico de red tabular | `groupkfold/fold_0` | Benchmark robusto fuera de `random`; `official` queda como stress test posterior. |
| UGR16 | Trafico longitudinal/drift | `date` sobre `UGR16_MARAPR_HYBRID` | Aporta validacion temporal y cambio de distribucion. |
| LAB-ALERTS | Alertas/eventos de laboratorio SIEM | `date` | Aporta senales mas cercanas a integracion SIEM. |
| COWRIE_FULL | Honeypot/comportamiento ofensivo | `date` | En V1 se usa lectura binaria; multiclass queda para V2. |

CSR-LANL queda fuera de V1 porque su valor principal no esta en clasificacion fila a fila, sino en priorizacion SOC por entidad/entity-day bajo desbalance extremo. Puede anadirse posteriormente como extension operacional.

## Versiones Del Experimento

El experimento se divide en versiones para evitar mezclar problemas distintos en una unica prueba.

| Version | Nombre | Datasets | Objetivo | Estado |
| --- | --- | --- | --- | --- |
| V1 | `GLOBAL_BINARY_V1` | CIC, UNSW, UGR16, LAB-ALERTS, COWRIE_FULL | Clasificacion binaria global usando los mejores preprocesados compatibles. | Dataset preparado; baseline `fast` entrenado. |
| V1-LODO | `GLOBAL_BINARY_V1_LODO` | Los mismos que V1 | Leave-one-dataset-out para medir generalizacion a dominio no visto. | Runner preparado con `-HoldoutDataset ALL`. |
| V2 | `GLOBAL_MULTIHEAD_V2` | V1 + COWRIE multiclass | Backbone compartido con cabeza binaria y cabeza multiclass para comportamiento honeypot. | Diseno posterior. |
| V3 | `GLOBAL_CSR_EXTENSION_V3` | CSR-LANL `datasets_redteam_identity_v3` | Extension operacional con scoring por entidad/entity-day. | No mezclar con V1. |

## Preprocesados Y Splits Elegidos

La regla del experimento es usar para cada dataset su version preparada mas defendible, no necesariamente la que da el numero mas alto en un split optimista.

| Dataset | Preprocesado/version | Split | Uso en global |
| --- | --- | --- | --- |
| CIC-IDS2017 | `MachineLearningCVE` | `day` | V1 binario. |
| UNSW-NB15 | `NUSW-NB15` | `groupkfold/fold_0` | V1 binario. |
| UGR16 | `UGR16_MARAPR_HYBRID` | `date` | V1 binario. |
| LAB-ALERTS | `operational_no_label_proxy` | `date` | V1 binario. |
| COWRIE_FULL | `operational_no_label_proxy` | `date` | V1 binario; V2 multiclass. |
| CSR-LANL | `datasets_redteam_identity_v3` | `redteam_stratified_groupkfold/fold_0` | V3 operacional, no V1. |

## Transformer Elegido

El modelo mas adecuado para V1 es un **FTTransformer tabular** adaptado al dataset global.

Motivos:

- los datos ya preparados son tabulares, no secuencias crudas;
- hay mezcla de dominios con distintos esquemas originales;
- el modelo puede tokenizar cada feature canonica como un token numerico;
- permite anadir un `dataset_embedding` para escenarios mixed-domain;
- es mas apropiado que un Transformer temporal cuando no estamos alimentando ventanas secuenciales;
- es mas flexible que un MLP para capturar interacciones entre familias de features.

Arquitectura V1:

```text
features canonicas numericas
  -> feature tokenizer tipo FTTransformer
  -> token CLS
  -> dataset embedding opcional
  -> Transformer encoder
  -> binary classification head
```

Para mixed test se puede usar `dataset_embedding`, porque el modelo ve todos los dominios durante entrenamiento. Para leave-one-dataset-out, la evaluacion mas estricta debe desactivar ese embedding o usar un embedding `unknown`, porque el dataset oculto no tendria embedding entrenado.

## Hipotesis

| Hipotesis | Lectura esperada |
| --- | --- |
| H1 | El Transformer global puede aprender senales utiles cuando train, val y test contienen todos los datasets. |
| H2 | El rendimiento bajara en evaluacion leave-one-dataset-out, especialmente cuando el dataset oculto tenga telemetria distinta. |
| H3 | El modelo global no superara siempre al mejor modelo especifico, pero puede servir como pretraining o baseline comun. |
| H4 | LAB-ALERTS y COWRIE_FULL aumentaran diversidad, pero tambien elevaran el riesgo de dataset bias. |

## Riesgos Metodologicos

| Riesgo | Descripcion | Mitigacion |
| --- | --- | --- |
| Dataset bias | El modelo aprende a identificar el dataset en vez del ataque. | Reportar metricas por dataset y leave-one-dataset-out. |
| Schema mismatch | Los datasets no comparten exactamente las mismas columnas. | Usar representacion canonica agregada por familias de features en V1. |
| Catastrophic forgetting | Si se entrena secuencialmente por dataset, puede olvidar dominios previos. | Entrenar mezclando datasets o usar fine-tuning controlado. |
| Label mismatch | Algunas etiquetas multiclass no son equivalentes entre datasets. | V1 binario; V2 multi-head/multiclass. |
| Overfitting por dominio | Buen resultado mixed test pero mala generalizacion a dataset no visto. | Incluir evaluacion leave-one-dataset-out. |

## Representacion Global V1

No se concatenaran columnas crudas de todos los datasets sin control. Eso haria que el modelo aprendiera artefactos de schema y no necesariamente senales generalizables.

La V1 usa una representacion canonica agregada:

1. Cada dataset se carga desde sus splits ya preparados.
2. Se seleccionan solo features numericas.
3. Las columnas se agrupan por familias semanticas aproximadas, por ejemplo bytes, packets, duration, ports, dns, http, auth, counts, ratios y temporalidad.
4. Para cada familia se calculan estadisticos simples por fila: media, maximo absoluto, media absoluta y ratio de no ceros.
5. Se anade una mascara de presencia por familia para indicar si ese grupo existia en el dataset original.
6. Se anaden estadisticos globales de fila para conservar informacion general.
7. Se conserva `dataset_id` como metadato para analisis y, mas adelante, como embedding del modelo.

Esta representacion sacrifica detalle especifico, pero permite una primera prueba metodologicamente limpia de generalizacion multi-dataset.

## Estructura De Archivos Nueva

Todo el experimento se implementara en archivos nuevos:

```text
GLOBAL_TRANSFORMER_EXPERIMENT.md
src/models/GLOBAL_TRANSFORMER/
  global_schema.py
  prepare_global_dataset.py
  data_loader.py
  models.py
  train_global_binary_transformer.py
  evaluate_global.py           # fase posterior
src/scripts/global_transformer_run.ps1
```

Los entrenadores y preparadores existentes no se modifican.

## Fases De Trabajo

### Fase 1 - Preparacion Global Binary V1

Crear un dataset global binario con:

- `target_binary`: 0 benigno, 1 ataque,
- `target_raw`: etiqueta original,
- `dataset_id` y `dataset_name`,
- features canonicas numericas,
- splits `train`, `val` y `test`.

Salida esperada:

```text
src/models/GLOBAL_TRANSFORMER/datasets/GLOBAL_BINARY_V1/
  metadata.json
  feature_columns.json
  dataset_map.json
  train/global_train.parquet
  val/global_val.parquet
  test/global_test.parquet
```

### Fase 2 - Modelo Global Binario

Entrenar un Transformer binario con:

- entrada numerica canonica,
- embedding de dataset,
- tokenizacion FTTransformer por feature,
- dropout y weight decay,
- early stopping,
- metricas por dataset.

### Fase 3 - Evaluacion Mixed Test

Evaluar el modelo cuando todos los datasets aparecen en train/val/test. Esta prueba mide si el modelo aprende en un escenario multi-dominio conocido.

### Fase 4 - Leave-One-Dataset-Out

Entrenar dejando un dataset fuera y evaluar sobre ese dataset oculto. Esta es la prueba fuerte de generalizacion.

Ejemplos:

```text
train: UNSW + UGR16 + LAB + COWRIE
test: CIC

train: CIC + UNSW + LAB + COWRIE
test: UGR16
```

### Fase 5 - Comparacion Contra Baselines

Comparar el modelo global con los mejores modelos especificos documentados en:

- `BEST_RESULTS_BY_DATASET.md`,
- `BEST_CHOICE_BY_DATASET.md`,
- resultados de tuning `20260601`.

## Metricas

Las metricas principales seran:

- accuracy,
- macro-F1,
- macro-recall,
- ROC-AUC,
- PR-AUC,
- logloss,
- ECE,
- metricas separadas por dataset.

Para leave-one-dataset-out, la metrica mas importante sera macro-F1 y ROC-AUC sobre el dataset oculto.

## Criterios De Exito

El experimento sera util si cumple al menos uno de estos puntos:

1. El modelo global se acerca a los modelos especificos en mixed test.
2. El modelo global mantiene rendimiento razonable en al menos algunos escenarios leave-one-dataset-out.
3. El modelo global mejora tras fine-tuning por dataset frente a entrenar desde cero.
4. El experimento muestra de forma clara las limitaciones de generalizacion cross-dataset.

No se exigira que el Transformer global supere a todos los modelos especificos. En ciberseguridad, demostrar la dificultad del cambio de dominio tambien es un resultado defendible.

## Primer Comando Previsto

La preparacion completa de V1 se ejecuta con:

```powershell
.\src\scripts\global_transformer_run.ps1 `
  -Stage prepare `
  -Datasets CIC-IDS2017,UNSW-NB15,UGR16,LAB-ALERTS,COWRIE_FULL `
  -MaxRowsPerDataset 200000 `
  -OutputRoot src/models/GLOBAL_TRANSFORMER/datasets/GLOBAL_BINARY_V1 `
  -Overwrite
```

El primer baseline mixed-domain se entrena con:

```powershell
.\src\scripts\global_transformer_run.ps1 `
  -Stage train `
  -OutputRoot src/models/GLOBAL_TRANSFORMER/datasets/GLOBAL_BINARY_V1 `
  -Profile fast
```

La version estricta sin embedding de dataset usa:

```powershell
.\src\scripts\global_transformer_run.ps1 `
  -Stage train `
  -OutputRoot src/models/GLOBAL_TRANSFORMER/datasets/GLOBAL_BINARY_V1 `
  -Profile fast `
  -DisableDatasetEmbedding
```

La bateria leave-one-dataset-out V1-LODO se lanza con:

```powershell
.\src\scripts\global_transformer_run.ps1 `
  -Stage train `
  -OutputRoot src/models/GLOBAL_TRANSFORMER/datasets/GLOBAL_BINARY_V1 `
  -Profile fast `
  -HoldoutDataset ALL
```
