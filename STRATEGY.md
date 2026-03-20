# STRATEGY

## Objetivo

Este documento describe como esta implementada la logica del codigo en el proyecto, desde la lectura de los CSV originales de CIC-IDS2017 hasta la generacion de metricas, plots y comparativas finales entre modelos.

El pipeline principal vive en `src/models/CIC-IDS2017/` y se apoya en dos fuentes de datos:

- `src/datasets/CIC-IDS2017/MachineLearningCVE`: vision offline del dataset.
- `src/datasets/CIC-IDS2017/TrafficLabelling`: vision online con metadatos de flujo como IPs, Flow ID y Timestamp.

---

## Flujo End-to-End

1. Se leen los CSV originales por chunks para no cargar todo en memoria.
2. Se normalizan columnas, etiquetas y tipos de datos.
3. Se limpian labels invalidos y valores infinitos.
4. Se convierten las features a numerico y se fijan dtypes estables.
5. Se generan targets segun la tarea: binaria, multiclase, multiclase agrupada o anomalias.
6. Se escriben datasets intermedios en Parquet con una estructura de carpetas por modo de split.
7. Los scripts de entrenamiento cargan esos Parquets, construyen `X` e `y` y entrenan el modelo correspondiente.
8. Se calculan metricas, curvas y matrices de confusion.
9. Se guardan artefactos versionados por fecha en `artifacts/`.
10. `compare_models.py` consolida las metricas test de todos los runs y produce la comparativa final.

---

## 1. Origen de Datos

### Datasets de entrada

- `MachineLearningCVE` se usa para los modelos offline basados en clasificacion tabular clasica.
- `TrafficLabelling` se usa para el escenario online, para transfer learning tabular y para el pipeline secuencial.

### Scripts auxiliares de inspeccion

En `src/helpers/` hay utilidades de apoyo para revisar el dataset antes del entrenamiento:

- `analyze_cic_folder.py`
- `list_columns.py`
- `schema_check.py`

No forman parte del entrenamiento en si, pero sirven para validar que los CSV originales tienen el esquema esperado.

---

## 2. Preprocesamiento Tabular Base

La normalizacion y limpieza principal se implementa en `prepare_dataset.py`. La idea del archivo es convertir CSV grandes y heterogeneos en Parquets consistentes y reutilizables.

### 2.1 Lectura por chunks

Cada CSV se procesa con `pandas.read_csv(..., chunksize=...)`. Esto evita cargar archivos completos de CIC-IDS2017 en memoria y permite escribir el resultado de forma incremental.

### 2.2 Normalizacion de columnas

Se aplican varias rutinas comunes:

- `normalize_colname(c)`: elimina BOM, espacios duplicados y normaliza nombres.
- `find_label_col(cols)`: detecta automaticamente la columna objetivo buscando alias como `label`, `class`, `attack` o `attacktype`.
- `normalize_label(s)`: limpia espacios, normaliza guiones y unifica variantes textuales del label.

Esto evita que pequenas diferencias de formato entre CSV rompan el pipeline.

### 2.3 Limpieza de labels

La funcion `drop_bad_labels(df, label_col)` elimina filas con etiquetas:

- nulas,
- vacias,
- o convertidas a texto `nan`.

Esto es especialmente importante para `TrafficLabelling`, donde las columnas pueden llegar con ruido o celdas inconsistentes.

### 2.4 Tratamiento de infinitos y NaN

`replace_inf_with_nan(df)` reemplaza:

- `np.inf`
- `-np.inf`
- cadenas como `Infinity`, `-Infinity`, `inf`

por `NaN`.

El objetivo es que el pipeline de conversion a numerico y estandarizacion no falle por valores extremos heredados del dataset bruto.

### 2.5 Conversion a numerico

`coerce_numeric_features(df, label_col, dataset_name)` intenta convertir a numerico todas las columnas excepto:

- la columna de label,
- y en `TrafficLabelling`, las columnas meta: `Flow ID`, `Source IP`, `Destination IP`, `Timestamp`.

Esas columnas meta se preservan cuando interesa mantener contexto online, pero no participan como features del modelo tabular.

### 2.6 Dtypes estables

`force_stable_numeric_dtypes(...)` fuerza todas las features numericas a `float64` antes de escribir a Parquet. Esto resuelve un problema practico: si un chunk sale con `int64` y otro con `float64`, `pyarrow` puede detectar schemas distintos y fallar o generar datasets inconsistentes.

### 2.7 Particularidades de TrafficLabelling

En `preprocess_chunk(...)`:

- `Timestamp` se parsea con `pd.to_datetime(errors="coerce")`.
- `Flow ID`, `Source IP` y `Destination IP` se fuerzan a `str`.

Esto mantiene separadas las columnas de contexto de las features numericas.

---

## 3. Construccion de Targets

El proyecto no usa un unico objetivo. Construye distintos targets segun el experimento.

### 3.1 Pipeline binario

`make_binary_target(labels)` transforma:

- `BENIGN` -> `BENIGN`
- cualquier ataque -> `ATTACK`

Este es el pipeline mas usado en los experimentos de IDS binario.

### 3.2 Pipeline multiclase

`make_multiclass_target(labels)` deja la etiqueta normalizada tal como viene del dataset.

### 3.3 Pipeline multiclase agrupado

`make_grouped_target(labels)` agrupa ataques en familias mas grandes:

- `Web Attack *` -> `WebAttack`
- `DoS *` -> `DoS`
- ataques con `Patator` -> `BruteForce`
- otras clases concretas como `DDoS`, `PortScan`, `Bot`, `Infiltration`, `Heartbleed`
- cualquier resto -> `OtherAttack`

Esto reduce la fragmentacion de clases y permite un problema multicategoria mas estable.

### 3.4 Pipeline de anomalias

En lugar de clasificacion supervisada completa:

- `train` usa solo trafico `BENIGN`.
- `val` y `test` se guardan como datasets mixtos con target binario `BENIGN` o `ATTACK`.

Ese esquema esta pensado especificamente para `IsolationForest`.

---

## 4. Estrategias de Split

`prepare_dataset.py` soporta tres formas de separacion.

### 4.1 `day`

La separacion temporal esta definida por nombre de archivo:

- Monday, Tuesday, Wednesday -> `train`
- Thursday -> `val`
- Friday -> `test`

Es la evaluacion mas realista temporalmente, porque obliga al modelo a generalizar a trafico de dias futuros.

### 4.2 `groupkfold`

No usa un KFold sobre filas, sino sobre archivos/dias:

- `fold_k` usa un CSV como test,
- el CSV siguiente como validacion,
- y el resto como train.

Con esto se evita mezclar filas del mismo archivo entre train y test.

### 4.3 `random`

Genera mascaras aleatorias por fila usando un RNG reproducible.

Puntos importantes de implementacion:

- usa la misma mascara base para todos los pipelines del mismo CSV,
- permite comparar binario, multiclase y anomalias sobre exactamente la misma particion,
- ratios por defecto: `train=0.70`, `val=0.15`, `test=0.15`.

---

## 5. Escritura del Dataset Tabular en Parquet

La salida de `prepare_dataset.py` se escribe en `src/models/CIC-IDS2017/datasets/`.

### 5.1 Estructura de salida

Para pipelines supervisados:

```text
datasets/<split_mode>/<dataset>/<pipeline>/<split>/*.parquet
```

Para `groupkfold`:

```text
datasets/groupkfold/<dataset>/fold_k/<pipeline>/<split>/*.parquet
```

Para anomalias:

```text
datasets/<split_mode>/<dataset>/anomaly/train_benign/*.parquet
datasets/<split_mode>/<dataset>/anomaly/val_mixed/*.parquet
datasets/<split_mode>/<dataset>/anomaly/test_mixed/*.parquet
```

### 5.2 Estadisticas persistidas

Despues de procesar cada dataset, `write_stats(...)` genera `stats.json` con:

- numero de filas por split,
- conteo de benignos y ataques,
- distribucion de labels.

Esto sirve como control de calidad del preprocesado y de la distribucion de clases.

---

## 6. Generacion del Dataset Secuencial

La parte secuencial se implementa en `prepare_sequence_dataset.py` y se basa exclusivamente en `TrafficLabelling`.

### 6.1 Idea del pipeline secuencial

En lugar de clasificar cada flujo aislado, se construyen ventanas temporales de varios flujos consecutivos de un mismo grupo.

### 6.2 Agrupacion de secuencias

Las secuencias pueden agruparse por:

- `source_ip`
- `flow_id`
- `five_tuple`

La funcion `get_group_id(...)` construye el identificador del grupo y mantiene un buffer deslizante por grupo.

### 6.3 Ventanas deslizantes

Por cada grupo se conserva un `deque(maxlen=window_size)`. Cuando el buffer alcanza el tamano de ventana:

- se genera una muestra secuencial,
- se aplica `stride`,
- se aplana la ventana en columnas del tipo `feature__t-k`.

La etiqueta usada para la secuencia es la del ultimo flujo de la ventana.

### 6.4 Flattening de secuencias

La funcion `flatten_window(window, feat_names, window_size)` genera columnas como:

- `Flow Duration__t-19`
- `Flow Duration__t-18`
- ...
- `Flow Duration__t-0`

Esto permite guardar las secuencias en Parquet sin perder la posibilidad de reconstruir luego la forma `(N, T, F)`.

### 6.5 Salida secuencial

Las secuencias se guardan en:

```text
datasets/sequence/<mode>/TrafficLabelling/<task>/<split>/*.parquet
datasets/sequence/groupkfold/TrafficLabelling/<task>/fold_k/<split>/*.parquet
```

Ademas, cada ejecucion escribe:

- `sequence_meta.json`
- `sequence_stats.json`

con configuracion de ventana, stride, grouping y conteo de targets.

---

## 7. Carga de Datos para Entrenamiento

### 7.1 Carga tabular

`data_loader.py` se encarga de:

- localizar la carpeta del split correcto,
- leer todos los Parquets del split,
- concatenarlos en un `DataFrame`,
- inferir las columnas numericas validas,
- devolver `LoadedSplit(X, y, feature_names)`.

`_infer_numeric_feature_columns(...)` ignora columnas no numericas, `target` y `label_raw`. Esto permite que `TrafficLabelling` mantenga metadatos sin romper el entrenamiento.

### 7.2 Carga secuencial

`sequence_loader.py`:

- detecta columnas `__t-k`,
- infiere `window_size`,
- reconstruye el orden temporal,
- hace `reshape` del plano `(N, T*F)` a `(N, T, F)`.

De esta forma el dataset secuencial se serializa plano, pero se entrena con estructura temporal real.

---

## 8. Logica Comun de Entrenamiento

La logica compartida vive en `train_utils.py`.

### 8.1 Reproducibilidad y dispositivo

- `set_seed(...)` fija semillas de Python, NumPy y PyTorch.
- `get_device()` usa CUDA si esta disponible.

### 8.2 Estandarizacion

Los modelos PyTorch aplican z-score con:

- `standardize_fit(X)` sobre train,
- `standardize_apply(X, mean, std)` sobre val y test.

Detalles relevantes:

- limpia `NaN` e infinitos antes y despues,
- protege contra desviaciones tipicas casi nulas,
- guarda `x_mean.npy` y `x_std.npy` como parte del experimento.

### 8.3 Codificacion estable de etiquetas

`fit_label_encoder(y_train)` fuerza, en el caso binario, el orden:

- `BENIGN` -> 0
- clase positiva restante -> 1

Esto mantiene coherente el calculo de ROC-AUC y la interpretacion de la clase positiva en todos los runs.

### 8.4 Entrenamiento PyTorch

`train_torch_classifier(...)` implementa:

- bucle de entrenamiento por epocas,
- `CrossEntropyLoss`,
- `AdamW`,
- AMP cuando hay GPU,
- clipping de gradiente,
- early stopping.

La seleccion del mejor modelo no se hace solo por `val_loss`. Usa esta puntuacion:

```text
score = val_loss + gap_weight * max(0, val_loss - train_loss)
```

Eso penaliza modelos con mucha separacion entre train y validation, es decir, modelos que ya muestran sobreajuste.

Cada mejora guarda inmediatamente `best_model.pt`.

---

## 9. Familias de Modelos Implementadas

### 9.1 Offline ML binario con HGB

Archivo: `train_ml_binary_hgb.py`

Implementacion:

- dataset: `MachineLearningCVE`
- pipeline: `binary`
- modelo: `HistGradientBoostingClassifier`
- splits soportados: `day`, `groupkfold`

Este script representa el baseline clasico offline sobre datos tabulares ya procesados.

### 9.2 Offline ML binario con MLP

Archivo: `train_ml_binary_mlp.py`

Implementacion:

- dataset: `MachineLearningCVE`
- pipeline: `binary`
- entrenamiento sobre split `random`
- arquitectura: `MLP` en `models_torch.py`

Ademas del test sobre random, reutiliza el mismo modelo entrenado para generar reportes sobre:

- `day`
- `groupkfold/fold_4`

Es decir, entrena una vez y evalua su capacidad de generalizacion sobre otros esquemas de particion.

### 9.3 Offline ML binario con FT-Transformer

Archivo: `train_ml_binary_fttransformer.py`

Implementacion:

- dataset: `MachineLearningCVE`
- pipeline: `binary`
- entrenamiento sobre split `random`
- arquitectura: `FTTransformer`

El modelo proyecta cada feature numerica como un token, pasa esos tokens por un `TransformerEncoder` y usa el pooling medio para clasificar.

### 9.4 Offline ML multiclase con HGB

Archivo: `train_ml_multiclass_hgb.py`

Implementacion:

- dataset: `MachineLearningCVE`
- pipeline: `multiclass`
- modelo: `HistGradientBoostingClassifier`
- splits: `random`, `day`, `groupkfold`

Es el clasificador multiclase principal del proyecto.

### 9.5 Online TL binario con HGB

Archivo: `train_tl_binary_hgb.py`

Implementacion:

- dataset: `TrafficLabelling`
- pipeline: `binary`
- modelo: `HistGradientBoostingClassifier`
- splits: `day`, `groupkfold`

Se usa para el escenario online con los datos etiquetados de flujo.

### 9.6 Online TL binario con regresion logistica en PyTorch

Archivo: `train_tl_binary_logreg_torch.py`

Implementacion:

- dataset: `TrafficLabelling`
- pipeline: `binary`
- modelo: `TorchLogReg`
- entrenamiento con la infraestructura PyTorch comun.

Es el baseline lineal dentro del escenario online.

### 9.7 Deteccion de anomalias con Isolation Forest

Archivo: `train_anomaly_isoforest.py`

Implementacion:

- dataset: `TrafficLabelling` o `MachineLearningCVE`
- pipeline: `anomaly`
- modelo: `IsolationForest`
- train con trafico benigno puro,
- evaluacion en validation y test mixtos.

Los scores se invierten con `-model.score_samples(X)` para que un valor mayor signifique mas anomalia.

### 9.8 Modelo secuencial GRU

Archivo: `train_seq_tl_gru.py`

Implementacion:

- dataset: secuencias derivadas de `TrafficLabelling`
- tareas: `binary`, `multiclass_grouped`, `multiclass`
- modelo: `GRUClassifier`
- entrada real: tensores `(N, T, F)`

Antes de entrenar, el script aplana las secuencias para estandarizar y luego las reconstruye a su forma temporal.

---

## 10. Arquitecturas PyTorch

Todas estan definidas en `models_torch.py`.

### `TorchLogReg`

Una capa lineal `Linear(F, C)`. Sirve como baseline muy interpretable.

### `MLP`

Bloques repetidos de:

- `Linear`
- `ReLU`
- `Dropout`

y una capa final de clasificacion.

### `FTTransformer`

Para cada feature:

- aplica `Linear(1, d_model)`
- apila tokens
- pasa por `TransformerEncoder`
- hace mean pooling
- clasifica con una cabeza final.

### `GRUClassifier`

Usa una GRU sobre la secuencia temporal y clasifica usando el ultimo timestep.

### Modelos adicionales

`models_torch.py` tambien incluye `LSTMClassifier` y `Autoencoder`, pero en la orquestacion actual no aparecen como parte del pipeline principal ejecutado por scripts.

---

## 11. Evaluacion y Reporting

### 11.1 Metricas de clasificacion

`metrics.py` calcula:

- accuracy
- balanced accuracy
- macro F1
- weighted F1
- matriz de confusion
- classification report

### 11.2 Metricas de anomalias

Para `IsolationForest` se usan:

- ROC-AUC
- PR-AUC
- mejor F1 segun threshold
- mejor threshold encontrado sobre la curva precision-recall

### 11.3 Plots y artefactos visuales

`reporting.py` genera, segun el tipo de modelo:

- `confusion_train.png`, `confusion_val.png`, `confusion_test.png`
- `roc_curve.png` en binario
- `calibration.png`
- `curve_loss.png` y `curve_accuracy.png` en modelos PyTorch
- `corr_matrix.png`

Tambien guarda ficheros `metrics_<split>.json` con las metricas usadas por la comparativa global.

---

## 12. Persistencia de Artefactos

Todos los entrenamientos versionan su salida en:

```text
src/models/CIC-IDS2017/artifacts/<model_name>/<split_mode>/<run_id>/
```

Donde `run_id` se genera con timestamp (`YYYYMMDD_HHMMSS`).

Dependiendo del tipo de modelo, el directorio puede incluir:

- `model.joblib` o `best_model.pt`
- `label_map.json`
- `x_mean.npy`
- `x_std.npy`
- `history.csv`
- `results.json`
- `summary.json`
- `metrics_train.json`, `metrics_val.json`, `metrics_test.json`
- carpeta `plots/`
- subcarpetas `fold_k/` para experimentos `groupkfold`

---

## 13. Orquestacion Completa

El script `src/scripts/cic_run_all_models.ps1` ejecuta la bateria principal de experimentos.

### Orden actual de ejecucion

1. `train_tl_binary_logreg_torch.py` con `day`
2. `train_tl_binary_logreg_torch.py` con `groupkfold`, `fold 4`
3. `train_tl_binary_hgb.py` con `day`
4. `train_tl_binary_hgb.py` con `groupkfold`, `fold 4`
5. `train_ml_binary_hgb.py` con `day`
6. `train_ml_binary_hgb.py` con `groupkfold`, `fold 4`
7. `train_ml_binary_mlp.py`
8. `train_ml_binary_fttransformer.py`
9. `train_ml_multiclass_hgb.py` con `random`
10. `train_anomaly_isoforest.py` con `TrafficLabelling`, `day`
11. `train_anomaly_isoforest.py` con `TrafficLabelling`, `groupkfold`, `fold 4`
12. `train_seq_tl_gru.py` con `day`, tarea `binary`
13. `train_seq_tl_gru.py` con `groupkfold`, `fold 4`, tarea `binary`
14. `compare_models.py`

Este script es, en la practica, la receta reproducible del pipeline experimental completo.

---

## 14. Comparacion Final de Modelos

`compare_models.py` recorre `artifacts/` y busca resultados en:

- `metrics_test.json`, si existe,
- o `results.json` como fallback.

De cada run extrae, cuando estan disponibles:

- `test_accuracy`
- `test_macro_f1`
- `test_macro_recall`
- `test_logloss`
- `test_roc_auc`
- `test_ece`

Luego:

1. construye un `DataFrame` con todos los experimentos,
2. lo ordena priorizando `roc_auc`, si existe,
3. si no existe, usa `macro_f1`,
4. y si tampoco existe, usa `accuracy`.

La salida final se escribe en:

```text
src/models/CIC-IDS2017/artifacts/compare_models/<timestamp>/
```

con dos ficheros principales:

- `comparison.csv`
- `comparison.md`

Ese es el resultado final consolidado del proyecto a nivel experimental: una tabla comparable entre todos los modelos entrenados.

---

## 15. Resumen Ejecutivo de la Logica del Codigo

La logica completa del proyecto sigue esta estrategia:

1. Convertir los CSV crudos de CIC-IDS2017 en datasets Parquet limpios, coherentes y reproducibles.
2. Separar los datos segun varios escenarios de evaluacion: temporal, por folds de archivo y aleatorio.
3. Construir objetivos diferentes para responder a tres problemas distintos: clasificacion binaria, clasificacion multiclase y deteccion de anomalias.
4. Añadir una segunda via de modelado basada en secuencias, agrupando trafico por entidad de red y generando ventanas temporales.
5. Entrenar varias familias de modelos, desde baselines clasicos hasta modelos PyTorch mas expresivos.
6. Evaluar todos los experimentos con una capa comun de metricas y reporting.
7. Guardar todos los resultados en una estructura de artefactos trazable por modelo, split y fecha.
8. Consolidar las metricas test en una comparativa final unica.

En otras palabras: el proyecto no es solo un conjunto de scripts de entrenamiento, sino un pipeline completo de experimentacion reproducible para IDS/IPS con datos tabulares y secuenciales sobre CIC-IDS2017.