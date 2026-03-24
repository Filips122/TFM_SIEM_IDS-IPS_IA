# STRATEGY_CIC-IDS2017

## Objective

This document describes how the code logic is implemented in the project, from reading the original CIC-IDS2017 CSV files to generating metrics, plots, and final model comparisons.

The main pipeline lives in `src/models/CIC-IDS2017/` and relies on two data sources:

- `src/datasets/CIC-IDS2017/MachineLearningCVE`: offline view of the dataset.
- `src/datasets/CIC-IDS2017/TrafficLabelling`: online view with flow metadata such as IPs, Flow ID, and Timestamp.

---

## End-to-End Flow

1. The original CSV files are read in chunks so everything is not loaded into memory at once.
2. Columns, labels, and data types are normalized.
3. Invalid labels and infinite values are cleaned.
4. Features are converted to numeric values and stable dtypes are enforced.
5. Targets are generated depending on the task: binary, multiclass, grouped multiclass, or anomalies.
6. Intermediate datasets are written to Parquet with a folder structure organized by split mode.
7. The training scripts load those Parquet files, build `X` and `y`, and train the corresponding model.
8. Metrics, curves, and confusion matrices are computed.
9. Artifacts versioned by date are stored in `artifacts/`.
10. `compare_models.py` consolidates test metrics from all runs and produces the final comparison.

---

## 1. Data Sources

### Input datasets

- `MachineLearningCVE` is used for offline models based on classical tabular classification.
- `TrafficLabelling` is used for the online scenario, for tabular transfer learning, and for the sequential pipeline.

### Auxiliary inspection scripts

In `src/helpers/` there are supporting utilities to inspect the dataset before training:

- `analyze_cic_folder.py`
- `list_columns.py`
- `schema_check.py`

They are not part of training itself, but they help validate that the original CSV files have the expected schema.

---

## 2. Base Tabular Preprocessing

The main normalization and cleaning logic is implemented in `prepare_dataset.py`. The goal of this file is to convert large and heterogeneous CSV files into consistent and reusable Parquet files.

### 2.1 Chunk-based reading

Each CSV is processed with `pandas.read_csv(..., chunksize=...)`. This avoids loading complete CIC-IDS2017 files into memory and allows the result to be written incrementally.

### 2.2 Column normalization

Several common routines are applied:

- `normalize_colname(c)`: removes BOM, duplicate spaces, and normalizes names.
- `find_label_col(cols)`: automatically detects the target column by searching for aliases such as `label`, `class`, `attack`, or `attacktype`.
- `normalize_label(s)`: trims spaces, normalizes hyphens, and unifies textual label variants.

This prevents small formatting differences between CSV files from breaking the pipeline.

### 2.3 Label cleaning

The function `drop_bad_labels(df, label_col)` removes rows with labels that are:

- null,
- empty,
- or converted to the text `nan`.

This is especially important for `TrafficLabelling`, where columns may contain noise or inconsistent cells.

### 2.4 Handling infinities and NaN

`replace_inf_with_nan(df)` replaces:

- `np.inf`
- `-np.inf`
- strings such as `Infinity`, `-Infinity`, `inf`

with `NaN`.

The goal is to ensure the numeric conversion and standardization pipeline does not fail because of extreme values inherited from the raw dataset.

### 2.5 Conversion to numeric

`coerce_numeric_features(df, label_col, dataset_name)` attempts to convert all columns to numeric except:

- the label column,
- and in `TrafficLabelling`, the metadata columns: `Flow ID`, `Source IP`, `Destination IP`, `Timestamp`.

These metadata columns are preserved when keeping online context is useful, but they do not participate as features in the tabular model.

### 2.6 Stable dtypes

`force_stable_numeric_dtypes(...)` forces all numeric features to `float64` before writing to Parquet. This solves a practical problem: if one chunk comes out as `int64` and another as `float64`, `pyarrow` may detect different schemas and fail or generate inconsistent datasets.

### 2.7 TrafficLabelling specifics

In `preprocess_chunk(...)`:

- `Timestamp` is parsed with `pd.to_datetime(errors="coerce")`.
- `Flow ID`, `Source IP`, and `Destination IP` are forced to `str`.

This keeps context columns separate from numeric features.

---

## 3. Target Construction

The project does not use a single objective. It builds different targets depending on the experiment.

### 3.1 Binary pipeline

`make_binary_target(labels)` transforms:

- `BENIGN` -> `BENIGN`
- any attack -> `ATTACK`

This is the most commonly used pipeline in binary IDS experiments.

### 3.2 Multiclass pipeline

`make_multiclass_target(labels)` leaves the normalized label exactly as it appears in the dataset.

### 3.3 Grouped multiclass pipeline

`make_grouped_target(labels)` groups attacks into larger families:

- `Web Attack *` -> `WebAttack`
- `DoS *` -> `DoS`
- attacks containing `Patator` -> `BruteForce`
- other specific classes such as `DDoS`, `PortScan`, `Bot`, `Infiltration`, `Heartbleed`
- anything else -> `OtherAttack`

This reduces class fragmentation and enables a more stable multicategory problem.

### 3.4 Anomaly pipeline

Instead of full supervised classification:

- `train` uses only `BENIGN` traffic.
- `val` and `test` are stored as mixed datasets with the binary target `BENIGN` or `ATTACK`.

This setup is designed specifically for `IsolationForest`.

---

## 4. Split Strategies

`prepare_dataset.py` supports three ways of splitting the data.

### 4.1 `day`

The temporal split is defined by filename:

- Monday, Tuesday, Wednesday -> `train`
- Thursday -> `val`
- Friday -> `test`

This is the most realistic temporal evaluation, because it forces the model to generalize to traffic from future days.

### 4.2 `groupkfold`

It does not use KFold over rows, but over files/days:

- `fold_k` uses one CSV as test,
- the next CSV as validation,
- and the rest as train.

This prevents rows from the same file from being mixed between train and test.

### 4.3 `random`

It generates random row-level masks using a reproducible RNG.

Important implementation points:

- it uses the same base mask for all pipelines of the same CSV,
- it allows binary, multiclass, and anomaly pipelines to be compared on exactly the same partition,
- default ratios: `train=0.70`, `val=0.15`, `test=0.15`.

---

## 5. Writing the Tabular Dataset to Parquet

The output of `prepare_dataset.py` is written to `src/models/CIC-IDS2017/datasets/`.

### 5.1 Output structure

For supervised pipelines:

```text
datasets/<split_mode>/<dataset>/<pipeline>/<split>/*.parquet
```

For `groupkfold`:

```text
datasets/groupkfold/<dataset>/fold_k/<pipeline>/<split>/*.parquet
```

For anomalies:

```text
datasets/<split_mode>/<dataset>/anomaly/train_benign/*.parquet
datasets/<split_mode>/<dataset>/anomaly/val_mixed/*.parquet
datasets/<split_mode>/<dataset>/anomaly/test_mixed/*.parquet
```

### 5.2 Persisted statistics

After processing each dataset, `write_stats(...)` generates `stats.json` with:

- number of rows per split,
- count of benign and attack samples,
- label distribution.

This serves as quality control for preprocessing and class distribution.

---

## 6. Sequential Dataset Generation

The sequential part is implemented in `prepare_sequence_dataset.py` and is based exclusively on `TrafficLabelling`.

### 6.1 Idea of the sequential pipeline

Instead of classifying each isolated flow, temporal windows of several consecutive flows from the same group are built.

### 6.2 Sequence grouping

Sequences can be grouped by:

- `source_ip`
- `flow_id`
- `five_tuple`

The function `get_group_id(...)` builds the group identifier and maintains a sliding buffer per group.

### 6.3 Sliding windows

For each group, a `deque(maxlen=window_size)` is maintained. When the buffer reaches the window size:

- a sequential sample is generated,
- `stride` is applied,
- the window is flattened into columns of the form `feature__t-k`.

The label used for the sequence is the one from the last flow in the window.

### 6.4 Sequence flattening

The function `flatten_window(window, feat_names, window_size)` generates columns such as:

- `Flow Duration__t-19`
- `Flow Duration__t-18`
- ...
- `Flow Duration__t-0`

This makes it possible to store sequences in Parquet without losing the ability to reconstruct the `(N, T, F)` shape later.

### 6.5 Sequential output

The sequences are stored in:

```text
datasets/sequence/<mode>/TrafficLabelling/<task>/<split>/*.parquet
datasets/sequence/groupkfold/TrafficLabelling/<task>/fold_k/<split>/*.parquet
```

In addition, each run writes:

- `sequence_meta.json`
- `sequence_stats.json`

with window configuration, stride, grouping, and target counts.

---

## 7. Data Loading for Training

### 7.1 Tabular loading

`data_loader.py` is responsible for:

- locating the correct split folder,
- reading all Parquet files for the split,
- concatenating them into a `DataFrame`,
- inferring valid numeric columns,
- returning `LoadedSplit(X, y, feature_names)`.

`_infer_numeric_feature_columns(...)` ignores non-numeric columns, `target`, and `label_raw`. This allows `TrafficLabelling` to retain metadata without breaking training.

### 7.2 Sequential loading

`sequence_loader.py`:

- detects `__t-k` columns,
- infers `window_size`,
- reconstructs temporal order,
- reshapes the flat `(N, T*F)` representation back into `(N, T, F)`.

This way, the sequential dataset is serialized flat, but trained with real temporal structure.

---

## 8. Shared Training Logic

The shared logic lives in `train_utils.py`.

### 8.1 Reproducibility and device

- `set_seed(...)` sets seeds for Python, NumPy, and PyTorch.
- `get_device()` uses CUDA if available.

### 8.2 Standardization

PyTorch models apply z-score normalization with:

- `standardize_fit(X)` on train,
- `standardize_apply(X, mean, std)` on val and test.

Relevant details:

- it cleans `NaN` and infinities before and after,
- it protects against near-zero standard deviations,
- it saves `x_mean.npy` and `x_std.npy` as part of the experiment.

### 8.3 Stable label encoding

`fit_label_encoder(y_train)` forces, in the binary case, the order:

- `BENIGN` -> 0
- remaining positive class -> 1

This keeps ROC-AUC computation and positive-class interpretation consistent across all runs.

### 8.4 PyTorch training

`train_torch_classifier(...)` implements:

- epoch-based training loop,
- `CrossEntropyLoss`,
- `AdamW`,
- AMP when GPU is available,
- gradient clipping,
- early stopping.

The best model is not selected only by `val_loss`. It uses this score:

```text
score = val_loss + gap_weight * max(0, val_loss - train_loss)
```

This penalizes models with a large gap between train and validation, i.e. models already showing overfitting.

Each improvement immediately saves `best_model.pt`.

---

## 9. Implemented Model Families

### 9.1 Offline binary ML with HGB

File: `train_ml_binary_hgb.py`

Implementation:

- dataset: `MachineLearningCVE`
- pipeline: `binary`
- model: `HistGradientBoostingClassifier`
- supported splits: `day`, `groupkfold`

This script represents the classic offline baseline on already processed tabular data.

### 9.2 Offline binary ML with MLP

File: `train_ml_binary_mlp.py`

Implementation:

- dataset: `MachineLearningCVE`
- pipeline: `binary`
- training on the `random` split
- architecture: `MLP` in `models_torch.py`

In addition to test evaluation on the random split, it reuses the same trained model to generate reports on:

- `day`
- `groupkfold/fold_4`

That is, it trains once and evaluates its generalization ability on other partition schemes.

### 9.3 Offline binary ML with FT-Transformer

File: `train_ml_binary_fttransformer.py`

Implementation:

- dataset: `MachineLearningCVE`
- pipeline: `binary`
- training on the `random` split
- architecture: `FTTransformer`

The model projects each numeric feature as a token, passes those tokens through a `TransformerEncoder`, and uses mean pooling for classification.

### 9.4 Offline multiclass ML with HGB

File: `train_ml_multiclass_hgb.py`

Implementation:

- dataset: `MachineLearningCVE`
- pipeline: `multiclass`
- model: `HistGradientBoostingClassifier`
- splits: `random`, `day`, `groupkfold`

This is the main multiclass classifier in the project.

### 9.5 Online binary TL with HGB

File: `train_tl_binary_hgb.py`

Implementation:

- dataset: `TrafficLabelling`
- pipeline: `binary`
- model: `HistGradientBoostingClassifier`
- splits: `day`, `groupkfold`

It is used for the online scenario with labeled flow data.

### 9.6 Online binary TL with logistic regression in PyTorch

File: `train_tl_binary_logreg_torch.py`

Implementation:

- dataset: `TrafficLabelling`
- pipeline: `binary`
- model: `TorchLogReg`
- training with the shared PyTorch infrastructure.

This is the linear baseline within the online scenario.

### 9.7 Anomaly detection with Isolation Forest

File: `train_anomaly_isoforest.py`

Implementation:

- dataset: `TrafficLabelling` or `MachineLearningCVE`
- pipeline: `anomaly`
- model: `IsolationForest`
- train on pure benign traffic,
- evaluation on mixed validation and test sets.

The scores are inverted with `-model.score_samples(X)` so that a higher value means more anomalous.

### 9.8 Sequential GRU model

File: `train_seq_tl_gru.py`

Implementation:

- dataset: sequences derived from `TrafficLabelling`
- tasks: `binary`, `multiclass_grouped`, `multiclass`
- model: `GRUClassifier`
- real input: `(N, T, F)` tensors

Before training, the script flattens the sequences for standardization and then reconstructs them into their temporal shape.

---

## 10. PyTorch Architectures

All of them are defined in `models_torch.py`.

### `TorchLogReg`

A single linear layer `Linear(F, C)`. It serves as a highly interpretable baseline.

### `MLP`

Repeated blocks of:

- `Linear`
- `ReLU`
- `Dropout`

and a final classification layer.

### `FTTransformer`

For each feature:

- applies `Linear(1, d_model)`
- stacks tokens
- passes them through `TransformerEncoder`
- performs mean pooling
- classifies with a final head.

### `GRUClassifier`

Uses a GRU over the temporal sequence and classifies using the last timestep.

### Additional models

`models_torch.py` also includes `LSTMClassifier` and `Autoencoder`, but in the current orchestration they do not appear as part of the main pipeline executed by scripts.

---

## 11. Evaluation and Reporting

### 11.1 Classification metrics

`metrics.py` computes:

- accuracy
- balanced accuracy
- macro F1
- weighted F1
- confusion matrix
- classification report

### 11.2 Anomaly metrics

For `IsolationForest`, the following are used:

- ROC-AUC
- PR-AUC
- best F1 according to threshold
- best threshold found on the precision-recall curve

### 11.3 Plots and visual artifacts

`reporting.py` generates, depending on the model type:

- `confusion_train.png`, `confusion_val.png`, `confusion_test.png`
- `roc_curve.png` for binary classification
- `calibration.png`
- `curve_loss.png` and `curve_accuracy.png` for PyTorch models
- `corr_matrix.png`

It also saves `metrics_<split>.json` files with the metrics used by the global comparison.

---

## 12. Artifact Persistence

All training runs version their output in:

```text
src/models/CIC-IDS2017/artifacts/<model_name>/<split_mode>/<run_id>/
```

Where `run_id` is generated with a timestamp (`YYYYMMDD_HHMMSS`).

Depending on the type of model, the directory may include:

- `model.joblib` or `best_model.pt`
- `label_map.json`
- `x_mean.npy`
- `x_std.npy`
- `history.csv`
- `results.json`
- `summary.json`
- `metrics_train.json`, `metrics_val.json`, `metrics_test.json`
- `plots/` folder
- `fold_k/` subfolders for `groupkfold` experiments

---

## 13. Full Orchestration

The script `src/scripts/cic_run_all_models.ps1` executes the main batch of experiments.

### Current execution order

1. `train_tl_binary_logreg_torch.py` with `day`
2. `train_tl_binary_logreg_torch.py` with `groupkfold`, `fold 4`
3. `train_tl_binary_hgb.py` with `day`
4. `train_tl_binary_hgb.py` with `groupkfold`, `fold 4`
5. `train_ml_binary_hgb.py` with `day`
6. `train_ml_binary_hgb.py` with `groupkfold`, `fold 4`
7. `train_ml_binary_mlp.py`
8. `train_ml_binary_fttransformer.py`
9. `train_ml_multiclass_hgb.py` with `random`
10. `train_anomaly_isoforest.py` with `TrafficLabelling`, `day`
11. `train_anomaly_isoforest.py` with `TrafficLabelling`, `groupkfold`, `fold 4`
12. `train_seq_tl_gru.py` with `day`, task `binary`
13. `train_seq_tl_gru.py` with `groupkfold`, `fold 4`, task `binary`
14. `compare_models.py`

In practice, this script is the reproducible recipe for the complete experimental pipeline.

---

## 14. Final Model Comparison

`compare_models.py` scans `artifacts/` and looks for results in:

- `metrics_test.json`, if it exists,
- or `results.json` as a fallback.

From each run it extracts, when available:

- `test_accuracy`
- `test_macro_f1`
- `test_macro_recall`
- `test_logloss`
- `test_roc_auc`
- `test_ece`

Then it:

1. builds a `DataFrame` with all experiments,
2. sorts it by prioritizing `roc_auc`, if available,
3. if not available, uses `macro_f1`,
4. and if that is not available either, uses `accuracy`.

The final output is written to:

```text
src/models/CIC-IDS2017/artifacts/compare_models/<timestamp>/
```

with two main files:

- `comparison.csv`
- `comparison.md`

That is the final consolidated experimental result of the project: a comparable table across all trained models.

---

## 15. Executive Summary of the Code Logic

The complete logic of the project follows this strategy:

1. Convert the raw CIC-IDS2017 CSV files into clean, consistent, and reproducible Parquet datasets.
2. Split the data according to several evaluation scenarios: temporal, file-based folds, and random.
3. Build different objectives to address three different problems: binary classification, multiclass classification, and anomaly detection.
4. Add a second modeling path based on sequences, grouping traffic by network entity and generating temporal windows.
5. Train several model families, from classical baselines to more expressive PyTorch models.
6. Evaluate all experiments with a shared metrics and reporting layer.
7. Store all results in an artifact structure traceable by model, split, and date.
8. Consolidate test metrics into a single final comparison.

In other words: the project is not just a set of training scripts, but a complete reproducible experimentation pipeline for IDS/IPS with tabular and sequential data on CIC-IDS2017.