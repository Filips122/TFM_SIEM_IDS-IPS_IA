# STRATEGY_NUSW-NB15

## Objective

This document defines the implementation strategy for adding a **NUSW-NB15** experimentation pipeline to the project, following the same general philosophy already used for CIC-IDS2017:

- reproducible preprocessing from raw CSV files,
- explicit split strategies,
- reusable tabular datasets in Parquet format,
- comparable model training and evaluation,
- artifact persistence for later comparison.

The NUSW-NB15 pipeline is intentionally introduced in **phases**. The first version focuses on:

- simple dataset inspection and preprocessing-oriented EDA,
- tabular binary classification,
- tabular multiclass classification,
- anomaly detection,
- model comparison and reproducibility.

It does **not** attempt to implement streaming inference, SIEM correlation, or sequential modeling in the first iteration.

---

## End-to-End Flow

1. Raw NUSW-NB15 CSV files are inspected to validate schema, labels, missing values, and categorical columns.
2. Input columns, labels, and dtypes are normalized.
3. Binary, multiclass, and anomaly targets are generated.
4. Cleaned datasets are written to Parquet using a structure compatible with the CIC-IDS2017 pipeline.
5. Training scripts load those Parquet splits and train baseline models.
6. Metrics, plots, and summaries are generated per run.
7. Results are written to `artifacts/` using timestamped run folders.
8. Final model comparison consolidates all NUSW-NB15 runs into a single comparable table.

---

## 1. Data Sources

### Input root

The raw dataset root for this pipeline is:

```text
out/NUSW-NB15/
```

### Available files detected in the repository

The current workspace contains the following relevant files:

- `out/NUSW-NB15/UNSW_NB15_training-set.csv`
- `out/NUSW-NB15/UNSW_NB15_testing-set.csv`
- `out/NUSW-NB15/UNSW-NB15_1.csv`
- `out/NUSW-NB15/UNSW-NB15_2.csv`
- `out/NUSW-NB15/UNSW-NB15_3.csv`
- `out/NUSW-NB15/UNSW-NB15_4.csv`
- `out/NUSW-NB15/NUSW-NB15_features.csv`
- `out/NUSW-NB15/train_test_network.csv`

### Dataset role by file type

The first implementation phase should use two complementary sources:

#### A. Official supervised split files

- `UNSW_NB15_training-set.csv`
- `UNSW_NB15_testing-set.csv`

Why:

- they already provide a canonical supervised split,
- they are widely used in published benchmarking,
- they simplify the first reproducible baseline.

#### B. Four-part raw export

- `UNSW-NB15_1.csv`
- `UNSW-NB15_2.csv`
- `UNSW-NB15_3.csv`
- `UNSW-NB15_4.csv`

Why:

- they support grouped split strategies by source file,
- they provide broader raw coverage than a fixed train/test pair,
- they are better suited for building CIC-style reusable datasets.

#### C. Feature dictionary

- `NUSW-NB15_features.csv`

Why:

- it acts as the authoritative feature description reference,
- it helps justify type handling and preprocessing decisions.

#### D. Secondary network-oriented file

- `train_test_network.csv`

Why deferred:

- it appears to represent a different schema and provenance,
- it should not be mixed into the primary NUSW-NB15 tabular pipeline without a separate design decision,
- it may be useful later for a network-log-oriented extension, but not in version 1.

---

## 2. Implementation Scope for Version 1

The NUSW-NB15 pipeline should initially mirror the **tabular** branch of CIC-IDS2017, not the full end-state thesis architecture.

### Included in version 1

- dataset inspection and preprocessing-oriented EDA,
- chunk-based CSV preprocessing,
- Parquet dataset generation,
- binary target construction,
- multiclass target construction,
- anomaly dataset construction,
- random split strategy,
- grouped split strategy,
- baseline training scripts,
- artifact persistence,
- final comparison report.

### Excluded from version 1

- sequential dataset generation,
- GRU/LSTM sequence training,
- real-time ingestion,
- SIEM integration,
- Suricata or Zeek correlation,
- automated response logic,
- multi-source enrichment.

These capabilities may be added later, but they are out of scope for the initial NUSW-NB15 implementation.

---

## 3. Simple EDA and Inspection Layer

Before training, the project should include a lightweight inspection stage for NUSW-NB15, similar in purpose to the current CIC helpers.

### EDA goals

The first inspection utility should answer the following questions:

- how many rows and columns each CSV contains,
- whether schemas differ between the official split files and the four raw files,
- which columns are numeric versus categorical,
- which columns contain missing values,
- whether non-finite or placeholder values are present,
- what the label balance looks like for binary classification,
- what the class distribution looks like for multiclass classification,
- whether duplicate rows are likely present.

### Why this step matters

This EDA is not meant to be a separate research product. Its main role is to provide defensible preprocessing assumptions before dataset generation starts.

### Recommended inspection outputs

- per-file schema summary,
- label distribution summary,
- categorical cardinality summary,
- missing-value report,
- dataset comparison between file families.

---

## 4. Column and Label Characteristics

Based on the detected NUSW-NB15 files, the supervised train/test files include columns such as:

- `id`
- `dur`
- `proto`
- `service`
- `state`
- numeric traffic statistics such as bytes, packets, rates, and timing fields,
- `attack_cat`
- `label`

The feature dictionary also confirms the presence of network-relevant fields such as:

- source and destination IP information,
- ports,
- protocol,
- state,
- duration,
- bytes,
- packet counts,
- jitter and timing information.

### Important preprocessing implication

Unlike the CIC MachineLearningCVE branch, NUSW-NB15 contains clearly important categorical columns such as:

- `proto`
- `service`
- `state`

These should not be discarded by default. Version 1 should explicitly preserve and encode them for tabular models.

---

## 5. Base Tabular Preprocessing

The NUSW-NB15 preprocessing script should be implemented as a dataset-specific parallel to `src/models/CIC-IDS2017/prepare_dataset.py`.

Its main job is to transform the raw CSV files into stable, reusable Parquet datasets.

### 5.1 Chunk-based reading

All large CSV files should be processed with `pandas.read_csv(..., chunksize=...)`.

Why:

- it prevents excessive memory use,
- it keeps preprocessing consistent with the CIC-IDS2017 pipeline,
- it supports later scaling to the full dataset.

### 5.2 Column normalization

The preprocessing script should normalize column names by:

- trimming whitespace,
- removing BOM characters,
- collapsing duplicated spaces,
- preserving stable internal naming.

This avoids schema mismatches across input files.

### 5.3 Label normalization

The expected label-related columns are:

- `label`
- `attack_cat`

Recommended normalization:

- convert `label` into a stable binary interpretation,
- normalize `attack_cat` by trimming spaces and filling missing categories consistently,
- treat `Normal` as the benign class.

### 5.4 Missing and infinite values

The preprocessing layer should:

- convert textual and numeric infinite values to `NaN`,
- preserve missingness until the final feature matrix stage,
- avoid implicit type corruption caused by mixed values.

### 5.5 Numeric and categorical handling

Numeric columns should be coerced to numeric dtypes where possible.

Categorical columns such as `proto`, `service`, and `state` should be explicitly retained and encoded using a reproducible policy.

Recommended version 1 policy:

- fit categorical encoding from train data only,
- apply the same mapping to validation and test,
- reserve an unknown category for unseen values.

### 5.6 Stable Parquet schema

Like CIC-IDS2017, the script should enforce stable dtypes before writing Parquet.

Why:

- chunked processing can otherwise produce inconsistent schemas,
- pyarrow is sensitive to dtype mismatches across shards,
- stable schemas simplify later loading and model training.

---

## 6. Target Construction

The NUSW-NB15 implementation should support three version-1 objectives.

### 6.1 Binary target

Binary target should map:

- `Normal` -> `BENIGN`
- any non-normal attack category -> `ATTACK`

This creates the most directly comparable IDS baseline.

### 6.2 Multiclass target

Multiclass target should use normalized `attack_cat` values.

Expected categories depend on the dataset content, but typical examples include classes such as:

- `Normal`
- `Generic`
- `Exploits`
- `Fuzzers`
- `DoS`
- `Reconnaissance`
- `Analysis`
- `Backdoor`
- `Shellcode`
- `Worms`

The exact category list should be derived from the observed files during preprocessing.

### 6.3 Anomaly target

The anomaly pipeline should be constructed similarly to the CIC Isolation Forest setup:

- training uses only benign samples,
- validation and test contain benign and attack traffic,
- the output target remains binary: `BENIGN` or `ATTACK`.

### 6.4 Grouped anomaly train policy (implemented)

For `groupkfold`, some folds built from `UNSW-NB15_{1..4}.csv` can contain no benign rows in the training source files.

To keep this behavior explicit and reproducible, preprocessing now supports a policy switch:

- `strict` (default): do not inject extra data. If no benign samples exist, anomaly training for that fold is expected to be skipped.
- `fallback_official_benign`: if grouped training has zero benign rows, inject benign-only rows from `UNSW_NB15_training-set.csv` into `anomaly/train_benign` for that fold.

Each grouped fold writes an `anomaly_policy.json` file documenting:

- selected policy,
- whether fallback was applied,
- fallback source file,
- number of injected benign rows.

This keeps anomaly behavior auditable in both strict and fallback evaluation protocols.

---

## 7. Split Strategies

The user requested that version 1 support both **random** and **grouped** splitting from the start.

### 7.1 Random split

Random split should:

- operate over the combined dataset,
- use a fixed random seed,
- preserve reproducibility,
- default to ratios similar to CIC, for example `train=0.70`, `val=0.15`, `test=0.15`.

This is the simplest general-purpose baseline.

### 7.2 Grouped split

Grouped split should use source-file identity for the four raw files:

- `UNSW-NB15_1.csv`
- `UNSW-NB15_2.csv`
- `UNSW-NB15_3.csv`
- `UNSW-NB15_4.csv`

Recommended policy:

- one file used as test,
- one file used as validation,
- remaining files used as training,
- repeated over all available grouped folds.

This mirrors the CIC file-based grouping idea while adapting it to NUSW-NB15.

For anomaly experiments on grouped splits, report which policy was used (`strict` vs `fallback_official_benign`) and avoid mixing both policy types in a single aggregated headline metric.

### 7.3 Optional official fixed split

In addition to random and grouped modes, the project should preserve the official supervised train/test pair as an optional evaluation path.

Why:

- it improves comparability with published UNSW-NB15 baselines,
- it gives the project both a benchmark-aligned split and a custom reproducible split pipeline.

---

## 8. Writing the Dataset to Parquet

The output should be written under:

```text
src/models/NUSW-NB15/datasets/
```

### 8.1 Output structure

The structure should stay aligned with CIC-IDS2017 whenever possible.

For supervised pipelines:

```text
datasets/<split_mode>/<dataset>/<pipeline>/<split>/*.parquet
```

For grouped splits:

```text
datasets/groupkfold/<dataset>/fold_k/<pipeline>/<split>/*.parquet
```

For anomaly:

```text
datasets/<split_mode>/<dataset>/anomaly/train_benign/*.parquet
datasets/<split_mode>/<dataset>/anomaly/val_mixed/*.parquet
datasets/<split_mode>/<dataset>/anomaly/test_mixed/*.parquet
```

### 8.2 Persisted statistics

Each preprocessing run should also write a `stats.json` file summarizing:

- rows per split,
- benign versus attack counts,
- multiclass distribution,
- file participation in grouped splits.

---

## 9. Data Loading and Shared Infrastructure

The NUSW-NB15 pipeline should reuse as much of the CIC shared infrastructure as possible.

### Components that should be reused or lightly adapted

- `data_loader.py`
- `metrics.py`
- `reporting.py`
- `models_torch.py`
- `train_utils.py`
- `compare_models.py`

### Main adaptation required

The current helper logic in the CIC area assumes CIC-specific path roots. That path handling should be generalized or wrapped so the same loading and artifact conventions work for NUSW-NB15.

### Design principle

Keep the refactor narrow and low-risk. The goal is not to redesign the whole repository into a new framework. The goal is to let NUSW-NB15 reuse the proven CIC flow with minimal duplication.

---

## 10. Initial Model Families

The first NUSW-NB15 implementation should start with strong, interpretable baselines.

### 10.1 Binary HGB baseline

Equivalent role to the CIC offline binary HGB classifier:

- task: binary classification,
- model: `HistGradientBoostingClassifier`,
- split support: random and grouped,
- optional support for the official train/test split.

### 10.2 Multiclass HGB baseline

Equivalent role to the CIC multiclass tabular classifier:

- task: multiclass classification,
- model: `HistGradientBoostingClassifier`,
- split support: random and grouped,
- optional support for the official train/test split.

### 10.3 Anomaly baseline

Equivalent role to the CIC anomaly detector:

- task: anomaly detection,
- model: `IsolationForest`,
- train only on benign,
- evaluate on mixed validation and test splits.

### 10.4 Optional first deep model

If the baseline pipeline is stable, an optional next step is:

- binary MLP trained on the random split.

This should remain secondary to the tabular baseline models.

---

## 11. Evaluation and Reporting

The NUSW-NB15 pipeline should preserve the same reporting philosophy as CIC-IDS2017.

### 11.1 Classification metrics

For supervised classification:

- accuracy,
- balanced accuracy,
- macro F1,
- weighted F1,
- confusion matrix,
- classification report,
- ROC-AUC when binary probabilities are available,
- calibration metrics when applicable.

### 11.2 Anomaly metrics

For Isolation Forest:

- ROC-AUC,
- PR-AUC,
- best F1 over threshold,
- selected threshold.

### 11.3 Visual artifacts

When supported by the model type, the pipeline should generate:

- confusion matrices,
- ROC curves,
- calibration plots,
- training curves for PyTorch models,
- feature correlation plots.

---

## 12. Artifact Persistence

All run outputs should be written under:

```text
src/models/NUSW-NB15/artifacts/<model_name>/<split_mode>/<run_id>/
```

Where `run_id` is timestamp-based.

Typical contents should include:

- `model.joblib` or `best_model.pt`
- `label_map.json`
- `x_mean.npy`
- `x_std.npy`
- `history.csv`
- `results.json`
- `summary.json`
- `metrics_train.json`
- `metrics_val.json`
- `metrics_test.json`
- `plots/`
- `fold_k/` subfolders for grouped experiments

---

## 13. Full Orchestration

After the first model scripts exist, a NUSW orchestration script should be added, similar in role to `src/scripts/cic_run_all_models.ps1`.

### Recommended initial execution order

1. run NUSW preprocessing,
2. run NUSW inspection or EDA utility,
3. train binary HGB,
4. train multiclass HGB,
5. train anomaly Isolation Forest,
6. optionally train binary MLP,
7. run final comparison.

This keeps the first version focused and easy to validate.

---

## 14. Final Model Comparison

The NUSW-NB15 area should include a comparison step equivalent to the CIC pipeline.

The comparison script should:

1. scan the NUSW artifact tree,
2. extract available test metrics,
3. build a single comparable table,
4. rank runs by the most informative available metric,
5. save both CSV and Markdown outputs.

In addition to detailed per-run outputs, the current implementation also emits:

- aggregated comparison outputs with mean and standard deviation by model and split mode,
- skipped-fold diagnostics,
- missing-metrics diagnostics.

This is especially important for grouped anomaly runs where strict policy may produce valid skips.

Suggested output folder:

```text
src/models/NUSW-NB15/artifacts/compare_models/<timestamp>/
```

---

## 15. Verification Workflow

The implementation should be validated in the following order:

1. run the simple EDA utility on the raw NUSW files,
2. verify schemas and label distributions,
3. generate Parquet datasets for random and grouped modes,
4. verify that train, validation, and test splits expose a stable feature matrix,
5. execute one binary HGB training run,
6. execute one multiclass HGB training run,
7. execute one anomaly run,
8. verify that final comparison works over the generated artifacts.

When `groupkfold` anomaly is included, verification should also confirm:

- whether fold skips are expected under strict policy,
- whether fallback injections are recorded in `anomaly_policy.json` when fallback mode is enabled,
- whether comparison outputs classify these cases correctly (ok/skipped/missing).

---

## 16. Executive Summary of the NUSW-NB15 Logic

The NUSW-NB15 implementation should follow this practical strategy:

1. inspect the raw CSV files and document their schema and label behavior,
2. convert them into stable, clean, reusable Parquet datasets,
3. support both random and grouped evaluation from the first version,
4. start with strong tabular baselines for binary, multiclass, and anomaly tasks,
5. keep results reproducible and traceable through standardized artifacts,
6. preserve compatibility with the CIC-style evaluation and comparison workflow.

In short: the NUSW-NB15 pipeline should be a **parallel, phased, tabular-first extension** of the existing CIC-IDS2017 experimentation framework.