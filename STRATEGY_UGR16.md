# STRATEGY_UGR16

## Objective

This document defines the implementation strategy for adding a **UGR16** experimentation pipeline to the project, following the same general philosophy already used for CIC-IDS2017 and UNSW-NB15:

- reproducible preprocessing from raw weekly flow archives,
- explicit split strategies,
- reusable tabular datasets in Parquet format,
- comparable model training and evaluation,
- artifact persistence for later comparison.

The UGR16 pipeline is intentionally introduced as a **reduced-subset, anomaly-oriented extension** rather than as a full replay of the entire raw corpus.

Version 1 focuses on:

- a storage-conscious subset of the best UGR16 files,
- tabular binary classification,
- anomaly detection,
- optional multiclass experimentation when weak labels are sufficient,
- model comparison and reproducibility,
- forward-in-time evaluation for concept drift.

It does **not** attempt to implement full raw-corpus ingestion, SIEM correlation, sequence models, or nfcapd reprocessing in the first iteration.

---

## End-to-End Flow

1. The selected UGR16 weekly flow archives are inspected to validate schema stability, weak labels, and timeline coverage.
2. The raw CSV members inside the selected tar archives are streamed in chunks.
3. The 13 stable raw columns are normalized into a consistent semantic schema.
4. Timestamps and temporal helper features are derived.
5. Flow-level targets are generated primarily from the raw weak label column, while matching `attack_ts` files are attached as temporal context.
6. Cleaned datasets are written to Parquet using a folder structure compatible with the CIC-IDS2017 and UNSW-NB15 pipelines.
7. Training scripts load those Parquet splits and train baseline models.
8. Metrics, plots, and summaries are generated per run.
9. Results are written to `artifacts/` using timestamped run folders.
10. Final model comparison consolidates all UGR16 runs into a single comparable table.

---

## 1. Data Sources

### Input root

The raw dataset root for this pipeline is:

```text
out/UGR16/
```

### Available file families

The current workspace contains four relevant UGR16 file families:

#### A. Main weekly flow archives

- `*_week*_csv.tar.gz`

Why:

- they contain the core weekly flow records,
- they are the best source for stable tabular modeling,
- they are already recommended by the repository UGR analysis helper,
- they avoid the complexity of reprocessing the raw `nfcapd` captures.

#### B. Matching attack timeline files

- `attack_ts_*.csv`

Why:

- they provide week-level temporal attack context,
- they help validate the split design and attack periods,
- they can be used as weak temporal supervision metadata,
- they are negligible in storage cost compared with the raw archives.

#### C. Attack-family archives

- `blacklist_*_csv.tar.gz`
- `spam_*_csv.tar.gz`
- `sshscan_*_csv.tar.gz`
- `udpscan_*_csv.tar.gz`
- `dos_*_csv.tar.gz`
- `scan11_*_csv.tar.gz`
- `scan44_*_csv.tar.gz`

Why deferred:

- they substantially increase the total storage footprint,
- they are better suited for targeted validation than for the primary version 1 pipeline,
- the main weekly flow archives already provide enough signal to start the first tabular implementation.

#### D. Raw `nfcapd` archives

- `*_nfcapd.tar.gz`

Why deferred:

- they are useful only if the project later requires raw flow reprocessing,
- they are not required for version 1 model training,
- keeping them out of scope avoids unnecessary ingestion complexity.

---

## 2. Best Files for Version 1

The full UGR16 tree is too large to treat as the default modeling input. The version 1 implementation should therefore use the **best files only**.

### Recommended thesis subset

The preferred subset for version 1 is:

- March 2016: Weeks 3, 4, and 5
- April 2016: Weeks 2, 3, 4, and 5
- May 2016: Weeks 1 through 6
- June 2016: Weeks 1 through 4
- July 2016: Week 5
- August 2016: Weeks 1, 2, 3, and 5

For every selected weekly flow archive, the matching `attack_ts_*.csv` file should also be used.

### Why this subset is preferred

- it keeps the best core files recommended by the repository UGR analysis,
- it preserves the long-duration behavior needed for drift experiments,
- it keeps August as the forward-in-time holdout period,
- it excludes `August - Week #4`, whose attack timeline file is empty in the current analysis output,
- it avoids the additional storage and redundancy of the attack-family archives.

### File selection policy

#### Core inputs for version 1

- selected main weekly flow archives,
- matching `attack_ts` files.

#### Deferred inputs for version 1

- attack-family archives,
- `nfcapd` archives.

---

## 3. Implementation Scope for Version 1

The UGR16 pipeline should initially mirror the **tabular** branch of the existing project, not the full end-state thesis architecture.

### Included in version 1

- reduced-subset archive selection,
- UGR16 preprocessing script for Parquet generation,
- date-based split strategy,
- random split strategy,
- grouped split strategy,
- binary target construction,
- anomaly dataset construction,
- optional multiclass dataset construction,
- baseline training scripts,
- artifact persistence,
- final comparison report.

### Excluded from version 1

- full 500 GB corpus ingestion,
- attack-family archive ingestion,
- `nfcapd` reprocessing,
- sequence models,
- GRU/LSTM pipelines,
- real-time ingestion,
- SIEM integration,
- Suricata or Zeek correlation,
- automated response logic.

These capabilities may be added later, but they are out of scope for the initial UGR16 implementation.

---

## 4. Column and Label Characteristics

Based on the current repository analysis outputs, the selected main UGR16 archives expose a stable 13-column schema.

### Working semantic mapping for version 1

The version 1 pipeline should use the following semantic interpretation:

- `col_1` -> `event_ts`
- `col_2` -> `duration`
- `col_3` -> `src_ip`
- `col_4` -> `dst_ip`
- `col_5` -> `src_port`
- `col_6` -> `dst_port`
- `col_7` -> `protocol`
- `col_8` -> `flags`
- `col_9` -> reserved constant-zero field
- `col_10` -> TTL-like numeric feature
- `col_11` -> packet count
- `col_12` -> byte count
- `col_13` -> raw weak label

This mapping is supported by the repository-generated UGR16 analysis and should be treated as the working schema for version 1.

### Important preprocessing implication

UGR16 includes both:

- stable numeric flow metadata,
- metadata-style fields such as IP addresses, protocol, flags, and raw weak labels.

Version 1 should therefore:

- retain metadata columns where useful for context and diagnostics,
- derive stable numeric features from protocol, flags, ports, and timestamps,
- avoid using high-cardinality raw IP strings directly as numeric model inputs.

---

## 5. Target Construction

The UGR16 version 1 pipeline should define targets explicitly.

### 5.1 Binary pipeline

The binary target should be derived primarily from the raw weak flow label in `col_13`:

- `background` -> `BENIGN`
- any non-background flow label -> `ATTACK`

This gives a stable, flow-level target that avoids marking every flow in an attack-active minute as malicious.

### 5.2 Multiclass pipeline

The multiclass target should use the normalized raw weak label:

- `background` -> `BENIGN`
- other labels remain as their normalized family label, for example:
  - `blacklist`
  - `anomaly-spam`
  - `anomaly-sshscan`
  - `anomaly-udpscan`

This pipeline should be treated as optional and secondary because the class balance is highly skewed.

### 5.3 Anomaly pipeline

The anomaly pipeline should not depend on a multiclass label.

Recommended policy:

- `train` contains only `BENIGN` flows,
- `val` and `test` contain mixed flows,
- anomaly scoring is done with models such as `IsolationForest`.

### 5.4 Role of `attack_ts`

The matching `attack_ts` files should be attached as temporal context and evaluation metadata.

In version 1 they should be used to:

- validate the temporal split design,
- track attack-active minutes per week,
- enrich metadata outputs,
- support later weak-supervision extensions.

They should not be treated as a direct replacement for the flow-level target column in version 1.

---

## 6. Base Tabular Preprocessing

The UGR16 preprocessing script should be implemented as a dataset-specific parallel to the existing `prepare_dataset.py` files.

Its main job is to transform the selected raw weekly archives into stable, reusable Parquet datasets.

### 6.1 Streaming archive reading

The selected `*_csv.tar.gz` files should be processed by streaming the CSV members in chunks.

Why:

- the archives are large,
- loading them fully into memory is unnecessary,
- chunk-based reading keeps the pipeline aligned with the existing project style.

### 6.2 Schema normalization

The preprocessing layer should:

- assign stable semantic column names,
- normalize protocol and flag strings,
- normalize the raw weak label values,
- parse timestamps with `pandas.to_datetime(errors="coerce")`.

### 6.3 Derived numeric features

The first version should derive stable features such as:

- duration,
- ports,
- TTL-like value,
- packets,
- bytes,
- bytes per packet,
- packets per second,
- bytes per second,
- hour of day,
- day of week,
- month,
- protocol indicator columns,
- simple TCP flag indicator columns,
- port role indicators such as system and ephemeral ranges.

### 6.4 Metadata retention

The preprocessing layer should retain metadata columns such as:

- `event_ts`,
- `src_ip`,
- `dst_ip`,
- raw protocol text,
- raw flags text,
- normalized raw label,
- attack timeline metadata from the matching `attack_ts` file.

These metadata fields are useful for diagnostics and reporting, but they should not be assumed to be numeric model features.

### 6.5 Stable Parquet schema

To keep the output schema stable between chunks and archives:

- all numeric feature columns should be forced to a stable floating dtype before writing,
- all metadata columns should keep consistent string or datetime types,
- the same feature order should be preserved across all splits.

---

## 7. Split Strategies

`prepare_dataset.py` should support three split families for UGR16.

### 7.1 `date`

This should be the primary split mode for UGR16.

Recommended default:

- March through June -> `train`
- July week 5 -> `val`
- August weeks 1, 2, 3, and 5 -> `test`

Why:

- this is the closest match to the thesis objective of forward-in-time validation,
- it aligns with the long-duration nature of the dataset,
- it is the most defensible split for drift-oriented evaluation.

### 7.2 `groupkfold`

This mode should operate at the weekly archive level:

- `fold_k` uses one weekly archive as test,
- the next weekly archive as validation,
- the remaining selected weekly archives as train.

This prevents flows from the same weekly source archive from being mixed between train and test.

### 7.3 `random`

This mode should generate reproducible row-level splits over the selected subset.

Default ratios:

- `train=0.70`
- `val=0.15`
- `test=0.15`

This is useful as a secondary baseline, but it should not replace the date split in the thesis narrative.

---

## 8. Output Structure

The output of `prepare_dataset.py` should be written to `src/models/UGR16/datasets/`.

### 8.1 Supervised pipelines

```text
datasets/<split_mode>/UGR16/<pipeline>/<split>/*.parquet
```

### 8.2 `groupkfold`

```text
datasets/groupkfold/UGR16/fold_k/<pipeline>/<split>/*.parquet
```

### 8.3 Anomaly pipeline

```text
datasets/<split_mode>/UGR16/anomaly/train_benign/*.parquet
datasets/<split_mode>/UGR16/anomaly/val_mixed/*.parquet
datasets/<split_mode>/UGR16/anomaly/test_mixed/*.parquet
```

### 8.4 Persisted metadata

The preprocessing step should also persist:

- `stats.json` per pipeline,
- `feature_columns.json`,
- a subset manifest describing the selected weekly archives,
- split-policy metadata for `date` and `groupkfold`.

---

## 9. Model Stack for Version 1

To stay similar to CIC and UNSW-NB15, the UGR16 version 1 model stack should include:

- `train_anomaly_isoforest.py`
- `train_ml_binary_hgb.py`
- `train_ml_binary_mlp.py`
- `train_ml_multiclass_hgb.py`
- `compare_models.py`

### Priority order

The first two models are the highest priority:

- anomaly Isolation Forest,
- binary HGB.

The MLP and multiclass HGB scripts should still be implemented to keep structural parity, but they are secondary because of the label quality and class imbalance of UGR16.

---

## 10. Evaluation Focus

UGR16 should be evaluated differently from the cleaner benchmark datasets.

### Primary emphasis

- anomaly detection quality,
- forward-in-time robustness,
- stability across weekly periods,
- behavior under concept drift.

### Important caveat

The repository-generated UGR16 analysis shows extremely attack-dense timeline periods in the selected weeks.

This means UGR16 should be framed as:

- a drift and anomaly extension,
- a long-duration flow-behavior dataset,
- a complement to CIC-IDS2017 and UNSW-NB15,

and **not** as the cleanest standalone balanced benchmark.

---

## 11. Immediate Implementation Targets

The first UGR16 implementation should therefore prioritize:

1. strategy and TODO documents,
2. preprocessing from selected weekly archives,
3. reusable Parquet generation,
4. data loader and utilities,
5. anomaly and binary baseline trainers,
6. comparison reporting,
7. only then optional multiclass refinements.
