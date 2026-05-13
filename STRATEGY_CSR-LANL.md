# STRATEGY_CSR-LANL

## Objective

This document defines the implementation strategy for adding a **CSR-LANL** experimentation pipeline to the project, following the same general philosophy already used for CIC-IDS2017, UNSW-NB15, UGR16, and LAB-ALERTS:

- reproducible preprocessing from raw compressed event logs,
- explicit split strategies,
- reusable tabular datasets in Parquet format,
- comparable model training and evaluation,
- artifact persistence for later comparison.

The CSR-LANL pipeline should preserve the existing model-training logic as much as possible. The dataset-specific work should be concentrated in:

- raw `.txt.gz` parsing,
- schema normalization,
- temporal aggregation,
- red-team target construction,
- feature generation and split materialization.

The training scripts should remain close to the current tabular baselines: Isolation Forest for anomaly detection, Histogram Gradient Boosting for supervised binary and multiclass tasks, shared metrics/reporting helpers, and timestamped artifacts.

---

## End-to-End Flow

1. Raw CSR-LANL `.txt.gz` files are inspected with the existing EDA helper.
2. Each compressed source file is streamed rather than loaded fully into memory.
3. Known schemas are applied to authentication, DNS, flow, process, and red-team files.
4. Dataset timestamps are parsed as integer seconds from the LANL time origin.
5. Events are normalized into a consistent set of source-specific tables.
6. Events are aggregated into fixed entity/time windows.
7. Red-team rows are used as high-confidence attack seeds for supervised targets.
8. Binary, multiclass, and anomaly datasets are generated from the same aggregated feature table.
9. Parquet splits are written under `src/models/CSR-LANL/datasets/`.
10. Training scripts load the generated splits and reuse the existing model and reporting pattern.
11. Metrics, plots, model files, and comparison reports are written under `src/models/CSR-LANL/artifacts/`.

---

## 1. Data Sources

### Input root

The raw dataset root for this pipeline is:

```text
out/CSR-LANL/
```

### Available files detected in the repository

The current workspace contains the expected CSR-LANL files:

- `out/CSR-LANL/auth.txt.gz`
- `out/CSR-LANL/dns.txt.gz`
- `out/CSR-LANL/flows.txt.gz`
- `out/CSR-LANL/proc.txt.gz`
- `out/CSR-LANL/redteam.txt.gz`

The existing helper `src/helpers/analyze_csr_lanl_folder_v2.py` has already been prepared for these files and writes analysis output to:

```text
out/CSR-LANL_analysis_v2/
```

The current capped EDA output confirms that all five files use known schemas, comma delimiters, and no malformed rows in the sampled rows. The row counts in that report are capped by the helper run, so they should be treated as sample diagnostics rather than full-corpus counts.

### File roles

#### A. Authentication events

- `auth.txt.gz`

Expected fields:

- `time`
- `src_user`
- `dst_user`
- `src_computer`
- `dst_computer`
- `auth_type`
- `logon_type`
- `auth_orient`
- `result`

Why this file matters:

- it is the strongest source for credential-use behavior,
- it supports failed/successful authentication ratios,
- it supports user-computer and computer-computer novelty features,
- it is the best first source for supervised red-team alignment.

#### B. Network flow events

- `flows.txt.gz`

Expected fields:

- `time`
- `duration`
- `src_computer`
- `src_port`
- `dst_computer`
- `dst_port`
- `protocol`
- `packet_count`
- `byte_count`

Why this file matters:

- it provides host-to-host communication context,
- it supports volume, duration, port, and protocol features,
- it can enrich authentication windows with network behavior.

#### C. DNS events

- `dns.txt.gz`

Expected fields:

- `time`
- `src_computer`
- `dst_computer`

Why this file matters:

- it provides lightweight communication and name-resolution context,
- it can identify unusual source/destination relationships,
- it is useful for per-host activity baselines.

#### D. Process events

- `proc.txt.gz`

Expected fields:

- `time`
- `user`
- `computer`
- `process`
- `event_type`

Why this file matters:

- it adds host/process behavior that complements authentication and flows,
- it supports process rarity and process-event count features,
- it can improve context around red-team windows.

#### E. Red-team events

- `redteam.txt.gz`

Expected fields:

- `time`
- `user`
- `src_computer`
- `dst_computer`

Why this file matters:

- it is the primary high-confidence label source,
- it marks known adversary activity,
- it should drive supervised target construction and validation.

---

## 2. Implementation Scope for Version 1

CSR-LANL should be treated as a **multi-source enterprise activity dataset**, not as a simple row-level CSV benchmark.

### Included in version 1

- reuse of the existing CSR-LANL EDA helper,
- streaming `.txt.gz` parsing,
- source-specific schema normalization,
- event-time normalization from integer seconds,
- fixed-window aggregation,
- auth-centered feature generation,
- optional enrichment from flows, DNS, and process events,
- red-team target construction,
- binary target construction,
- anomaly dataset construction,
- optional multiclass target construction,
- date/time split strategy,
- random split strategy for quick debugging,
- grouped split strategy for entity generalization,
- baseline training scripts using the existing model pattern,
- artifact persistence,
- final comparison report.

### Excluded from version 1

- raw graph neural network modeling,
- full sequence modeling over individual events,
- real-time streaming ingestion,
- SIEM reinjection,
- automated response logic,
- analyst feedback loops,
- deep entity resolution beyond the provided user/computer identifiers.

These capabilities may be added later, but they are out of scope for the first CSR-LANL implementation.

---

## 3. Preprocessing Design

The preprocessing script should be implemented as:

```text
src/models/CSR-LANL/prepare_dataset.py
```

Its main responsibility is to transform the raw LANL event streams into stable Parquet splits compatible with the existing training stack.

### 3.1 Streaming gzip reading

All source files should be read with streaming gzip logic and chunked processing.

Why:

- the authentication file is several GB compressed,
- the process and flow files are also large,
- full in-memory loading is unnecessary and fragile,
- the existing EDA helper already proves that line-oriented parsing is sufficient.

### 3.2 Schema normalization

The preprocessing stage should reuse the known source schemas from the helper:

- `auth`
- `dns`
- `flows`
- `proc`
- `redteam`

Each source should receive:

- stable lowercase column names,
- normalized missing tokens,
- numeric conversion for time and numeric counters,
- source-family metadata,
- consistent entity fields where possible.

### 3.3 Time handling

CSR-LANL timestamps are integer offsets rather than normal datetimes.

The preprocessing stage should derive:

- `event_time`
- `day_index`
- `hour_index`
- `minute_index`
- `window_start`
- `window_end`

The default window size should be:

- `60 seconds` for version 1,
- optionally `300 seconds` for later 5-minute aggregation.

### 3.4 Entity design

The first version should generate a stable entity-window table.

Recommended primary entity:

- `src_computer`

Recommended secondary entities for later extension:

- `user`
- `dst_computer`
- `(src_user, src_computer)`
- `(src_computer, dst_computer)`

The first implementation should avoid raw high-cardinality identifiers as direct model features. Identifiers should be kept as metadata for splitting, label matching, diagnostics, and explainability.

---

## 4. Feature Engineering

The version 1 feature table should be numeric, reproducible, and ordered consistently across splits.

### 4.1 Authentication-derived features

Useful initial features include:

- authentication event count,
- failed authentication count,
- successful authentication count,
- failure ratio,
- unique source users,
- unique destination users,
- unique destination computers,
- count by `auth_orient`,
- count by `auth_type`,
- count by `logon_type`,
- machine-account ratio,
- anonymous-logon count,
- first-seen user-computer indicator,
- first-seen source-destination computer indicator.

### 4.2 Flow-derived features

Useful initial features include:

- flow count,
- total duration,
- mean duration,
- total packets,
- total bytes,
- mean bytes per flow,
- unique destination computers,
- unique destination ports,
- privileged destination port count,
- protocol counts,
- bytes-per-packet ratio.

### 4.3 DNS-derived features

Useful initial features include:

- DNS event count,
- unique destination computers,
- repeated destination ratio,
- first-seen DNS destination indicator.

### 4.4 Process-derived features

Useful initial features include:

- process event count,
- unique process count,
- unique user count,
- counts by `event_type`,
- rare process indicator,
- first-seen process-on-host indicator.

### 4.5 Cross-source features

Useful initial features include:

- number of active source families in the window,
- authentication-to-flow ratio,
- authentication-failure-to-flow ratio,
- process-to-authentication ratio,
- red-team proximity flags for validation metadata,
- rolling count features over previous windows when feasible.

Rolling features should be added only after the base window table is stable, because they introduce leakage risk if computed after splitting.

---

## 5. Target Construction

CSR-LANL labels are sparse. The red-team file marks known adversary activity, but non-red-team windows should be described carefully as `BENIGN_OR_UNLABELED` in metadata rather than treated as perfect ground truth.

### 5.1 Binary pipeline

The recommended binary target is:

- `ATTACK` for windows that match a red-team event by time and at least one relevant entity key,
- `BENIGN` for windows that do not overlap red-team activity and are outside a configurable exclusion horizon.

Recommended matching keys:

- exact `window_start` or same minute bucket,
- `src_computer`,
- `dst_computer`,
- `user` when available.

Recommended exclusion horizon:

- exclude windows within a small configurable time buffer around red-team activity from supervised benign training unless they are explicitly matched as attack.

This keeps the supervised task more defensible by avoiding ambiguous near-attack windows as easy negatives.

### 5.2 Multiclass pipeline

The red-team file does not provide rich tactic labels, so multiclass should be optional in version 1.

If implemented, the recommended first policy is evidence-family labeling:

- `BENIGN`
- `RedTeamAuth`
- `RedTeamFlow`
- `RedTeamDNS`
- `RedTeamProcess`
- `RedTeamMixed`

These classes should be derived from which source families are active in a red-team-matched window.

This multiclass target must be treated as weak and secondary. It should not be presented as a definitive attack-type classifier unless additional labeling is added later.

### 5.3 Anomaly pipeline

The anomaly pipeline should be the primary CSR-LANL baseline because it fits sparse labels and unknown-threat evaluation.

Recommended policy:

- `train_benign` contains windows with no red-team overlap and no red-team proximity,
- `val_mixed` contains normal windows plus red-team-matched windows,
- `test_mixed` contains normal windows plus red-team-matched windows,
- red-team labels are used only for evaluation, threshold selection, and reporting.

Isolation Forest should be the first anomaly model for consistency with the existing project.

---

## 6. Split Strategies

`prepare_dataset.py` should support three split families for CSR-LANL.

### 6.1 `date`

This is the preferred split mode for thesis reporting.

Because CSR-LANL uses integer time offsets, `date` should be interpreted as ordered time/day splitting based on `day_index`.

Recommended behavior:

- sort windows by `window_start`,
- split by day or time quantile,
- preserve temporal ordering,
- persist the exact time boundaries used.

This mode best supports operational realism and drift-oriented evaluation.

### 6.2 `random`

This mode should generate reproducible row-level splits over aggregated windows.

It is useful for quick smoke tests and debugging, but it should not be the primary thesis result because it can overestimate generalization when the same entities appear across train and test.

### 6.3 `groupkfold`

This mode should test entity generalization.

Recommended grouping keys:

- primary: `src_computer`,
- optional: `user`,
- optional: `(src_computer, dst_computer)`.

The selected grouping key must be persisted in split metadata. If a grouping key creates too few usable groups or no attack-positive folds, the script should fail with a clear message or use a documented fallback.

---

## 7. Writing the Tabular Dataset to Parquet

The output of `prepare_dataset.py` should be written to:

```text
src/models/CSR-LANL/datasets/
```

### 7.1 Output structure

For supervised pipelines:

```text
datasets/<split_mode>/CSR-LANL/<pipeline>/<split>/*.parquet
```

For `groupkfold`:

```text
datasets/groupkfold/CSR-LANL/fold_k/<pipeline>/<split>/*.parquet
```

For anomalies:

```text
datasets/<split_mode>/CSR-LANL/anomaly/train_benign/*.parquet
datasets/<split_mode>/CSR-LANL/anomaly/val_mixed/*.parquet
datasets/<split_mode>/CSR-LANL/anomaly/test_mixed/*.parquet
```

### 7.2 Persisted metadata

The preprocessing script should write:

- `stats.json`,
- `feature_columns.json`,
- `label_map.json` for supervised pipelines,
- `source_manifest.json`,
- `redteam_policy.json`,
- split-policy metadata for `date`, `random`, and `groupkfold`,
- anomaly-policy metadata when exclusion horizons or fallbacks are used.

The metadata should include split sizes, label distributions, feature order, source coverage, time boundaries, and any fallback decisions.

---

## 8. Training Stack

The CSR-LANL training stack should follow the existing tabular baseline pattern.

### 8.1 Required baseline models

The first implementation should include:

- `train_anomaly_isoforest.py`,
- `train_ml_binary_hgb.py`,
- `train_ml_multiclass_hgb.py`,
- `compare_models.py`.

### 8.2 Shared training logic

The model logic should remain as close as possible to the existing dataset pipelines:

- load Parquet splits,
- separate metadata columns from feature columns,
- train the same baseline model families,
- compute the same metrics,
- generate the same plot/report artifact types,
- write timestamped run directories.

Dataset-specific differences should be handled in the loader and metadata, not by changing model behavior unless a CSR-LANL-specific requirement justifies it.

### 8.3 Optional next models

After the preprocessing and baselines are stable, the following may be added:

- `train_ml_binary_mlp.py`,
- `train_ml_binary_fttransformer.py`,
- sequence models over entity windows.

These should only be added after the HGB and Isolation Forest baselines have been validated.

---

## 9. Validation and Quality Controls

The CSR-LANL implementation should include explicit validation checks.

Minimum checks:

- source schemas match expected column counts,
- feature order is identical across train, validation, and test,
- metadata columns are excluded from model feature matrices,
- date/time split outputs preserve ordering,
- grouped splits do not leak the same group across train and test,
- red-team rows are matched to generated windows at a measurable rate,
- supervised positive windows exist in validation and test where required,
- anomaly training excludes red-team and near-red-team windows,
- label mappings are stable and reproducible,
- empty split and single-class cases fail with clear messages.

Because CSR-LANL is sparse and multi-source, the validation report should also include:

- red-team coverage by day,
- red-team coverage by source/destination computer,
- number of windows with each source family present,
- label distribution by split,
- benign candidate count after exclusion policies.

---

## 10. Recommended Implementation Order

The CSR-LANL work should be implemented in this order:

1. Create strategy and TODO documents.
2. Re-run or review the existing CSR-LANL EDA helper output.
3. Implement `prepare_dataset.py` with auth-only plus red-team labeling first.
4. Add flow, DNS, and process enrichment behind explicit source-set options.
5. Add `date`, `random`, and `groupkfold` split support.
6. Write metadata files for features, source manifest, split policy, and red-team policy.
7. Add `data_loader.py`, `train_utils.py`, `metrics.py`, and `reporting.py`.
8. Implement anomaly `IsolationForest` baseline.
9. Implement binary HGB baseline.
10. Implement optional multiclass HGB baseline.
11. Add `compare_models.py`.
12. Add orchestration script under `src/scripts`.
13. Run end-to-end validation for all selected split modes.

---

## Final Position

CSR-LANL should be treated as a **windowed, multi-source enterprise behavior dataset**.

The correct first version is therefore:

- streaming-first,
- aggregation-first,
- red-team-aware,
- anomaly-ready,
- conservative about weak supervised labels,
- compatible with the existing training and artifact conventions.

The main implementation challenge is not the model stack. It is producing a reliable, explainable, leakage-aware Parquet dataset that lets the existing model logic run consistently.