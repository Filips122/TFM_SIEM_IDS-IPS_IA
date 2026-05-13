# TODO_CSR-LANL

This checklist tracks the CSR-LANL implementation status and should be updated as tasks are completed.

## Phase 1 - Foundations

- [x] Create strategy document for CSR-LANL
- [x] Create TODO document for CSR-LANL
- [x] Verify expected raw files exist under `out/CSR-LANL/`
- [x] Reuse the existing CSR-LANL folder analysis helper as the base inspection layer
- [x] Document the known schemas for `auth`, `dns`, `flows`, `proc`, and `redteam`
- [x] Review full EDA output and decide whether the first preprocessing pass should be auth-only or all-source
- [x] Define the default CSR-LANL source-set policy for version 1
- [x] Define metadata columns that must be preserved but excluded from model features
- [x] Define the default entity key for aggregation
- [x] Define the default 1-minute windowing policy

Notes:
- Current raw inputs are `auth.txt.gz`, `dns.txt.gz`, `flows.txt.gz`, `proc.txt.gz`, and `redteam.txt.gz`.
- Existing analysis output is available under `out/CSR-LANL_analysis_v2/`.
- The current model folder only contains placeholder `artifacts/` and `datasets/` directories.
- Version 1 should keep model logic close to the existing tabular pipelines and concentrate new work in preprocessing and feature generation.
- Initial implementation defaults to `source_set=auth`, with optional `auth_flow`, `auth_flow_dns`, and `all` source sets.
- Default aggregation key is `src_computer`/`computer`, stored as `entity`; raw entity identifiers are preserved as metadata and excluded from model features.
- Default window size is 60 seconds.

## Phase 2 - Preprocessing and Feature Datasets

- [x] Implement `src/models/CSR-LANL/prepare_dataset.py`
- [x] Add streaming `.txt.gz` readers for all CSR-LANL source files
- [x] Normalize source schemas and missing tokens consistently
- [x] Convert integer LANL timestamps into `day_index`, `hour_index`, and `window_start`
- [x] Implement auth-derived window features
- [x] Implement red-team loading and window matching
- [x] Implement binary target generation from red-team windows
- [x] Implement anomaly split generation with benign-only training windows
- [x] Decide whether multiclass evidence-family labels are useful enough for version 1
- [x] Implement optional flow-derived window features
- [x] Implement optional DNS-derived window features
- [x] Implement optional process-derived window features
- [x] Implement cross-source activity features
- [x] Support `date` split mode using ordered LANL time windows
- [x] Support `random` split mode for quick smoke tests
- [x] Support `groupkfold` split mode by entity
- [x] Persist `stats.json`
- [x] Persist `feature_columns.json`
- [x] Persist `source_manifest.json`
- [x] Persist `redteam_policy.json`
- [x] Persist split-policy metadata for all split modes

Notes:
- `prepare_dataset.py` now writes binary, multiclass, and anomaly Parquet splits under the same folder contract used by the other dataset pipelines.
- The multiclass branch is retained as a weak evidence-family view: `BENIGN`, `RedTeamAuth`, `RedTeamFlow`, `RedTeamDNS`, `RedTeamProcess`, `RedTeamMixed`, and `RedTeamOther`.
- Capped smoke preprocessing was validated with `source_set=auth`, `split_mode=random`, and `max_rows_per_source=5000`.

## Phase 3 - Dataset and Utility Stack

- [x] Implement CSR-LANL data loader for generated splits
- [x] Implement CSR-LANL training utilities for artifacts and run metadata
- [x] Implement or adapt CSR-LANL metrics helpers
- [x] Implement or adapt CSR-LANL reporting and plotting helpers
- [x] Persist `label_map.json` for supervised pipelines
- [x] Validate consistency of feature order across train, validation, and test
- [x] Validate metadata columns are excluded from model feature matrices
- [x] Add clear errors for missing Parquet splits
- [x] Add clear errors for empty or single-class supervised splits

Notes:
- Loader smoke validation read train/validation/test anomaly splits from the temporary capped dataset with a stable 51-feature matrix.

## Phase 4 - Baseline Training Stack

- [x] Implement anomaly Isolation Forest baseline trainer
- [x] Implement binary HGB baseline trainer
- [x] Implement multiclass HGB baseline trainer if multiclass labels are retained
- [x] Implement CSR-LANL model comparison script
- [x] Keep trainer CLI arguments consistent with existing dataset pipelines
- [x] Confirm artifact outputs match the current comparison tooling expectations

Notes:
- Anomaly Isolation Forest and binary HGB are the highest-priority CSR-LANL baselines.
- Multiclass should remain secondary until the weak evidence-family label policy is validated.
- Trainers follow the same model logic used by LAB-ALERTS, with an additional optional `--datasets_base` argument for smoke outputs or alternate dataset roots.
- Anomaly trainer smoke validation completed on the capped all-benign sample; AUC metrics are `nan` as expected because the sample has no red-team positives.

## Phase 5 - Orchestration and Validation

- [ ] Add CSR-LANL run-all orchestration script in `src/scripts`
- [ ] Run end-to-end preprocessing for `date` split
- [x] Run end-to-end preprocessing for `random` split
- [ ] Run end-to-end preprocessing for at least one `groupkfold` fold
- [ ] Run end-to-end anomaly Isolation Forest on `date` split
- [ ] Run end-to-end binary HGB on `date` split
- [ ] Run multiclass HGB on `date` split if retained
- [ ] Run at least one random split for comparison
- [ ] Run at least one grouped fold for anomaly baseline
- [ ] Run at least one grouped fold for binary baseline
- [ ] Generate first `comparison.csv` and `comparison.md` from CSR-LANL artifacts
- [ ] Add CSR-LANL usage commands to `README.md`

Notes:
- The completed random preprocessing run was a capped smoke test only, written to a temporary `datasets_smoke` directory and removed after validation.

## Phase 6 - Quality and Hardening

- [ ] Validate source schemas against the raw gzipped files before preprocessing
- [ ] Validate temporal ordering of `date` split outputs
- [ ] Validate grouped split leakage assumptions
- [ ] Validate red-team event match rate against generated windows
- [ ] Validate red-team coverage by day and entity
- [ ] Validate anomaly training excludes red-team and near-red-team windows
- [ ] Validate supervised label mappings are stable and reproducible
- [ ] Review class imbalance and decide whether binary downsampling is needed
- [x] Review whether raw high-cardinality identifiers are safely excluded from features
- [ ] Review memory usage on full compressed files
- [ ] Add a dataset validation script similar to the UGR16 and NUSW workflows

## Optional Next Extensions

- [ ] Add CSR-LANL binary MLP baseline
- [ ] Add CSR-LANL binary FTTransformer baseline
- [ ] Add rolling historical features over previous windows
- [ ] Add 5-minute aggregation as an alternative dataset view
- [ ] Add user-centered and computer-pair-centered aggregation modes
- [ ] Add sequence datasets over entity windows
- [ ] Evaluate graph-style features for user/computer relationships
- [ ] Evaluate red-team scenario holdout validation if enough labeled windows are available