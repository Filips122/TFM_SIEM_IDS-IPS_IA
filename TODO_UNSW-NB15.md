# TODO_NUSW-NB15

This checklist tracks the NUSW-NB15 implementation status and should be updated as tasks are completed.

## Phase 1 - Foundations

- [x] Create strategy document for NUSW-NB15
- [x] Implement simple NUSW folder analysis and EDA helper
- [x] Implement NUSW preprocessing script for Parquet generation
- [x] Support random split mode in NUSW preprocessing
- [x] Support groupkfold split mode in NUSW preprocessing
- [x] Support official split mode in NUSW preprocessing

## Phase 2 - Baseline Training Stack

- [x] Implement NUSW data loader for generated splits
- [x] Implement NUSW training utilities for artifacts and run metadata
- [x] Implement binary HGB baseline trainer
- [x] Implement multiclass HGB baseline trainer
- [x] Implement anomaly Isolation Forest baseline trainer
- [x] Implement NUSW model comparison script

## Phase 3 - Orchestration and Validation

- [x] Add NUSW run-all orchestration script in src/scripts
- [x] Run end-to-end binary HGB on random split
- [x] Run end-to-end multiclass HGB on random split
- [x] Run end-to-end anomaly Isolation Forest on random split
- [x] Run at least one groupkfold fold for each baseline
- [x] Generate first comparison.csv and comparison.md from NUSW artifacts
- [x] Run end-to-end binary HGB on official split
- [x] Run end-to-end multiclass HGB on official split
- [x] Run end-to-end anomaly Isolation Forest on official split

Notes:
- Orchestration script added at `src/scripts/nusw_run_all_models.ps1`.
- Binary HGB was executed on groupkfold fold_7.
- Multiclass HGB was executed on groupkfold fold_7.
- Under `strict` anomaly policy, groupkfold fold_7 is skipped on raw4 source because train_benign is empty (no BENIGN samples in training split).
- Official split was generated and trained for all three baselines via `nusw_run_all_models.ps1`.
- Groupkfold anomaly train policy is now explicit in preprocessing: `strict` (default) or `fallback_official_benign`.
- Anomaly groupkfold fold_7 completed successfully when using `fallback_official_benign` policy.

## Requested Improvements (March 25)

- [x] Expand NUSW groupkfold indexing to support folds 0..7
- [x] Add CIC-style artifact outputs (metrics per split + plots) for NUSW HGB baselines
- [x] Keep timestamped run folders for easier run tracking in artifacts
- [x] Add dataset consistency validation script and generate validation report
- [x] Add fold-aware aggregated model comparison outputs (mean/std + skipped/missing diagnostics)

## Phase 4 - Quality and Documentation

- [x] Add usage commands to README for NUSW workflow
- [x] Validate consistency of feature order across train/val/test for all modes
- [x] Validate that label mappings are stable and reproducible
- [x] Review and harden error handling for missing parquet splits

Additional notes:
- `validate_datasets.py` now checks schema consistency, split presence, target/label columns, and label-domain validity with explicit parquet-engine precheck.
- `validate_datasets.py` now validates binary/multiclass `label_map.json` reproducibility against dataset-derived expected mappings (`--label_map_scope latest|all`).
- `compare_models.py` now emits `comparison_aggregated.*`, `comparison_skipped.*`, and `comparison_missing_metrics.*` outputs.
- `prepare_dataset.py` now writes `anomaly_policy.json` per groupkfold fold to document whether fallback benign data was injected.
- Current validation report (`label_map_scope=latest`) is OK, while historical artifacts still include two legacy mapping mismatches.

## Optional Next Extensions

- [x] Add NUSW binary MLP baseline
- [x] Add calibration and plotting layer for NUSW baseline scripts
- [x] Add shared refactor to reduce duplicated utilities between CIC and NUSW
- [x] Evaluate whether train_test_network.csv should become a separate pipeline

Optional extension notes:
- `train_ml_binary_mlp.py` added under `src/models/NUSW-NB15` with artifact/history/plot outputs.
- `reporting.py` now includes torch probability inference/history plotting plus anomaly ROC/PR/score-hist plotting.
- Label-map write logic was refactored to utility usage in both NUSW and CIC binary HGB scripts.
- `evaluate_train_test_network.py` generates a recommendation report under `src/models/NUSW-NB15/artifacts/evaluations`.
