# TODO_UGR16

This checklist tracks the UGR16 implementation status and should be updated as tasks are completed.

## Phase 1 - Foundations

- [x] Create strategy document for UGR16
- [x] Reuse the existing UGR16 folder analysis helper as the base inspection layer
- [x] Define the reduced thesis subset of the best UGR16 files
- [x] Exclude attack-family archives and `nfcapd` archives from version 1
- [x] Implement UGR16 preprocessing script for Parquet generation
- [x] Support date split mode in UGR preprocessing
- [x] Support random split mode in UGR preprocessing
- [x] Support groupkfold split mode in UGR preprocessing
- [x] Persist subset manifest and feature column metadata

Notes:
- Version 1 uses the selected weekly main archives plus matching `attack_ts` files.
- `August - Week #4` is excluded from the thesis subset because the matching attack timeline file is empty in the current repository analysis.

## Phase 2 - Dataset and Utility Stack

- [x] Implement UGR data loader for generated splits
- [x] Implement UGR training utilities for artifacts and run metadata
- [x] Implement UGR metrics helpers
- [x] Implement UGR reporting and plotting helpers
- [x] Implement UGR model comparison script
- [ ] Validate consistency of feature order across train, val, and test
- [ ] Persist and validate label-map outputs for supervised pipelines

Notes:
- The first UGR loader follows the same folder and Parquet conventions already used in CIC and UNSW-NB15.

## Phase 3 - Baseline Training Stack

- [x] Implement anomaly Isolation Forest baseline trainer
- [x] Implement binary HGB baseline trainer
- [x] Implement binary MLP baseline trainer
- [x] Implement multiclass HGB baseline trainer
- [ ] Validate whether multiclass weak-label quality is acceptable for thesis reporting

Notes:
- Binary HGB and anomaly Isolation Forest are the highest-priority UGR baselines.
- Multiclass is implemented for parity, but it should be treated as secondary until label quality is validated.

## Phase 4 - Orchestration and Validation

- [ ] Add UGR run-all orchestration script in `src/scripts`
- [ ] Run end-to-end preprocessing for date split
- [ ] Run end-to-end preprocessing for random split
- [ ] Run end-to-end preprocessing for groupkfold split
- [ ] Run end-to-end anomaly Isolation Forest on date split
- [ ] Run end-to-end binary HGB on date split
- [ ] Run end-to-end binary MLP on date split
- [ ] Run end-to-end multiclass HGB on date split
- [ ] Run at least one random split for comparison
- [ ] Run at least one groupkfold fold for anomaly baseline
- [ ] Run at least one groupkfold fold for binary baseline
- [ ] Generate first comparison.csv and comparison.md from UGR artifacts

## Phase 5 - Quality and Hardening

- [ ] Validate the semantic mapping of the 13 raw UGR columns against extracted weekly CSV members
- [ ] Validate temporal ordering of date-based split outputs
- [ ] Validate benign-only training coverage for anomaly mode
- [ ] Validate grouped split leakage assumptions
- [ ] Review weak-label usage from the raw flow label column and matching `attack_ts` files
- [ ] Review empty-split behavior and fallback messaging
- [ ] Add usage commands to README for the UGR16 workflow

## Optional Next Extensions

- [ ] Add UGR dataset validation script
- [ ] Add attack-family-specific evaluation mode using the deferred attack archives
- [ ] Add `nfcapd` reprocessing path for future raw-flow experiments
- [ ] Add explicit drift-summary reporting across weeks or months
- [ ] Evaluate a grouped temporal tabular dataset over 1-minute and 5-minute windows
- [ ] Evaluate whether multiclass should be moved to an optional-only path if imbalance remains too severe