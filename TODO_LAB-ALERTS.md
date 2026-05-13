# TODO_LAB-ALERTS

This checklist tracks the LAB-ALERTS implementation status and should be updated as tasks are completed.

## Phase 1 - Foundations

- [x] Create strategy document for LAB-ALERTS
- [x] Inspect `out/LAB-ALERTS/alerts.json` and document schema assumptions
- [x] Define binary target policy for LAB-ALERTS
- [x] Define multiclass target policy for LAB-ALERTS
- [x] Define anomaly baseline policy for LAB-ALERTS
- [x] Implement LAB-ALERTS preprocessing script for Parquet generation
- [x] Implement time-window aggregation for alert events
- [x] Support random split mode in LAB preprocessing
- [x] Support groupkfold split mode in LAB preprocessing
- [x] Support date split mode in LAB preprocessing

Notes:
- Current source is newline-delimited Wazuh JSON with 59,855 valid alerts.
- Version 1 aggregates alerts by `agent_id` and 1-minute windows.
- Binary labels are weak operational labels derived from Wazuh rule groups, MITRE tactics, severity, and operational service/system groups.
- Rare multiclass labels are collapsed into `OtherAlert` by default when they have fewer than 30 windows, avoiding temporal test-only classes.

## Phase 2 - Dataset and Utility Stack

- [x] Implement LAB data loader for generated splits
- [x] Implement LAB training utilities for artifacts and run metadata
- [x] Implement LAB metrics helpers
- [x] Implement LAB reporting and plotting helpers
- [x] Persist split-policy metadata for groupkfold and date modes
- [x] Persist stats.json and label_map.json for supervised pipelines
- [x] Validate consistency of feature order across train, val, and test

## Phase 3 - Baseline Training Stack

- [x] Implement anomaly Isolation Forest baseline trainer
- [x] Implement binary HGB baseline trainer
- [x] Implement multiclass HGB baseline trainer
- [x] Implement LAB model comparison script

## Phase 4 - Orchestration and Validation

- [x] Add LAB run-all orchestration script in `src/scripts`
- [ ] Run end-to-end preprocessing for random split
- [ ] Run end-to-end preprocessing for groupkfold split
- [ ] Run end-to-end preprocessing for date split
- [ ] Run end-to-end anomaly Isolation Forest on random split
- [ ] Run end-to-end binary HGB on random split
- [ ] Run end-to-end multiclass HGB on random split
- [ ] Run at least one groupkfold fold for anomaly baseline
- [ ] Run at least one groupkfold fold for binary baseline
- [ ] Run at least one groupkfold fold for multiclass baseline
- [x] Run at least one date split for anomaly baseline
- [x] Run at least one date split for binary baseline
- [x] Run at least one date split for multiclass baseline
- [x] Generate first comparison.csv and comparison.md from LAB artifacts

## Phase 5 - Quality and Hardening

- [ ] Validate grouped split leakage assumptions
- [ ] Validate temporal ordering of date-based split outputs
- [ ] Validate label mappings are stable and reproducible
- [ ] Review empty-split and single-class fallback behavior
- [ ] Review anomaly training policy for benign-window selection
- [ ] Add clear error handling for missing Parquet splits
- [ ] Add usage commands to README for LAB-ALERTS workflow

## Optional Next Extensions

- [ ] Add LAB binary MLP baseline
- [ ] Add LAB binary FTTransformer baseline
- [ ] Add LAB dataset validation script
- [ ] Evaluate alternative grouping keys for k-fold
- [ ] Evaluate alternative window sizes such as 5-minute aggregation
- [ ] Evaluate whether raw rule IDs should be supported as an optional multiclass target