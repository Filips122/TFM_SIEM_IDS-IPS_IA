# Production Baseline Summary

Generated at UTC: 2026-06-02T14:02:33Z

This file summarizes the active production candidates and the latest full/specialist evidence used for comparison.

HGB full run: `full_hgb_active_20260602`
CSR full run: `full_csr_active_20260602`
CIC metric source: independent calibration policy holdout.

| domain | dataset_key | model_id | status | threshold | metric_source | rows_scored | events_written | precision | recall | f1 | accuracy | alert_rate | false_positive_rate | first_attack_rank | top10_attack_window_recall | daily_budget10_attack_window_recall | policy_path | events_path |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| network_sequence | CIC-IDS2017 | gru_cic_day_20260520_145849 | production_candidate_independent_threshold | 0.0050 | independent_policy_holdout |  |  | 0.9739 | 0.9383 | 0.9558 | 0.9602 | 0.4417 | 0.0213 |  |  |  | src/models/PRODUCTION_PIPELINE/policies/cic_gru_threshold_policy_independent.json |  |
| honeypot | COWRIE_FULL | hgb_cowrie_multiclass_date_20260520_182459 | taxonomy_candidate_not_binary_detector | 0.5000 | active_registry_only |  |  |  |  |  |  |  |  |  |  |  |  |  |
| siem_lab_alerts | LAB-ALERTS | hgb_lab_alerts_binary_date_20260520_181715 | production_candidate | 0.0743 | full_test_inference | 517 | 342 | 0.9181 | 0.9874 | 0.9515 | 0.9381 | 0.6615 | 0.1407 |  |  |  |  | src/models/PRODUCTION_PIPELINE/inference_runs/hgb_lab_alerts_binary_date_20260520_181715/full_hgb_active_20260602/test_events.jsonl |
| network_temporal | UGR16 | hgb_ugr16_binary_date_20260520_151846_sigmoid_calibrated_20260602_ugr16_sigmoid | calibrated_candidate | 0.4456 | full_test_inference | 3699166 | 5000 | 0.9241 | 0.8672 | 0.8948 | 0.8980 | 0.4692 | 0.0712 |  |  |  |  | src/models/PRODUCTION_PIPELINE/inference_runs/hgb_ugr16_binary_date_20260520_151846_sigmoid_calibrated_20260602_ugr16_sigmoid/full_hgb_active_20260602/test_events.jsonl |
| network_tabular | UNSW-NB15 | hgb_unsw_binary_groupkfold0_20260520_135042 | production_candidate_precision_first | 0.6485 | full_test_inference | 700001 | 5000 | 0.9698 | 0.8935 | 0.9301 | 0.9957 | 0.0292 | 0.0009 |  |  |  |  | src/models/PRODUCTION_PIPELINE/inference_runs/hgb_unsw_binary_groupkfold0_20260520_135042/full_hgb_active_20260602/test_events.jsonl |
| entity_day_triage | CSR-LANL | isoforest_csr_entity_day_20260531_002323_fold0 | soc_triage_candidate | 0.9903 | entity_day_triage | 400000 | 25 |  |  |  |  |  |  | 3 | 0.9412 | 0.9412 |  | src/models/PRODUCTION_PIPELINE/inference_runs/isoforest_csr_entity_day_20260531_002323_fold0/full_csr_active_20260602/test_events.jsonl |

## Operational Notes

- HGB rows use complete test inference. Exported SIEM events may be capped by `--max_events`, but metrics use all scored rows.
- CIC uses the active independent threshold policy because this is the defensible full holdout result, not the small smoke run.
- CSR-LANL is evaluated as entity-day SOC triage; precision/recall/F1 are intentionally empty for that row.
- COWRIE is kept as multiclass taxonomy support, not as a binary benign/attack detector.
