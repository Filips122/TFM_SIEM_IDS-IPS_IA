# Active Production Model Registry

Generated from archived model_store manifests.

| domain | dataset_key | pipeline | model_id | version | status | threshold | precision | recall | f1 | macro_f1 | roc_auc | policy_path | warning_count |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| entity_day_triage | CSR-LANL | anomaly_entity_day | isoforest_csr_entity_day_20260531_002323_fold0 | 20260531_002323_fold_0 | soc_triage_candidate | 0.5000 |  |  |  |  | 0.8732 |  | 0 |
| honeypot | COWRIE_FULL | multiclass | hgb_cowrie_multiclass_date_20260520_182459 | 20260520_182459 | taxonomy_candidate_not_binary_detector | 0.5000 | 1.0000 | 1.0000 | 1.0000 |  |  |  | 4 |
| network_sequence | CIC-IDS2017 | sequence_binary | gru_cic_day_20260520_145849 | 20260520_145849 | production_candidate_independent_threshold | 0.0050 | 0.9739 | 0.9383 | 0.9558 |  |  | src/models/PRODUCTION_PIPELINE/policies/cic_gru_threshold_policy_independent.json | 0 |
| network_tabular | UNSW-NB15 | binary | hgb_unsw_binary_groupkfold0_20260520_135042 | 20260520_135042_fold_0 | production_candidate_precision_first | 0.6485 | 0.9698 | 0.8935 | 0.9301 |  |  |  | 0 |
| network_temporal | UGR16 | binary | hgb_ugr16_binary_date_20260520_151846_sigmoid_calibrated_20260602_ugr16_sigmoid | 20260602_ugr16_sigmoid | calibrated_candidate | 0.4456 | 0.9241 | 0.8672 | 0.8948 |  |  |  | 0 |
| siem_lab_alerts | LAB-ALERTS | binary | hgb_lab_alerts_binary_date_20260520_181715 | 20260520_181715 | production_candidate | 0.0743 | 0.9181 | 0.9874 | 0.9515 |  |  |  | 0 |
