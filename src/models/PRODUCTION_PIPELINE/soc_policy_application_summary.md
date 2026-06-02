# SOC Policy Application Summary

Policy: `src/models/PRODUCTION_PIPELINE/policies/soc_alert_policy.production.json`

The policy was applied to the active baseline JSONL outputs generated on 2026-06-02. Filtered outputs are written next to each input as `*_soc_filtered.jsonl`, with counters in `*_soc_summary.json`.

| Model | Run | Events read | Events kept | Dropped by model rate limit | Dropped by entity rate limit | Dropped duplicates | Downgraded to enrichment |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CIC GRU | `smoke_cic_gru_active_registry_policy` | 20 | 20 | 0 | 0 | 0 | 0 |
| LAB HGB | `full_hgb_active_20260602` | 342 | 342 | 0 | 0 | 0 | 0 |
| UGR16 HGB sigmoid | `full_hgb_active_20260602` | 5,000 | 500 | 4,500 | 0 | 0 | 195 |
| UNSW HGB | `full_hgb_active_20260602` | 5,000 | 500 | 4,500 | 0 | 0 | 0 |
| CSR IsolationForest entity-day | `full_csr_active_20260602` | 25 | 25 | 0 | 0 | 0 | 0 |

## Interpretation

- UGR16 and UNSW hit the default model-level hourly cap because batch exports use concentrated generation timestamps. In live streaming, these events would normally be distributed across time windows.
- UGR16 also downgraded 195 events to enrichment-only because the temporal baseline has a high alert rate and the SOC policy marks medium-risk temporal events as correlation signals unless supported by additional context.
- CSR keeps the daily-budget triage behavior; the policy does not convert it into row-level classification.
- The filtered files are suitable for SIEM ingestion experiments where alert fatigue control needs to be demonstrated explicitly.