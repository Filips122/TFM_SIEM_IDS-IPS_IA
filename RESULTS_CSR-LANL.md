# RESULTS CSR-LANL

## Current Reading

CSR-LANL is evaluated as a SOC prioritization problem. Row-level accuracy is not a reliable success metric because the test split is extremely imbalanced and a model can score well while missing red-team activity.

The current primary evidence uses the `date` split from:

```text
src/models/CSR-LANL/datasets_redteam/date/CSR-LANL
```

Current `date` test support:

| Item | Value |
| --- | ---: |
| Test rows | 2,575,431 |
| Red-team windows | 38 |
| Red-team entities | 15 |
| Attack days | 3 |

## Baseline Operational Results

| Model | Window top-100 | Window top-500 | Entity top-100 | Entity top-500 | Reading |
| --- | ---: | ---: | ---: | ---: | --- |
| IsolationForest | 1/38 | 1/38 | 3/15 | 5/15 | Best low-budget window ranking, but weak global PR-AUC. |
| HGB binary balanced | 0/38 | 1/38 | 3/15 | 8/15 | Best entity ranking; direct thresholding creates many false positives. |
| HGB multiclass | 0/38 | 2/38 | 0/15 | 2/15 | Finds some windows at high budget but is noisy. |
| Percentile ensemble | 0/38 | 0/38 | 3/15 | 5/15 | Does not improve over the strongest individual signals. |

## Temporal Entity-History Features

A new temporal feature profile was materialized under:

```text
src/models/CSR-LANL/datasets_redteam_temporal/date/CSR-LANL
```

This dataset keeps the same `date` labels and support as the baseline, but adds 31 causal temporal/entity-history features to the original 51 features. The temporal features include cyclic time encodings, off-hours flags, per-entity seen-window/gap features, and shifted rolling means/deltas over previous entity windows. They are computed from already prepared Parquet data, so no full raw `.txt.gz` rescan is required.

Temporal `date` support is unchanged for the operational target: 2,575,431 test rows, 38 red-team windows, and 15 red-team entities. The operational evaluator counts 3 attack days; `validate_splits.py` reports 4 test days with red-team metadata because it counts day support at split level.

HGB binary balanced on `date`:

| Feature profile | Artifact run | First attack rank | Window top-100 | Window top-500 | Entity top-100 | Entity top-500 | Policy note |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Baseline auth/flow | `20260520_225134` | 121 | 0/38 | 1/38 | 3/15 | 8/15 | `budget_daily_50_on_val`: 52.25 alerts/day, 1/38 windows, 3/15 entities. |
| Temporal entity history | `20260526_145328` | 22 | 4/38 | 7/38 | 4/15 | 8/15 | `budget_daily_50_on_val`: 17.00 alerts/day, 3/38 windows, 1/15 entities. |
| Temporal rarity/multi-scale | `20260527_144125` | 72 | 2/38 | 3/38 | 5/15 | 7/15 | `budget_daily_50_on_val`: 45.50 alerts/day, 2/38 windows, 2/15 entities. |

Interpretation for `date`:

- Temporal features materially improve window ranking: first red-team rank moves from 121 to 22, top-100 improves from 0/38 to 4/38, and top-500 improves from 1/38 to 7/38.
- Entity top-500 remains unchanged at 8/15, while entity top-100 improves slightly from 3/15 to 4/15.
- Validation-calibrated policies remain unstable across time: the temporal `budget_daily_50_on_val` policy reduces alert volume and finds more windows than the baseline, but only 1/15 red-team entities.
- The temporal rarity/multi-scale profile does not improve direct window ranking on `date`; first rank moves back to 72 and top-500 drops to 3/38. Its useful signal appears mainly in entity-day policies, not raw window top-k.

## Validation-Calibrated Policies

Policies are calibrated on validation and applied to test. This avoids choosing thresholds on test.

Important observations:

- HGB binary balanced with `budget_daily_50_on_val`: about 52 alerts/day, 1/38 red-team windows, 3/15 red-team entities.
- IsolationForest with `max_f2_on_val`: about 28 alerts/day, 1/38 red-team windows, 3/15 red-team entities.
- Multiclass with `max_f2_on_val`: 2/38 red-team windows and 6/15 entities, but about 770 alerts/day, so it is not operationally acceptable as-is.

## Entity-Calibrated SOC Policies

The operational evaluator now also calibrates policies at entity level. Instead of selecting individual event windows directly, these policies select high-risk entities or entity-day pairs using validation thresholds, then measure how many red-team entities, windows, and attack days would fall inside the investigation scope.

This is closer to SOC triage: an analyst can investigate a limited set of suspicious hosts/entities and then inspect the highest-risk windows inside them.

Selected `entity_budget_daily_*_on_val` results:

| Artifact | Policy | Selected entity-days | Red-team entities | Red-team windows | Attack days | Reading |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Date baseline HGB | `entity_budget_daily_25_on_val` | 123 | 1/15 | 7/38 | 1/3 | Better window coverage than direct window thresholding, but many entity-days. |
| Date temporal HGB | `entity_budget_daily_10_on_val` | 13 | 1/15 | 8/38 | 1/3 | Strongest low-volume date policy tested. |
| Date temporal HGB | `entity_budget_daily_25_on_val` | 47 | 2/15 | 9/38 | 1/3 | Best date window coverage with moderate entity-day volume. |
| Date temporal rarity HGB | `entity_budget_daily_10_on_val` | 31 | 1/15 | 8/38 | 1/3 | Matches temporal daily-10 window hits with more entity-days. |
| Date temporal rarity HGB | `entity_budget_daily_25_on_val` | 92 | 3/15 | 15/38 | 2/3 | Best date entity-day policy so far, but at higher triage volume. |
| Fold baseline HGB | `entity_budget_daily_5_on_val` | 50 | 3/5 | 3/522 | 2/14 | Good entity recall at low daily entity budget. |
| Fold temporal HGB | `entity_budget_daily_10_on_val` | 118 | 3/5 | 3/522 | 2/14 | Matches baseline entity/window hits with more entity-days. |
| Fold temporal HGB | `entity_budget_daily_25_on_val` | 341 | 4/5 | 4/522 | 2/14 | Best fold entity recall among tested entity policies, but high triage volume. |
| Fold temporal rarity HGB | `entity_budget_daily_5_on_val` | 45 | 3/5 | 3/522 | 2/14 | Matches the low-volume baseline with slightly fewer entity-days. |
| Fold temporal rarity HGB | `entity_budget_daily_25_on_val` | 316 | 4/5 | 4/522 | 2/14 | Matches temporal fold coverage with fewer entity-days. |

Interpretation:

- Entity-calibrated policies improve the SOC reading of CSR-LANL because they recover red-team windows through entity prioritization, especially on the `date` temporal run.
- The temporal rarity/multi-scale profile improves this SOC policy view on `date`: `entity_budget_daily_25_on_val` recovers 15/38 red-team windows and 3/15 entities, compared with 9/38 and 2/15 for the temporal profile.
- They do not yet solve sparse window recall on `fold_0`: even when 4/5 red-team entities are selected, only 4/522 red-team windows are inside the selected entity-days.
- The temporal rarity/multi-scale profile transfers partially to `fold_0`: it improves first-hit ranking and keeps the best entity-day coverage with fewer entity-days, but it does not materially improve red-team window recall.
- This supports the next feature direction: preserve concrete destination and source-destination identities during preparation, or train/evaluate entity-first scoring directly, so selected entities also include more of their relevant attack windows.

## Entity-Day Scorer Experiment

An entity-day dataset was derived from `datasets_redteam_temporal_rarity` without modifying the original window-level datasets. Each row represents `(entity, day_index)` and is positive when that entity-day contains at least one red-team window. Two variants were tested:

- Raw entity-day aggregation: aggregated temporal-rarity window features only.
- Scored entity-day aggregation: same features plus aggregated `window_model_score` from the temporal-rarity HGB window model.

Artifacts:

| Split | Variant | Dataset | Run | First entity-day rank | Top-50 windows | Top-500 windows | Calibrated daily-25 policy | Reading |
| --- | --- | --- | --- | ---: | ---: | ---: | --- | --- |
| `date` | Raw entity-day HGB | `datasets_redteam_temporal_rarity_entity_day` | `20260529_164015` | 9 | 3/38 | 6/38 | 105 entity-days, 3/15 entities, 3/38 windows | Good first hit, but weaker than the previous entity-day policy. |
| `date` | Scored entity-day HGB | `datasets_redteam_temporal_rarity_entity_day_scored` | `20260529_164752` | 87 | 0/38 | 20/38 | 149 entity-days, 4/15 entities, 9/38 windows | Improves global top-500 window coverage, but not calibrated SOC coverage. |
| `fold_0` | Raw entity-day HGB | `datasets_redteam_temporal_rarity_entity_day` | `20260529_164128` | 99 | 0/522 | 2/522 | 391 entity-days, 2/5 entities, 2/522 windows | Does not transfer well to unseen red-team entities. |
| `fold_0` | Scored entity-day HGB | `datasets_redteam_temporal_rarity_entity_day_scored` | `20260529_165022` | 33 | 2/522 | 3/522 | 364 entity-days, 3/5 entities, 3/522 windows | Better than raw entity-day, but still below the existing fold entity-day policy. |

Interpretation:

- Entity-day training is reproducible and much cheaper than window-level training after derivation, but it does not replace the current best SOC policies.
- Adding the window HGB score is useful: `date` top-500 improves to 20/38 windows and `fold_0` first entity-day rank improves from 99 to 33.
- Validation-calibrated policy coverage remains weaker than the existing temporal-rarity entity-day policy: `date` daily-25 reaches 9/38 windows versus 15/38, and `fold_0` daily-25 reaches 3/522 versus 4/522.
- This closes the low-cost entity-first experiment. The next improvement should preserve concrete destination and source-destination identity features during preparation instead of adding more aggregate-only entity-day models.

## Identity-Enriched Preparation

P8E is now implemented as a separate raw preparer, `src/models/CSR-LANL/prepare_dataset_identity.py`, so `src/models/CSR-LANL/prepare_dataset.py` can remain the original/base preparation path. The identity profile writes to `datasets_redteam_identity` by default and adds stable hashed counters plus causal novelty features for destination computers, destination ports, source-destination pairs, and source-destination-port pairs.

Smoke validation passed on `datasets_redteam_identity_smoke/date/CSR-LANL`: 88,487 windows, 6/6 matched red-team entity-windows, and 209 total features. The schema contains 51 base features, 128 identity sketch buckets, and 30 identity summary/novelty features. `validate_splits.py` accepts the smoke `date` split.

The first full-window attempt with all red-team events and a +/- 1 hour radius was too memory-intensive for the current in-memory accumulator design. A bounded identity profile was therefore materialized under:

```text
src/models/CSR-LANL/datasets_redteam_identity_500k
```

This bounded profile uses `source_set=auth_flow`, `redteam_window_hours=0.25`, `redteam_window_limit=100`, `max_rows_per_source=500000`, and 209 features. It produced 198,909 windows and 13 matched red-team entity-windows. This is useful as a smoke-to-training experiment, but it is not directly comparable with the larger temporal/rarity datasets because the test support is much smaller.

Identity 500k operational results:

| Split | Model | Artifact run | Test rows | Test attacks | First attack rank | Window top-25 | Window top-50 | Window top-100 | Entity top-10 | Entity-day daily-5 | Reading |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `date` | HGB binary balanced | `20260530_193005` | 19,308 | 4 | 13 | 1/4 | 2/4 | 2/4 | 1/1 | 1/1 | Strong low-budget ranking on the bounded subset. |
| `date` | IsolationForest | `20260530_193117` | 19,308 | 4 | 733 | 0/4 | 0/4 | 0/4 | 0/1 | 0/1 | Does not benefit from identity sketches here. |
| `date` | HGB multiclass | `20260530_193409` | 19,308 | 4 | 9,397 | 0/4 | 0/4 | 0/4 | 0/1 | 0/1 | Not useful on this tiny multiclass support. |
| `fold_0` | HGB binary balanced | `20260530_193046` | 39,782 | 9 | 10 | 1/9 | 2/9 | 2/9 | 1/1 | 0/1 | Good first hit and entity ranking, limited window recall. |
| `fold_0` | IsolationForest | `20260530_193124` | 39,782 | 9 | 1,429 | 0/9 | 0/9 | 0/9 | 0/1 | 0/1 | Weak operational ranking. |

Comparison against the previous temporal-rarity HGB is favorable in low-budget ranking, but only on the bounded subset:

| Split | Feature profile | Artifact run | Test attacks | First attack rank | Window top-100 | Entity top-10 / top-100 | Entity-day daily-5 | Caveat |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `date` | Temporal rarity/multi-scale | `20260527_144125` | 38 | 72 | 2/38 | 1/15 at top-10 | 2/38 windows | Larger and more thesis-comparable. |
| `date` | Identity 500k | `20260530_193005` | 4 | 13 | 2/4 | 1/1 at top-10 | 4/4 windows inside selected entity-day | Better ranking, but much smaller support. |
| `fold_0` | Temporal rarity/multi-scale | `20260527_151925` | 522 | 4 | 3/522 | 2/5 at top-10, 3/5 at top-100 | 3/522 windows | Larger secondary evidence. |
| `fold_0` | Identity 500k | `20260530_193046` | 9 | 10 | 2/9 | 1/1 at top-10 | 0/9 windows at daily-5, 9/9 at daily-10 | Better bounded subset entity ranking; not enough attack support. |

Interpretation:

- Identity-preserving sketches help the HGB binary model rank red-team activity much earlier on the bounded subset.
- The bounded profile is operationally promising, especially for first-hit and entity ranking, but it is too small to replace the temporal/rarity evidence in the thesis.
- IsolationForest remains weak on CSR-LANL, even with identity features.
- Multiclass is not useful at this support level.

A larger bounded identity profile was then materialized under:

```text
src/models/CSR-LANL/datasets_redteam_identity_1m
```

Despite the name, this run used `max_rows_per_source=5000000`, `redteam_window_hours=0.5`, and `redteam_window_limit=200`. It produced 1,773,706 windows and 60 matched red-team entity-windows. This is more useful than the 500k profile for support analysis, but still much smaller than the full temporal/rarity reference datasets.

Identity 5M operational results:

| Split | Model | Artifact run | Test rows | Test attacks | First attack rank | Window top-100 | Window top-500 | Entity top-50 | Entity-day daily-25 | Reading |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `date` | HGB binary balanced | `20260530_204440` | 231,386 | 5 | 50,946 | 0/5 | 0/5 | 1/4 | 1/4 | Poor window ranking; entity ranking preserves a weak signal. |
| `date` | HGB multiclass | `20260530_204646` | 231,386 | 5 | 7,715 | 0/5 | 0/5 | 0/4 | 0/4 | Better than binary by rank, still misses low-budget windows. |
| `date` | IsolationForest | `20260530_205144` | 231,386 | 5 | 1,325 | 0/5 | 0/5 | 3/4 at top-50 | 2/4 | Best identity-5M model by entity ranking, but no top-500 window recall. |
| `fold_0` | HGB binary balanced | `20260530_204510` | 354,742 | 30 | 1,269 | 0/30 | 0/30 | 0/3 | 0/3 | Does not transfer on this larger identity subset. |
| `fold_0` | HGB multiclass | `20260530_205123` | 354,742 | 30 | 1,910 | 0/30 | 0/30 | 0/3 | 0/3 | No operational value here. |
| `fold_0` | IsolationForest | `20260530_205212` | 354,742 | 30 | 7,993 | 0/30 | 0/30 | 1/3 at top-50 | 3/3 at daily-25 | Useful only as entity-day triage signal, not window ranking. |

Interpretation of the larger identity run:

- Increasing the bounded profile from 500k to 5M rows per source improved attack support from 13 to 60 matched entity-windows, but degraded direct window ranking.
- HGB binary, which looked promising on 500k, does not keep that advantage on the larger bounded profile.
- IsolationForest becomes comparatively better for entity/entity-day triage on identity 5M, but it still fails to place attack windows inside low global top-k budgets.
- The identity sketches are therefore not yet a replacement for the temporal/rarity feature profile. They are a useful ablation showing that raw identity preservation matters, but the current in-memory sketch/novelty design and sampling policy need refinement.
- The next engineering step is to reduce memory and improve the identity feature design before attempting a full comparable P8E materialization: for example, incremental sketches instead of per-window raw sets, stronger destination/port aggregation, and explicit validation that selected entity-days contain the relevant attack windows.

## Identity V3 Preparation and Results

The CSR-LANL V3 profile was implemented as a separate branch of files, preserving all previous dataset versions. The preparer is `src/models/CSR-LANL/prepare_dataset_identity_v3.py`, the V3 evaluator is `src/models/CSR-LANL/evaluate_operational_v3.py`, and the interpretable SOC baseline is `src/models/CSR-LANL/score_hybrid_v3.py`.

The first V3 dataset was materialized under:

```text
src/models/CSR-LANL/datasets_redteam_identity_v3
```

Configuration summary: `source_set=auth_flow`, `redteam_window_hours=1.0`, `redteam_window_limit=250`, `max_rows_per_source=8000000`, `max_windows=2000000`, and `target_policy=exact`. The run produced 2,000,000 final windows from 2,860,659 aggregated windows, with 65 exact red-team windows, 2,128 context-60m windows, 4,112 entity-day windows, 20 red-team entities, and 23 red-team entity-days.

V3 split support:

| Split mode | Split | Rows | Exact attacks | Red-team entities | Red-team days | Reading |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `date` | Train | 1,503,686 | 47 | 15 | 2 | Enough positives for supervised training. |
| `date` | Val | 234,460 | 12 | 5 | 1 | Small but usable calibration set. |
| `date` | Test | 261,854 | 6 | 2 | 1 | Primary temporal evidence remains sparse. |
| `fold_0` | Train | 1,200,000 | 21 | 12 | 3 | Entity-separated training support is lower but valid. |
| `fold_0` | Val | 400,000 | 10 | 4 | 2 | Useful validation support. |
| `fold_0` | Test | 400,000 | 34 | 4 | 3 | Stronger V3 generalization test than the `date` test. |

Artifacts trained and evaluated:

| Model | Split | Artifact run | Labels evaluated |
| --- | --- | --- | --- |
| HGB binary balanced | `date` | `20260531_000623` | exact, context-60m, entity-day |
| HGB binary balanced | `fold_0` | `20260531_000706` | exact, context-60m, entity-day |
| HGB multiclass | `date` | `20260531_004002` | exact, context-60m, entity-day |
| HGB multiclass | `fold_0` | `20260531_004028` | exact, context-60m, entity-day |
| IsolationForest | `date` | `20260531_001734` | exact, context-60m, entity-day |
| IsolationForest | `fold_0` | `20260531_002323` | exact, context-60m, entity-day |
| Hybrid SOC score | `date` | `20260531_v3_hybrid_date_*` | exact, context-60m, entity-day |
| Hybrid SOC score | `fold_0` | `20260531_v3_hybrid_fold0_*` | exact, context-60m, entity-day |

Main V3 operational results:

| Split | Model / label | Test attacks | First rank | Top-500 window recall | Entity top-50 | Entity-day daily-25 | Entity policy daily-25 window recall | Reading |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `date` | HGB binary / exact | 6 | 9,696 | 0/6 | 0/2 | 0/2 | 0/6 | Not useful for exact temporal test. |
| `date` | IsolationForest / context-60m | 368 | 414 | 3/368 | 2/5 | 2/5 | 75/368 | Useful contextual triage signal. |
| `date` | IsolationForest / entity-day | 818 | 168 | 5/818 | 2/6 | 2/6 | 310/818 | Best V3 date triage result, but still not better than temporal/rarity for direct window ranking. |
| `date` | Hybrid / context-60m | 368 | 46 | 9/368 | 1/5 | 1/5 | 0/368 | Strong first contextual hit, weak calibrated entity policy. |
| `fold_0` | HGB binary / entity-day | 1,415 | 112 | 28/1,415 | 1/4 | 1/6 | 324/1,415 | Some signal, but below IsolationForest for entity-day triage. |
| `fold_0` | IsolationForest / exact | 34 | 3,193 | 0/34 | 2/4 | 4/6 | 32/34 | Strong entity-day coverage of exact attacks despite weak global window ranking. |
| `fold_0` | IsolationForest / entity-day | 1,415 | 1,282 | 0/1,415 | 2/4 | 4/6 | 1,327/1,415 | Best V3 fold triage result. |
| `fold_0` | Hybrid / exact | 34 | 4,182 | 0/34 | 2/4 | 3/6 | 31/34 | Useful fallback triage baseline, slightly weaker than IsolationForest. |
| `fold_0` | HGB multiclass / all labels | 34-1,415 | 3,718-8,333 | 0 | 0 | 0 | 0 | No operational value in this V3 configuration. |

Comparison with the previous temporal/rarity reference:

| Evidence | Temporal/rarity HGB | V3 result | Interpretation |
| --- | ---: | ---: | --- |
| `date` exact first rank | 72 | HGB exact 9,696; Iso exact 15,642 | V3 is worse for exact temporal window ranking. |
| `date` context/entity first rank | Not directly labeled | Hybrid context/entity 46; Iso entity-day 168 | V3 adds useful SOC-context evaluation not available in the old exact-only framing. |
| `date` entity-policy window recall | 15/38 exact windows | Iso V3 entity-day policy 310/818 entity-day windows | Not directly comparable, but V3 improves the triage narrative. |
| `fold_0` exact first rank | 4 | HGB exact 1,406; Iso exact 3,193 | V3 is worse for direct exact global ranking. |
| `fold_0` entity-day daily-25 | 1/6 red-team entity-days equivalent, 4/522 exact windows in selected entity-days | Iso V3 daily-25 finds 4/6 red-team entity-days and 32/34 exact windows in selected entity-days | V3 is much stronger as entity-day triage evidence. |

Interpretation of V3:

- V3 does not beat temporal/rarity for direct exact window ranking. The best exact global ranking remains the older temporal/rarity HGB fold result.
- V3 substantially improves the CSR-LANL SOC triage story, especially on `fold_0`, where IsolationForest ranks red-team entities at entity rank 3 and covers 32/34 exact attack windows through a daily entity-day policy of about 23 selected entity-days per day.
- This changes the role of CSR-LANL in the thesis: the strongest V3 result is not ML classification of exact rows, but entity-centric prioritization under severe imbalance.
- HGB binary is not the best V3 model. HGB multiclass should be treated as a negative ablation. IsolationForest V3 is currently the strongest candidate for CSR-LANL entity-day triage.
- The hybrid SOC score is valuable as an interpretable baseline, but its calibrated policy is weaker than IsolationForest in this run.

## Split Validity

Current split validation:

| Split | Status | Test red-team windows | Test red-team entities | Interpretation |
| --- | ---: | ---: | ---: | --- |
| `date` | ok | 38 | 15 | Primary CSR-LANL evidence. |
| `random` | warn | 3 | 3 | Sanity check only. |
| `groupkfold/fold_0` | warn | 1 | 1 | Not defensible for thesis conclusions. |
| `redteam_stratified_groupkfold/fold_0` | ok | 522 | 5 | Defensible as secondary entity-generalization evidence. |

The pipeline now includes `redteam_stratified_groupkfold`, which preserves entity separation while balancing red-team entities across folds. `fold_0` was materialized from the already prepared `date` Parquet dataset, avoiding a full raw `.txt.gz` rescan.

Validated `redteam_stratified_groupkfold/fold_0` support:

| Split | Rows | Red-team windows | Red-team entities | Attack days |
| --- | ---: | ---: | ---: | ---: |
| Train | 13,286,691 | 507 | 223 | 18 |
| Val | 4,428,897 | 169 | 74 | 14 |
| Test | 4,428,898 | 522 | 5 | 14 |

## Red-Team-Stratified Fold Results

Artifacts evaluated on `redteam_stratified_groupkfold/fold_0`:

| Model | Artifact run | First attack rank | Window top-100 | Window top-500 | Entity top-50 | Entity top-500 | Reading |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| HGB binary balanced | `20260526_140337` | 8 | 3/522 | 3/522 | 3/5 | 4/5 | Best low-budget operational signal; still weak window recall. |
| HGB multiclass | `20260526_140631` | 5,871 | 0/522 | 0/522 | 0/5 | 1/5 | High accuracy but poor low-budget prioritization. |
| IsolationForest | `20260526_140818` | 88,530 | 0/522 | 0/522 | 0/5 | 1/5 | Weak on this entity-generalization split. |

Temporal HGB binary balanced on the same validated fold:

| Feature profile | Artifact run | First attack rank | Window top-100 | Window top-500 | Entity top-50 | Entity top-500 | Reading |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Baseline auth/flow | `20260526_140337` | 8 | 3/522 | 3/522 | 3/5 | 4/5 | Best fold result for window recall at low budget. |
| Temporal entity history | `20260526_150731` | 7 | 2/522 | 3/522 | 2/5 | 4/5 | Earlier first hit, but no improvement in overall fold recall. |
| Temporal rarity/multi-scale | `20260527_151925` | 4 | 3/522 | 3/522 | 3/5 | 4/5 | Best first hit; matches baseline top-k recall but does not improve sparse window coverage. |

Validation-calibrated policies on `fold_0`:

| Model | Policy | Alerts/day | Red-team windows | Red-team entities | Attack days | Reading |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| HGB binary balanced | `budget_daily_5_on_val` | 3.89 | 3/522 | 3/5 | 2/14 | Best practical policy tested. |
| HGB binary balanced | `max_f2_on_val` | 30.44 | 3/522 | 3/5 | 2/14 | More alerts do not improve window recall. |
| HGB binary temporal | `budget_daily_5_on_val` | 4.50 | 2/522 | 2/5 | 2/14 | Slightly worse than the non-temporal fold baseline. |
| HGB binary temporal | `max_f2_on_val` | 31.28 | 3/522 | 3/5 | 2/14 | Matches baseline window/entity hits only with similar alert volume. |
| HGB binary temporal rarity | `budget_daily_5_on_val` | 4.28 | 2/522 | 2/5 | 2/14 | Better first-hit rank, but direct daily alert policy remains sparse. |
| HGB binary temporal rarity | `budget_daily_50_on_val` | 38.28 | 4/522 | 4/5 | 2/14 | Recovers one extra window/entity at higher alert volume. |
| HGB multiclass | `max_f2_on_val` | 941.72 | 49/522 | 2/5 | 7/14 | Better raw recall, operationally too noisy. |
| IsolationForest | `max_f2_on_val` | 0.00 | 0/522 | 0/5 | 0/14 | No useful calibrated alert policy here. |

Interpretation:

- The redesigned fold is now suitable for a secondary thesis experiment because test has enough red-team windows and multiple red-team entities with entity separation.
- HGB binary balanced remains the most useful operational model: it places a red-team window at rank 8 and finds 3/5 red-team entities in the top-50 entities.
- Temporal entity-history features are promising on the `date` split, but they do not improve the validated entity-generalization fold enough to replace the non-temporal fold baseline.
- Temporal rarity/multi-scale features improve the earliest fold hit from rank 8 to rank 4 and preserve 4/5 entity coverage in entity-day policy with fewer selected entity-days, but they still do not improve top-500 window recall beyond 3/522.
- Entity-calibrated policies improve the triage story and are more SOC-aligned than direct window thresholds, especially for the `date` temporal rarity artifact.
- The window-level recall remains low even on the better split, so CSR-LANL should still be framed as prioritization evidence and a limitation of the current feature set.
- Multiclass can recover more red-team windows only with an alert volume that is not SOC-practical.
- IsolationForest does not add value on this fold.

## Conclusion

CSR-LANL currently demonstrates that the project can expose weak operational behavior that accuracy hides. The best current use is prioritization and triage support, not direct automated incident classification.

The temporal feature experiment should be kept: it improves the primary `date` split and provides useful thesis evidence about feature design. The temporal rarity profile should also be kept as SOC triage evidence because it improves entity-day coverage on `date` and first-hit ranking on `fold_0`, but it is not a replacement for the strongest fold baseline at window recall. The entity-day scorer experiment is useful as an ablation, especially the scored variant, but it does not beat the current validation-calibrated entity-day policies. The next defensible step is evaluating the new identity-enriched raw preparation profile on `date` and `redteam_stratified_groupkfold/fold_0` before materializing all remaining folds.