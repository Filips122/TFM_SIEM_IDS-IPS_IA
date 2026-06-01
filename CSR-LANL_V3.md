# CSR-LANL V3

CSR-LANL V3 is a new experimental branch of the CSR-LANL pipeline. It does not replace the previous datasets or scripts.

## Purpose

The objective is to make CSR-LANL stronger as thesis evidence by treating it as an operational SOC triage problem instead of a simple row-level classification benchmark.

V3 adds:

- exact, context, and entity-day labels,
- causal entity-history features,
- identity/novelty pressure features,
- stratified benign sampling with hard benign windows,
- an interpretable hybrid risk baseline.

## New Files

| File | Purpose |
| --- | --- |
| `src/models/CSR-LANL/prepare_dataset_identity_v3.py` | Builds a new identity V3 dataset from raw CSR-LANL files. |
| `src/models/CSR-LANL/evaluate_operational_v3.py` | Evaluates trained artifacts using exact, context, or entity-day labels. |
| `src/models/CSR-LANL/score_hybrid_v3.py` | Computes an interpretable hybrid SOC risk score without training a model. |

## Recommended First V3 Dataset

This profile is larger and more balanced than the previous 500k profile, but still bounded to avoid exhausting RAM.

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\prepare_dataset_identity_v3.py `
  --out_dir src\models\CSR-LANL\datasets_redteam_identity_v3 `
  --split_mode date redteam_stratified_groupkfold `
  --fold 0 `
  --source_set auth_flow `
  --redteam_window_hours 1.0 `
  --redteam_window_limit 250 `
  --max_rows_per_source 8000000 `
  --max_windows 2000000 `
  --target_policy exact `
  --min_redteam_matches 15 `
  --chunk_size 75000 `
  --progress_every_chunks 5 `
  --progress_every_rows 1000000
```

If RAM pressure is high, reduce in this order:

1. `--max_rows_per_source 5000000`
2. `--redteam_window_limit 200`
3. `--max_windows 1200000`
4. `--redteam_window_hours 0.5`

## Train Models

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\train_ml_binary_hgb.py `
  --datasets_base src\models\CSR-LANL\datasets_redteam_identity_v3 `
  --split_mode date `
  --dataset CSR-LANL `
  --epochs 215 `
  --class_weight balanced

.\.venv\Scripts\python.exe src\models\CSR-LANL\train_ml_binary_hgb.py `
  --datasets_base src\models\CSR-LANL\datasets_redteam_identity_v3 `
  --split_mode redteam_stratified_groupkfold `
  --dataset CSR-LANL `
  --fold 0 `
  --epochs 215 `
  --class_weight balanced

.\.venv\Scripts\python.exe src\models\CSR-LANL\train_anomaly_isoforest.py `
  --datasets_base src\models\CSR-LANL\datasets_redteam_identity_v3 `
  --split_mode date `
  --dataset CSR-LANL `
  --epochs 315

.\.venv\Scripts\python.exe src\models\CSR-LANL\train_anomaly_isoforest.py `
  --datasets_base src\models\CSR-LANL\datasets_redteam_identity_v3 `
  --split_mode redteam_stratified_groupkfold `
  --dataset CSR-LANL `
  --fold 0 `
  --epochs 315
```

## Evaluate Trained Models With V3 Labels

Replace `<ARTIFACT_DIR>` with the run folder printed by the trainer.

Exact event-window evaluation:

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\evaluate_operational_v3.py `
  --artifact_dir <ARTIFACT_DIR> `
  --datasets_base src\models\CSR-LANL\datasets_redteam_identity_v3 `
  --split_mode date `
  --dataset CSR-LANL `
  --pipeline binary `
  --model_kind hgb `
  --attack_label exact
```

Context evaluation:

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\evaluate_operational_v3.py `
  --artifact_dir <ARTIFACT_DIR> `
  --datasets_base src\models\CSR-LANL\datasets_redteam_identity_v3 `
  --split_mode date `
  --dataset CSR-LANL `
  --pipeline binary `
  --model_kind hgb `
  --attack_label context_60m
```

Entity-day triage evaluation:

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\evaluate_operational_v3.py `
  --artifact_dir <ARTIFACT_DIR> `
  --datasets_base src\models\CSR-LANL\datasets_redteam_identity_v3 `
  --split_mode date `
  --dataset CSR-LANL `
  --pipeline binary `
  --model_kind hgb `
  --attack_label entity_day
```

## Hybrid Risk Baseline

The hybrid scorer does not train a model. It uses V3 risk features, robust scaling learned from train, and operational top-k evaluation.

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\score_hybrid_v3.py `
  --datasets_base src\models\CSR-LANL\datasets_redteam_identity_v3 `
  --split_mode date `
  --dataset CSR-LANL `
  --pipeline binary `
  --attack_label exact
```

For entity-day triage:

```powershell
.\.venv\Scripts\python.exe src\models\CSR-LANL\score_hybrid_v3.py `
  --datasets_base src\models\CSR-LANL\datasets_redteam_identity_v3 `
  --split_mode date `
  --dataset CSR-LANL `
  --pipeline binary `
  --attack_label entity_day
```

## Thesis Interpretation

Use V3 to compare four CSR-LANL profiles:

| Profile | Role |
| --- | --- |
| Temporal/rarity | Current strongest CSR-LANL reference. |
| Identity 500k | Small identity-preservation ablation. |
| Identity 5M | Larger bounded identity ablation. |
| Identity V3 | Candidate strong CSR-LANL profile with context labels, sampling, and hybrid risk. |

The most important V3 result is not only window recall. It should also be evaluated through red-team entity recall, entity-day recall, attack-day coverage, first-hit rank, and alerts/day.