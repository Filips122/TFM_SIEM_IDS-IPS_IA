# UGR16 prepare_dataset_v3

This folder contains a size-aware UGR16 dataset builder for the date split.

The goal is practical, not archival:

- produce a trainable Parquet dataset for the existing UGR16 binary and anomaly models,
- keep the final dataset inside a bounded disk budget,
- avoid overwriting the current `UGR16` dataset unless you explicitly choose that name.

## What It Builds

By default the builder writes:

- `binary`
- `anomaly`

Optional outputs:

- `multiclass` with `--include_multiclass`
- `binary_raw` with `--keep_binary_raw`

The default layout is still compatible with the existing UGR16 loaders and trainers:

```text
src/models/UGR16/datasets/date/<dataset_name>/binary/train/*.parquet
src/models/UGR16/datasets/date/<dataset_name>/binary/val/*.parquet
src/models/UGR16/datasets/date/<dataset_name>/binary/test/*.parquet
src/models/UGR16/datasets/date/<dataset_name>/anomaly/train_benign/*.parquet
src/models/UGR16/datasets/date/<dataset_name>/anomaly/val_mixed/*.parquet
src/models/UGR16/datasets/date/<dataset_name>/anomaly/test_mixed/*.parquet
```

## How The Size Cap Works

The script uses two passes.

1. A planning pass scans the selected archives, counts clean rows after timestamp parsing, and estimates Parquet bytes per row from sampled preprocessed chunks.
2. A build pass applies a deterministic sampling fraction so the final dataset stays near the requested disk target.

The defaults aim for an output close to `80 GB` while staying below `95 GB` in normal runs.

## Default Command

```powershell
python .\src\models\UGR16\prepare_dataset_v3\build.py
```

This creates:

```text
src/models/UGR16/datasets/date/UGR16_V3_80GB
```

## Useful Variants

Build a tighter dataset near `60 GB`:

```powershell
python .\src\models\UGR16\prepare_dataset_v3\build.py --target_size_gb 60 --max_size_gb 70 --dataset_name UGR16_V3_60GB
```

Include the multiclass pipeline too:

```powershell
python .\src\models\UGR16\prepare_dataset_v3\build.py --include_multiclass --target_size_gb 95 --max_size_gb 100 --dataset_name UGR16_V3_95GB_MULTI
```

Keep the raw binary staging split for auditability:

```powershell
python .\src\models\UGR16\prepare_dataset_v3\build.py --keep_binary_raw --dataset_name UGR16_V3_80GB_RAW
```

Write only the plan without building:

```powershell
python .\src\models\UGR16\prepare_dataset_v3\build.py --plan_only
```

## Train Existing Models On The New Dataset

Binary HGB:

```powershell
python .\src\models\UGR16\train_ml_binary_hgb.py --split_mode date --dataset UGR16_V3_80GB --epochs 200
```

Binary MLP:

```powershell
python .\src\models\UGR16\train_ml_binary_mlp.py --split_mode date --dataset UGR16_V3_80GB --epochs 25
```

Anomaly Isolation Forest:

```powershell
python .\src\models\UGR16\train_anomaly_isoforest.py --split_mode date --dataset UGR16_V3_80GB --epochs 300
```

Multiclass HGB, only if you built `--include_multiclass`:

```powershell
python .\src\models\UGR16\train_ml_multiclass_hgb.py --split_mode date --dataset UGR16_V3_95GB_MULTI --epochs 250
```

## Notes

- `prepare_dataset_v3` currently targets the `date` split only.
- The default metadata mode is `minimal` to save space.
- The builder keeps the original feature order used by the current UGR16 models.