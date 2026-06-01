#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import shutil
import warnings
from pathlib import Path
from typing import Any, Dict, List, Sequence

import numpy as np
import pandas as pd
import joblib
from pandas.errors import PerformanceWarning

from data_loader import GROUP_FOLD_SPLIT_MODES, list_parquets, load_feature_columns, mode_root, resolve_from_root, split_folder


SPLIT_MODE_CHOICES = ["date", "random", "groupkfold", "redteam_stratified_groupkfold"]
SPLITS = ["train", "val", "test"]
META_COLUMNS = ["target", "window_start", "window_end", "entity", "redteam_exact", "redteam_near"]
WINDOW_SCORE_COLUMN = "window_model_score"
EXCLUDED_BASE_FEATURES = {"day_index", "hour_index", "minute_of_day"}
SOC_FEATURE_TOKENS = (
    "event_count",
    "_count",
    "unique_",
    "_sum",
    "_mean",
    "_max",
    "ratio",
    "fail",
    "byte",
    "packet",
    "duration",
    "port",
    "dst_",
    "process",
    "source",
    "novelty",
    "breadth",
    "pressure",
    "prior",
    "zscore",
    "roll",
    "density",
    "age",
    "off_hours",
    "gap",
)
SUM_FEATURE_TOKENS = (
    "event_count",
    "_count",
    "_sum",
    "byte",
    "packet",
    "duration",
    "novelty",
    "breadth",
    "pressure",
)

warnings.filterwarnings("ignore", category=PerformanceWarning)


def json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    if isinstance(value, tuple):
        return [json_ready(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        number = float(value)
        return number if np.isfinite(number) else None
    if isinstance(value, float):
        return value if np.isfinite(value) else None
    if isinstance(value, (np.bool_,)):
        return bool(value)
    return value


def save_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_ready(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def bool_series(series: pd.Series) -> pd.Series:
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False).astype(bool)
    text = series.astype(str).str.strip().str.lower()
    return text.isin({"1", "true", "t", "yes", "y"})


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_artifact_dir(path: str | Path, fold: int | None) -> Path:
    artifact_dir = resolve_from_root(path)
    if (artifact_dir / "model.joblib").exists():
        return artifact_dir
    if fold is not None:
        fold_dir = artifact_dir / f"fold_{fold}"
        if (fold_dir / "model.joblib").exists():
            return fold_dir
    raise SystemExit(f"No model.joblib found in artifact directory: {artifact_dir}")


def label_order(artifact_dir: Path) -> List[str]:
    path = artifact_dir / "label_map.json"
    if not path.exists():
        return ["BENIGN", "ATTACK"]
    mapping = read_json(path)
    ordered = [None] * (max(int(index) for index in mapping.values()) + 1)
    for label, index in mapping.items():
        ordered[int(index)] = str(label)
    return [label if label is not None else f"class_{index}" for index, label in enumerate(ordered)]


def positive_column(class_names: Sequence[str]) -> int:
    upper_names = [str(name).upper() for name in class_names]
    if "ATTACK" in upper_names:
        return upper_names.index("ATTACK")
    return 1 if len(class_names) > 1 else 0


def predict_proba_batches(model: Any, features: np.ndarray, batch_size: int) -> np.ndarray:
    batches = []
    for start in range(0, len(features), batch_size):
        stop = min(start + batch_size, len(features))
        batches.append(model.predict_proba(features[start:stop]))
    return np.concatenate(batches, axis=0) if batches else np.empty((0, 0), dtype=np.float64)


def select_base_features(feature_columns: Sequence[str], feature_mode: str) -> List[str]:
    candidates = [column for column in feature_columns if column not in EXCLUDED_BASE_FEATURES]
    if feature_mode == "all":
        return candidates
    selected = [column for column in candidates if any(token in column.lower() for token in SOC_FEATURE_TOKENS)]
    if not selected:
        raise SystemExit("No base features selected for entity-day aggregation")
    return selected


def is_sum_feature(column: str) -> bool:
    lower = column.lower()
    return any(token in lower for token in SUM_FEATURE_TOKENS)


def split_input_paths(datasets_base: str | Path, split_mode: str, dataset: str, split: str, fold: int | None) -> List[Path]:
    folder = split_folder(datasets_base, split_mode, dataset, "binary", split, fold)
    paths = list_parquets(folder)
    if not paths:
        raise FileNotFoundError(f"No parquet files in: {folder}")
    return paths


def read_limited_parquet(path: Path, columns: Sequence[str], remaining_rows: int | None) -> pd.DataFrame:
    frame = pd.read_parquet(path, columns=list(columns))
    if remaining_rows is not None and len(frame) > remaining_rows:
        frame = frame.head(remaining_rows).copy()
    return frame


def aggregate_chunk(frame: pd.DataFrame, base_features: Sequence[str], sum_features: set[str]) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame()
    frame = frame.copy()
    frame["entity"] = frame.get("entity", "Unknown").fillna("Unknown").astype(str)
    frame["window_start"] = pd.to_numeric(frame.get("window_start", 0), errors="coerce").fillna(0).astype(np.int64)
    frame["window_end"] = pd.to_numeric(frame.get("window_end", frame["window_start"]), errors="coerce").fillna(frame["window_start"]).astype(np.int64)
    frame["day_index"] = (frame["window_start"] // 86400).astype(np.int64)
    target_attack = frame["target"].astype(str).str.upper() != "BENIGN"
    redteam_exact = bool_series(frame["redteam_exact"]) if "redteam_exact" in frame.columns else pd.Series(False, index=frame.index)
    redteam_near = bool_series(frame["redteam_near"]) if "redteam_near" in frame.columns else pd.Series(False, index=frame.index)
    frame["_is_attack"] = (target_attack | redteam_exact).astype(np.int8)
    frame["_redteam_near"] = redteam_near.astype(np.int8)
    frame.loc[:, list(base_features)] = frame.loc[:, list(base_features)].fillna(0.0)

    group = frame.groupby(["entity", "day_index"], dropna=False, sort=False)
    meta = group.agg(
        window_count=("target", "size"),
        attack_window_count=("_is_attack", "sum"),
        redteam_near_window_count=("_redteam_near", "sum"),
        first_window_start=("window_start", "min"),
        last_window_start=("window_start", "max"),
        first_window_end=("window_end", "min"),
        last_window_end=("window_end", "max"),
    )
    feature_sum = group[list(base_features)].sum().rename(columns={column: f"__sum__{column}" for column in base_features})
    feature_max = group[list(base_features)].max().rename(columns={column: f"__max__{column}" for column in base_features})
    out = pd.concat([meta, feature_sum, feature_max], axis=1).reset_index()
    out["window_count"] = out["window_count"].astype(np.int64)
    out["attack_window_count"] = out["attack_window_count"].astype(np.int64)
    out["redteam_near_window_count"] = out["redteam_near_window_count"].astype(np.int64)
    return out


def finalize_entity_days(partials: List[pd.DataFrame], base_features: Sequence[str], sum_features: set[str]) -> pd.DataFrame:
    if not partials:
        return pd.DataFrame()
    combined = pd.concat(partials, ignore_index=True)
    agg_spec: Dict[str, str] = {
        "window_count": "sum",
        "attack_window_count": "sum",
        "redteam_near_window_count": "sum",
        "first_window_start": "min",
        "last_window_start": "max",
        "first_window_end": "min",
        "last_window_end": "max",
    }
    for column in base_features:
        agg_spec[f"__sum__{column}"] = "sum"
        agg_spec[f"__max__{column}"] = "max"
    final = combined.groupby(["entity", "day_index"], dropna=False, sort=False).agg(agg_spec).reset_index()
    denominator = final["window_count"].replace(0, 1).astype(np.float32)
    feature_columns: List[str] = [
        "window_count",
        "window_span_seconds",
        "active_window_density",
        "first_minute_of_day",
        "last_minute_of_day",
    ]
    window_span_seconds = (final["last_window_start"] - final["first_window_start"] + 60).clip(lower=60)
    derived_columns: Dict[str, Any] = {
        "window_span_seconds": window_span_seconds.astype(np.float32),
        "active_window_density": final["window_count"].astype(np.float32) / (window_span_seconds.astype(np.float32) / 60.0).clip(lower=1.0),
        "first_minute_of_day": ((final["first_window_start"] % 86400) // 60).astype(np.int64),
        "last_minute_of_day": ((final["last_window_start"] % 86400) // 60).astype(np.int64),
    }
    for column in base_features:
        sum_column = f"__sum__{column}"
        max_column = f"__max__{column}"
        mean_name = f"{column}_day_mean"
        max_name = f"{column}_day_max"
        derived_columns[mean_name] = final[sum_column].astype(np.float32) / denominator
        derived_columns[max_name] = final[max_column].astype(np.float32)
        feature_columns.extend([mean_name, max_name])
        if column in sum_features:
            out_sum_name = f"{column}_day_sum"
            derived_columns[out_sum_name] = final[sum_column].astype(np.float32)
            feature_columns.append(out_sum_name)
    final["target"] = np.where(final["attack_window_count"].to_numpy(dtype=np.int64) > 0, "ATTACK", "BENIGN")
    drop_columns = [column for column in final.columns if column.startswith("__sum__") or column.startswith("__max__")]
    final = final.drop(columns=drop_columns)
    final = pd.concat([final, pd.DataFrame(derived_columns, index=final.index)], axis=1).copy()
    ordered = list(dict.fromkeys([
        "entity",
        "day_index",
        "target",
        "window_count",
        "attack_window_count",
        "redteam_near_window_count",
        "first_window_start",
        "last_window_start",
        "first_window_end",
        "last_window_end",
    ] + [column for column in feature_columns if column in final.columns]))
    return final.loc[:, ordered].sort_values(["day_index", "entity"], kind="mergesort").reset_index(drop=True)


def output_split_folder(target_datasets_base: str | Path, split_mode: str, dataset: str, split: str, fold: int | None) -> Path:
    return split_folder(target_datasets_base, split_mode, dataset, "binary", split, fold)


def write_split(frame: pd.DataFrame, folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for path in folder.glob("*.parquet"):
        path.unlink()
    frame.to_parquet(folder / "part-00000.parquet", index=False)


def materialize_split(
    source_datasets_base: str | Path,
    target_datasets_base: str | Path,
    dataset: str,
    split_mode: str,
    split: str,
    fold: int | None,
    base_features: Sequence[str],
    source_feature_columns: Sequence[str],
    window_model: Any | None,
    window_positive_index: int | None,
    score_batch_size: int,
    max_rows_per_split: int | None,
) -> Dict[str, Any]:
    paths = split_input_paths(source_datasets_base, split_mode, dataset, split, fold)
    aggregation_features = list(base_features)
    read_columns = list(dict.fromkeys(META_COLUMNS + list(base_features) + (list(source_feature_columns) if window_model is not None else [])))
    if window_model is not None:
        aggregation_features = list(dict.fromkeys(list(aggregation_features) + [WINDOW_SCORE_COLUMN]))
    sum_features = {column for column in aggregation_features if is_sum_feature(column)}
    partials: List[pd.DataFrame] = []
    rows_read = 0
    for path in paths:
        remaining = None if max_rows_per_split is None else max_rows_per_split - rows_read
        if remaining is not None and remaining <= 0:
            break
        chunk = read_limited_parquet(path, read_columns, remaining)
        rows_read += int(len(chunk))
        if window_model is not None:
            X_score = chunk.loc[:, list(source_feature_columns)].to_numpy(dtype=np.float32, copy=True)
            np.nan_to_num(X_score, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
            probabilities = predict_proba_batches(window_model, X_score, batch_size=score_batch_size)
            chunk[WINDOW_SCORE_COLUMN] = probabilities[:, int(window_positive_index)]
        partial = aggregate_chunk(chunk, aggregation_features, sum_features)
        if not partial.empty:
            partials.append(partial)
    entity_days = finalize_entity_days(partials, aggregation_features, sum_features)
    out_folder = output_split_folder(target_datasets_base, split_mode, dataset, split, fold)
    write_split(entity_days, out_folder)
    return {
        "split": split,
        "source_rows_read": rows_read,
        "entity_days": int(len(entity_days)),
        "attack_entity_days": int((entity_days["target"].astype(str) == "ATTACK").sum()) if not entity_days.empty else 0,
        "attack_windows": int(entity_days["attack_window_count"].sum()) if not entity_days.empty else 0,
        "redteam_entities": int(entity_days.loc[entity_days["attack_window_count"] > 0, "entity"].nunique()) if not entity_days.empty else 0,
        "days": int(entity_days["day_index"].nunique()) if not entity_days.empty else 0,
    }


def feature_columns_from_sample(target_datasets_base: str | Path, split_mode: str, dataset: str, fold: int | None) -> List[str]:
    train_folder = output_split_folder(target_datasets_base, split_mode, dataset, "train", fold)
    paths = list_parquets(train_folder)
    if not paths:
        raise FileNotFoundError(f"No train entity-day parquet found in: {train_folder}")
    sample = pd.read_parquet(paths[0])
    meta = {
        "entity",
        "day_index",
        "target",
        "attack_window_count",
        "redteam_near_window_count",
        "first_window_start",
        "last_window_start",
        "first_window_end",
        "last_window_end",
    }
    return [column for column in sample.columns if column not in meta]


def write_metadata(
    target_datasets_base: str | Path,
    source_datasets_base: str | Path,
    split_mode: str,
    dataset: str,
    fold: int | None,
    base_features: Sequence[str],
    window_artifact_dir: str | None,
    feature_columns: Sequence[str],
    summaries: Sequence[Dict[str, Any]],
    feature_mode: str,
    max_rows_per_split: int | None,
) -> None:
    root = mode_root(target_datasets_base, split_mode, dataset, fold)
    root.mkdir(parents=True, exist_ok=True)
    (root / "feature_columns.json").write_text(json.dumps(list(feature_columns), ensure_ascii=False, indent=2), encoding="utf-8")
    source_root = mode_root(source_datasets_base, split_mode, dataset, fold)
    profile = {
        "dataset": dataset,
        "profile": "entity_day_from_windows_v1",
        "source_datasets_base": str(resolve_from_root(source_datasets_base)),
        "source_dataset_root": str(source_root),
        "target_dataset_root": str(root),
        "split_mode": split_mode,
        "fold": fold,
        "pipeline": "binary",
        "feature_mode": feature_mode,
        "source_base_feature_count": len(base_features),
        "includes_window_model_score": window_artifact_dir is not None,
        "window_artifact_dir": window_artifact_dir,
        "entity_day_feature_count": len(feature_columns),
        "max_rows_per_split": max_rows_per_split,
        "splits": list(summaries),
    }
    save_json(root / "dataset_profile.json", profile)


def materialize(args: argparse.Namespace) -> Path:
    fold = args.fold if args.split_mode in GROUP_FOLD_SPLIT_MODES else None
    target_root = mode_root(args.target_datasets_base, args.split_mode, args.dataset, fold)
    if target_root.exists():
        if not args.overwrite:
            raise SystemExit(f"Target already exists, use --overwrite to replace it: {target_root}")
        shutil.rmtree(target_root)
    source_features = load_feature_columns(args.source_datasets_base, args.split_mode, args.dataset, fold)
    base_features = select_base_features(source_features, args.feature_mode)
    window_model = None
    window_positive_index = None
    resolved_window_artifact = None
    if args.window_artifact_dir:
        resolved_window_artifact = resolve_artifact_dir(args.window_artifact_dir, fold)
        window_model = joblib.load(resolved_window_artifact / "model.joblib")
        window_positive_index = positive_column(label_order(resolved_window_artifact))
    summaries = []
    for split in SPLITS:
        summaries.append(
            materialize_split(
                source_datasets_base=args.source_datasets_base,
                target_datasets_base=args.target_datasets_base,
                dataset=args.dataset,
                split_mode=args.split_mode,
                split=split,
                fold=fold,
                base_features=base_features,
                source_feature_columns=source_features,
                window_model=window_model,
                window_positive_index=window_positive_index,
                score_batch_size=args.score_batch_size,
                max_rows_per_split=args.max_rows_per_split,
            )
        )
    entity_day_features = feature_columns_from_sample(args.target_datasets_base, args.split_mode, args.dataset, fold)
    write_metadata(
        target_datasets_base=args.target_datasets_base,
        source_datasets_base=args.source_datasets_base,
        split_mode=args.split_mode,
        dataset=args.dataset,
        fold=fold,
        base_features=base_features,
        window_artifact_dir=str(resolved_window_artifact) if resolved_window_artifact is not None else None,
        feature_columns=entity_day_features,
        summaries=summaries,
        feature_mode=args.feature_mode,
        max_rows_per_split=args.max_rows_per_split,
    )
    return target_root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source_datasets_base", default="src/models/CSR-LANL/datasets_redteam_temporal_rarity")
    parser.add_argument("--target_datasets_base", default="src/models/CSR-LANL/datasets_redteam_temporal_rarity_entity_day")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--split_mode", default="date", choices=SPLIT_MODE_CHOICES)
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--feature_mode", default="soc", choices=["soc", "all"])
    parser.add_argument("--window_artifact_dir", default=None, help="Optional window-level HGB artifact used to add window_model_score aggregate features")
    parser.add_argument("--score_batch_size", type=int, default=200000)
    parser.add_argument("--max_rows_per_split", type=int, default=None)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    out = materialize(args)
    print("Saved:", out)


if __name__ == "__main__":
    main()