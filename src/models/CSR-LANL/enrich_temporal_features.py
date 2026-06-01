#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from data_loader import resolve_from_root


SPLITS = ("train", "val", "test")
SOURCE_SPLIT_FOLDERS = {
    "train": Path("binary/train"),
    "val": Path("binary/val"),
    "test": Path("binary/test"),
}
ANOMALY_SPLIT_FOLDERS = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}
ROLLING_WINDOWS = (5, 30)
ROLLING_METRICS = (
    "total_event_count",
    "auth_fail_count",
    "auth_failure_ratio",
    "flow_byte_sum",
    "flow_unique_dst_computer_count",
    "active_source_count",
)
BASE_TEMPORAL_FEATURES = (
    "hour_of_day_sin",
    "hour_of_day_cos",
    "minute_of_day_sin",
    "minute_of_day_cos",
    "is_off_hours",
    "entity_seen_window_count",
    "entity_window_gap_seconds",
)


@dataclass
class SourcePart:
    split: str
    path: Path
    rows: int
    start: int
    end: int


@dataclass
class LabelStats:
    rows: int = 0
    benign: int = 0
    attack: int = 0
    label_counts: Dict[str, int] = field(default_factory=dict)

    def update(self, labels: pd.Series) -> None:
        counts = labels.astype(str).value_counts(dropna=False).to_dict()
        self.rows += int(sum(counts.values()))
        for label, count in counts.items():
            label_text = str(label)
            count_int = int(count)
            self.label_counts[label_text] = self.label_counts.get(label_text, 0) + count_int
            if label_text.upper() == "BENIGN":
                self.benign += count_int
            else:
                self.attack += count_int

    def to_json(self) -> Dict[str, Any]:
        return {
            "rows": int(self.rows),
            "benign": int(self.benign),
            "attack": int(self.attack),
            "label_counts": dict(sorted(self.label_counts.items(), key=lambda item: item[1], reverse=True)),
        }


def temporal_feature_columns() -> List[str]:
    columns = list(BASE_TEMPORAL_FEATURES)
    for metric in ROLLING_METRICS:
        for window in ROLLING_WINDOWS:
            columns.append(f"entity_{metric}_roll{window}_mean")
            columns.append(f"entity_{metric}_roll{window}_delta")
    return columns


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Add causal entity-history features to a prepared CSR-LANL date dataset.")
    parser.add_argument("--source_datasets_base", default="src/models/CSR-LANL/datasets_redteam")
    parser.add_argument("--target_datasets_base", default="src/models/CSR-LANL/datasets_redteam_temporal")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--split_mode", default="date", choices=["date"])
    parser.add_argument("--batch_size", type=int, default=500_000)
    return parser.parse_args()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def clear_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def source_parts(source_root: Path) -> List[SourcePart]:
    parts: List[SourcePart] = []
    offset = 0
    for split in SPLITS:
        folder = source_root / SOURCE_SPLIT_FOLDERS[split]
        paths = sorted(path for path in folder.glob("*.parquet") if path.is_file())
        if not paths:
            raise FileNotFoundError(f"No binary parquet files under {folder}")
        for path in paths:
            rows = int(pq.ParquetFile(path).metadata.num_rows)
            parts.append(SourcePart(split=split, path=path, rows=rows, start=offset, end=offset + rows))
            offset += rows
    return parts


def iter_parquet_batches(path: Path, columns: Optional[Sequence[str]], batch_size: int) -> Iterable[pd.DataFrame]:
    parquet_file = pq.ParquetFile(path)
    for batch in parquet_file.iter_batches(batch_size=batch_size, columns=columns):
        yield batch.to_pandas()


def load_temporal_base(parts: Sequence[SourcePart], batch_size: int) -> pd.DataFrame:
    columns = ["window_start", "entity", *ROLLING_METRICS]
    frames: List[pd.DataFrame] = []
    offset = 0
    for part in parts:
        for frame in iter_parquet_batches(part.path, columns=columns, batch_size=batch_size):
            frame = frame.copy()
            row_count = int(len(frame))
            frame["_global_order"] = np.arange(offset, offset + row_count, dtype=np.int64)
            frames.append(frame)
            offset += row_count
    if not frames:
        raise SystemExit("No rows found while loading temporal base columns")
    base = pd.concat(frames, ignore_index=True)
    base["entity"] = base["entity"].astype(str).astype("category")
    base["window_start"] = pd.to_numeric(base["window_start"], errors="coerce").fillna(0).astype(np.int64)
    for column in ROLLING_METRICS:
        base[column] = pd.to_numeric(base[column], errors="coerce").fillna(0.0).astype(np.float32)
    return base


def rolling_mean_by_entity(ordered: pd.DataFrame, metric: str, window: int) -> pd.Series:
    shifted = ordered.groupby("entity", sort=False, observed=True)[metric].shift(1)
    rolled = shifted.groupby(ordered["entity"], sort=False, observed=True).rolling(window, min_periods=1).mean()
    rolled.index = rolled.index.droplevel(0)
    return rolled.reindex(ordered.index).fillna(0.0).astype(np.float32)


def compute_temporal_features(base: pd.DataFrame) -> pd.DataFrame:
    ordered = base.sort_values(["entity", "window_start", "_global_order"], kind="mergesort").copy()
    features = pd.DataFrame(index=ordered.index)

    seconds_in_day = 86_400.0
    seconds = ordered["window_start"].to_numpy(dtype=np.float64, copy=False)
    hour_of_day = np.floor((np.mod(seconds, seconds_in_day)) / 3600.0)
    minute_of_day = np.floor((np.mod(seconds, seconds_in_day)) / 60.0)
    hour_angle = 2.0 * math.pi * hour_of_day / 24.0
    minute_angle = 2.0 * math.pi * minute_of_day / 1440.0
    features["hour_of_day_sin"] = np.sin(hour_angle).astype(np.float32)
    features["hour_of_day_cos"] = np.cos(hour_angle).astype(np.float32)
    features["minute_of_day_sin"] = np.sin(minute_angle).astype(np.float32)
    features["minute_of_day_cos"] = np.cos(minute_angle).astype(np.float32)
    features["is_off_hours"] = ((hour_of_day < 7) | (hour_of_day >= 19)).astype(np.float32)

    grouped = ordered.groupby("entity", sort=False, observed=True)
    features["entity_seen_window_count"] = grouped.cumcount().astype(np.float32)
    gap = grouped["window_start"].diff().fillna(0).clip(lower=0)
    features["entity_window_gap_seconds"] = gap.astype(np.float32)

    for metric in ROLLING_METRICS:
        current = ordered[metric].astype(np.float32)
        for window in ROLLING_WINDOWS:
            mean_column = f"entity_{metric}_roll{window}_mean"
            delta_column = f"entity_{metric}_roll{window}_delta"
            mean_values = rolling_mean_by_entity(ordered, metric, window)
            features[mean_column] = mean_values
            delta_values = current - mean_values
            delta_values[features["entity_seen_window_count"] <= 0] = 0.0
            features[delta_column] = delta_values.astype(np.float32)

    features["_global_order"] = ordered["_global_order"].to_numpy(dtype=np.int64, copy=True)
    features = features.sort_values("_global_order", kind="mergesort").reset_index(drop=True)
    ordered_columns = ["_global_order", *temporal_feature_columns()]
    return features.loc[:, ordered_columns]


def write_part(folder: Path, frame: pd.DataFrame, counters: Dict[str, int], key: str) -> None:
    if frame.empty:
        return
    folder.mkdir(parents=True, exist_ok=True)
    part = counters.get(key, 0)
    counters[key] = part + 1
    frame.to_parquet(folder / f"part-{part:05d}.parquet", index=False)


def output_frame(frame: pd.DataFrame, target_column: str) -> pd.DataFrame:
    out = frame.copy()
    out["target"] = out[target_column].astype(str).to_numpy(copy=True)
    return out


def update_label_stats(stats: LabelStats, labels: pd.Series) -> None:
    stats.update(labels)


def bool_series(values: pd.Series) -> pd.Series:
    if values.dtype == bool:
        return values.fillna(False)
    return values.astype(str).str.strip().str.lower().isin(["true", "1", "yes", "y"])


def write_label_map(path: Path, labels: Sequence[str], binary: bool) -> None:
    ordered = sorted(set(map(str, labels)))
    if binary and {"BENIGN", "ATTACK"}.issubset(set(ordered)):
        ordered = ["BENIGN", "ATTACK"]
    write_json(path, {label: index for index, label in enumerate(ordered)})


def materialize_enriched(source_root: Path, target_root: Path, parts: Sequence[SourcePart], features: pd.DataFrame, batch_size: int) -> Dict[str, Dict[str, LabelStats]]:
    clear_dir(target_root)
    stats = {
        "binary": {split: LabelStats() for split in SPLITS},
        "multiclass": {split: LabelStats() for split in SPLITS},
        "anomaly": {split: LabelStats() for split in SPLITS},
    }
    counters: Dict[str, int] = {}

    for part in parts:
        offset = part.start
        for frame in iter_parquet_batches(part.path, columns=None, batch_size=batch_size):
            row_count = int(len(frame))
            feature_slice = features.iloc[offset : offset + row_count].reset_index(drop=True)
            if int(feature_slice["_global_order"].iloc[0]) != offset:
                raise SystemExit(f"Temporal feature order mismatch at source offset {offset}")
            enriched = pd.concat([frame.reset_index(drop=True), feature_slice.drop(columns=["_global_order"])], axis=1)
            for column in temporal_feature_columns():
                enriched[column] = pd.to_numeric(enriched[column], errors="coerce").fillna(0.0).astype(np.float32)

            binary_frame = output_frame(enriched, "binary_target")
            write_part(target_root / "binary" / part.split, binary_frame, counters, f"binary_{part.split}")
            update_label_stats(stats["binary"][part.split], binary_frame["target"])

            multiclass_frame = output_frame(enriched, "multiclass_target")
            write_part(target_root / "multiclass" / part.split, multiclass_frame, counters, f"multiclass_{part.split}")
            update_label_stats(stats["multiclass"][part.split], multiclass_frame["target"])

            if part.split == "train":
                anomaly_source = enriched[(enriched["binary_target"].astype(str) == "BENIGN") & (~bool_series(enriched["redteam_near"]))]
            else:
                anomaly_source = enriched
            anomaly_frame = output_frame(anomaly_source, "binary_target")
            write_part(target_root / "anomaly" / ANOMALY_SPLIT_FOLDERS[part.split], anomaly_frame, counters, f"anomaly_{part.split}")
            update_label_stats(stats["anomaly"][part.split], anomaly_frame["target"])

            offset += row_count

    for pipeline, stats_by_split in stats.items():
        write_json(target_root / pipeline / "stats.json", {split: item.to_json() for split, item in stats_by_split.items()})
    binary_labels = set()
    multiclass_labels = set()
    for split in SPLITS:
        binary_labels.update(stats["binary"][split].label_counts.keys())
        multiclass_labels.update(stats["multiclass"][split].label_counts.keys())
    write_label_map(target_root / "binary" / "label_map.json", sorted(binary_labels), binary=True)
    write_label_map(target_root / "multiclass" / "label_map.json", sorted(multiclass_labels), binary=False)
    return stats


def write_metadata(source_root: Path, target_root: Path, args: argparse.Namespace, source_features: List[str], new_features: List[str]) -> None:
    for name in ["category_maps.json", "source_manifest.json", "redteam_policy.json", "split_policy.json"]:
        source_path = source_root / name
        if source_path.exists():
            shutil.copy2(source_path, target_root / name)

    source_profile = read_json(source_root / "dataset_profile.json")
    source_manifest = read_json(source_root / "source_manifest.json") if (source_root / "source_manifest.json").exists() else source_profile.get("source_manifest", {})
    redteam_policy = read_json(source_root / "redteam_policy.json") if (source_root / "redteam_policy.json").exists() else source_profile.get("redteam_policy", {})
    split_policy = read_json(source_root / "split_policy.json") if (source_root / "split_policy.json").exists() else source_profile.get("split_policy", {})
    feature_columns = [*source_features, *new_features]
    write_json(target_root / "feature_columns.json", feature_columns)

    source_config = source_profile.get("config", {}) if isinstance(source_profile, dict) else {}
    profile_config = dict(source_config)
    profile_config.update(
        {
            "feature_profile": "temporal_entity_history_v1",
            "source_datasets_base": args.source_datasets_base,
            "source_split_mode": args.split_mode,
            "source_feature_count": len(source_features),
            "temporal_feature_count": len(new_features),
        }
    )
    source_summary = source_profile.get("summary", {}) if isinstance(source_profile, dict) else {}
    summary = dict(source_summary)
    summary.update(
        {
            "feature_profile": "temporal_entity_history_v1",
            "source_feature_count": len(source_features),
            "temporal_feature_count": len(new_features),
            "feature_count": len(feature_columns),
            "temporal_feature_columns": new_features,
        }
    )
    fingerprint_source = {
        "config": profile_config,
        "source_manifest": source_manifest,
        "redteam_policy": redteam_policy,
        "split_policy": split_policy,
        "feature_columns": feature_columns,
    }
    config_fingerprint = hashlib.sha256(json.dumps(fingerprint_source, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    write_json(
        target_root / "dataset_profile.json",
        {
            "dataset": args.dataset,
            "profile_version": 3,
            "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sampling_profile": source_profile.get("sampling_profile", "redteam_centered"),
            "config": profile_config,
            "source_manifest": source_manifest,
            "redteam_policy": redteam_policy,
            "split_policy": split_policy,
            "summary": summary,
            "config_fingerprint": config_fingerprint,
        },
    )
    write_json(target_root / "prepare_dataset_summary.json", summary)


def main() -> None:
    args = parse_args()
    source_root = resolve_from_root(args.source_datasets_base) / args.split_mode / args.dataset
    target_root = resolve_from_root(args.target_datasets_base) / args.split_mode / args.dataset
    if not source_root.exists():
        raise FileNotFoundError(f"Missing source dataset root: {source_root}")
    source_features = read_json(source_root / "feature_columns.json")
    if not isinstance(source_features, list):
        raise ValueError(f"Invalid feature_columns.json: {source_root / 'feature_columns.json'}")
    new_features = temporal_feature_columns()
    overlap = sorted(set(source_features).intersection(new_features))
    if overlap:
        raise ValueError(f"Temporal feature names already exist in source dataset: {overlap[:10]}")

    parts = source_parts(source_root)
    print(f"Source root : {source_root}")
    print(f"Target root : {target_root}")
    print(f"Rows        : {sum(part.rows for part in parts):,}")
    print("Loading temporal base columns...", flush=True)
    temporal_base = load_temporal_base(parts, args.batch_size)
    print("Computing causal temporal features...", flush=True)
    temporal_features = compute_temporal_features(temporal_base)
    del temporal_base
    print("Writing enriched date dataset...", flush=True)
    materialize_enriched(source_root, target_root, parts, temporal_features, args.batch_size)
    write_metadata(source_root, target_root, args, source_features, new_features)
    print("Done")


if __name__ == "__main__":
    main()