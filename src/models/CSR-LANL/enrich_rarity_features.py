#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
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
RARITY_WINDOWS = (15, 60)
RARITY_METRICS = (
    "total_event_count",
    "auth_fail_count",
    "flow_unique_dst_computer_count",
    "flow_unique_dst_port_count",
    "dns_unique_dst_computer_count",
    "proc_unique_process_count",
    "active_source_count",
)
COMPOSITE_INPUT_COLUMNS = (
    "auth_event_count",
    "auth_fail_count",
    "auth_failure_ratio",
    "flow_event_count",
    "flow_unique_dst_computer_count",
    "flow_unique_dst_port_count",
    "auth_unique_dst_computer_count",
    "dns_unique_dst_computer_count",
    "proc_unique_process_count",
    "has_new_src_user",
    "has_new_dst_computer",
    "has_new_process",
)
BASE_RARITY_FEATURES = (
    "entity_age_days",
    "entity_window_density",
    "current_novelty_signal_count",
    "current_destination_breadth",
    "current_dst_port_pressure",
    "current_auth_failure_pressure",
    "current_process_breadth",
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


def rarity_input_columns() -> List[str]:
    columns = ["window_start", "entity"]
    for column in [*RARITY_METRICS, *COMPOSITE_INPUT_COLUMNS]:
        if column not in columns:
            columns.append(column)
    return columns


def numeric_input_columns() -> List[str]:
    return [column for column in rarity_input_columns() if column not in {"window_start", "entity"}]


def rarity_feature_columns() -> List[str]:
    columns = list(BASE_RARITY_FEATURES)
    for metric in RARITY_METRICS:
        columns.append(f"entity_{metric}_prior_mean")
        columns.append(f"entity_{metric}_prior_zscore")
        for window in RARITY_WINDOWS:
            columns.append(f"entity_{metric}_roll{window}_mean")
            columns.append(f"entity_{metric}_roll{window}_ratio")
    return columns


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Add causal rarity and multi-scale features to a prepared CSR-LANL dataset.")
    parser.add_argument("--source_datasets_base", default="src/models/CSR-LANL/datasets_redteam_temporal")
    parser.add_argument("--target_datasets_base", default="src/models/CSR-LANL/datasets_redteam_temporal_rarity")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--split_mode", default="date", choices=["date"])
    parser.add_argument("--batch_size", type=int, default=500_000)
    parser.add_argument("--max_rows_per_split", type=int, default=None, help="Optional smoke-test limit; do not use for final datasets.")
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


def source_parts(source_root: Path, max_rows_per_split: Optional[int]) -> List[SourcePart]:
    if max_rows_per_split is not None and max_rows_per_split <= 0:
        raise ValueError("max_rows_per_split must be positive when provided")
    parts: List[SourcePart] = []
    offset = 0
    for split in SPLITS:
        folder = source_root / SOURCE_SPLIT_FOLDERS[split]
        paths = sorted(path for path in folder.glob("*.parquet") if path.is_file())
        if not paths:
            raise FileNotFoundError(f"No binary parquet files under {folder}")
        remaining = max_rows_per_split
        for path in paths:
            physical_rows = int(pq.ParquetFile(path).metadata.num_rows)
            rows = physical_rows if remaining is None else min(physical_rows, remaining)
            if rows > 0:
                parts.append(SourcePart(split=split, path=path, rows=rows, start=offset, end=offset + rows))
                offset += rows
            if remaining is not None:
                remaining -= rows
                if remaining <= 0:
                    break
    return parts


def iter_part_batches(part: SourcePart, columns: Optional[Sequence[str]], batch_size: int) -> Iterable[pd.DataFrame]:
    parquet_file = pq.ParquetFile(part.path)
    available_columns = set(parquet_file.schema_arrow.names)
    selected_columns = None if columns is None else [column for column in columns if column in available_columns]
    missing_required = [column for column in ["window_start", "entity"] if columns is not None and column not in available_columns]
    if missing_required:
        raise ValueError(f"Missing required columns in {part.path}: {missing_required}")
    remaining = int(part.rows)
    for batch in parquet_file.iter_batches(batch_size=batch_size, columns=selected_columns):
        if remaining <= 0:
            break
        frame = batch.to_pandas()
        if len(frame) > remaining:
            frame = frame.head(remaining).copy()
        if columns is not None:
            for column in columns:
                if column not in frame.columns:
                    frame[column] = 0
            frame = frame.loc[:, list(columns)]
        remaining -= int(len(frame))
        yield frame


def load_rarity_base(parts: Sequence[SourcePart], batch_size: int) -> pd.DataFrame:
    columns = rarity_input_columns()
    frames: List[pd.DataFrame] = []
    offset = 0
    for part in parts:
        loaded_rows = 0
        for frame in iter_part_batches(part, columns=columns, batch_size=batch_size):
            frame = frame.copy()
            row_count = int(len(frame))
            frame["_global_order"] = np.arange(offset, offset + row_count, dtype=np.int64)
            frames.append(frame)
            offset += row_count
            loaded_rows += row_count
        print(f"Loaded {part.split}: {part.path.name} ({loaded_rows:,} rows)", flush=True)
    if not frames:
        raise SystemExit("No rows found while loading rarity base columns")
    base = pd.concat(frames, ignore_index=True)
    base["entity"] = base["entity"].astype(str).astype("category")
    base["window_start"] = pd.to_numeric(base["window_start"], errors="coerce").fillna(0).astype(np.int64)
    for column in numeric_input_columns():
        base[column] = pd.to_numeric(base[column], errors="coerce").fillna(0.0).astype(np.float32)
    return base


def rolling_mean_by_entity(ordered: pd.DataFrame, metric: str, window: int) -> pd.Series:
    shifted = ordered.groupby("entity", sort=False, observed=True)[metric].shift(1)
    rolled = shifted.groupby(ordered["entity"], sort=False, observed=True).rolling(window, min_periods=1).mean()
    rolled.index = rolled.index.droplevel(0)
    return rolled.reindex(ordered.index).fillna(0.0).astype(np.float32)


def prior_mean_zscore_by_entity(ordered: pd.DataFrame, metric: str, seen_count: pd.Series) -> tuple[pd.Series, pd.Series]:
    current = ordered[metric].astype(np.float64)
    grouped = ordered.groupby("entity", sort=False, observed=True)[metric]
    prior_sum = grouped.cumsum().astype(np.float64) - current
    prior_sq_sum = (ordered[metric].astype(np.float64) ** 2).groupby(ordered["entity"], sort=False, observed=True).cumsum() - (current ** 2)
    count = seen_count.astype(np.float64)
    prior_mean = np.divide(prior_sum, count, out=np.zeros(len(ordered), dtype=np.float64), where=count > 0)
    prior_var = np.divide(prior_sq_sum, count, out=np.zeros(len(ordered), dtype=np.float64), where=count > 1) - prior_mean**2
    prior_std = np.sqrt(np.maximum(prior_var, 0.0))
    zscore = np.divide(current - prior_mean, prior_std, out=np.zeros(len(ordered), dtype=np.float64), where=prior_std > 1e-6)
    return pd.Series(prior_mean, index=ordered.index).astype(np.float32), pd.Series(zscore, index=ordered.index).astype(np.float32)


def compute_rarity_features(base: pd.DataFrame) -> pd.DataFrame:
    ordered = base.sort_values(["entity", "window_start", "_global_order"], kind="mergesort").copy()
    features = pd.DataFrame(index=ordered.index)
    grouped = ordered.groupby("entity", sort=False, observed=True)
    seen_count = grouped.cumcount().astype(np.float32)
    first_window = grouped["window_start"].transform("first")
    age_days = ((ordered["window_start"] - first_window).clip(lower=0).astype(np.float32) / 86_400.0).astype(np.float32)
    features["entity_age_days"] = age_days
    features["entity_window_density"] = (seen_count / (age_days + 1.0)).astype(np.float32)

    novelty_columns = ["has_new_src_user", "has_new_dst_computer", "has_new_process"]
    features["current_novelty_signal_count"] = ordered[novelty_columns].sum(axis=1).astype(np.float32)
    features["current_destination_breadth"] = (
        ordered["flow_unique_dst_computer_count"] + ordered["auth_unique_dst_computer_count"] + ordered["dns_unique_dst_computer_count"]
    ).astype(np.float32)
    features["current_dst_port_pressure"] = (
        np.log1p(ordered["flow_unique_dst_port_count"].astype(np.float32)) * np.log1p(ordered["flow_event_count"].astype(np.float32))
    ).astype(np.float32)
    features["current_auth_failure_pressure"] = (
        ordered["auth_fail_count"].astype(np.float32)
        * (1.0 + ordered["auth_failure_ratio"].astype(np.float32))
        * np.log1p(ordered["auth_event_count"].astype(np.float32))
    ).astype(np.float32)
    features["current_process_breadth"] = (
        ordered["proc_unique_process_count"].astype(np.float32) * (1.0 + ordered["has_new_process"].astype(np.float32))
    ).astype(np.float32)

    for metric in RARITY_METRICS:
        current = ordered[metric].astype(np.float32)
        prior_mean, prior_zscore = prior_mean_zscore_by_entity(ordered, metric, seen_count)
        features[f"entity_{metric}_prior_mean"] = prior_mean
        features[f"entity_{metric}_prior_zscore"] = prior_zscore
        for window in RARITY_WINDOWS:
            mean_column = f"entity_{metric}_roll{window}_mean"
            ratio_column = f"entity_{metric}_roll{window}_ratio"
            mean_values = rolling_mean_by_entity(ordered, metric, window)
            ratio_values = (current / (mean_values + 1.0)).astype(np.float32)
            ratio_values[seen_count <= 0] = 0.0
            features[mean_column] = mean_values
            features[ratio_column] = ratio_values

    features.replace([np.inf, -np.inf], 0.0, inplace=True)
    features.fillna(0.0, inplace=True)
    for column in rarity_feature_columns():
        features[column] = pd.to_numeric(features[column], errors="coerce").fillna(0.0).astype(np.float32)
    features["_global_order"] = ordered["_global_order"].to_numpy(dtype=np.int64, copy=True)
    features = features.sort_values("_global_order", kind="mergesort").reset_index(drop=True)
    return features.loc[:, ["_global_order", *rarity_feature_columns()]]


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
        written_rows = 0
        for frame in iter_part_batches(part, columns=None, batch_size=batch_size):
            row_count = int(len(frame))
            feature_slice = features.iloc[offset : offset + row_count].reset_index(drop=True)
            if int(feature_slice["_global_order"].iloc[0]) != offset:
                raise SystemExit(f"Rarity feature order mismatch at source offset {offset}")
            enriched = pd.concat([frame.reset_index(drop=True), feature_slice.drop(columns=["_global_order"])], axis=1)
            for column in rarity_feature_columns():
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
            written_rows += row_count
        print(f"Wrote {part.split}: {part.path.name} ({written_rows:,} rows)", flush=True)

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
            "feature_profile": "temporal_rarity_multiscale_v1",
            "source_datasets_base": args.source_datasets_base,
            "source_split_mode": args.split_mode,
            "source_feature_count": len(source_features),
            "rarity_feature_count": len(new_features),
            "rarity_windows": list(RARITY_WINDOWS),
            "rarity_metrics": list(RARITY_METRICS),
            "max_rows_per_split": args.max_rows_per_split,
        }
    )
    source_summary = source_profile.get("summary", {}) if isinstance(source_profile, dict) else {}
    summary = dict(source_summary)
    summary.update(
        {
            "feature_profile": "temporal_rarity_multiscale_v1",
            "source_feature_count": len(source_features),
            "rarity_feature_count": len(new_features),
            "feature_count": len(feature_columns),
            "rarity_feature_columns": new_features,
            "max_rows_per_split": args.max_rows_per_split,
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
            "profile_version": 4,
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
    new_features = rarity_feature_columns()
    overlap = sorted(set(source_features).intersection(new_features))
    if overlap:
        raise ValueError(f"Rarity feature names already exist in source dataset: {overlap[:10]}")

    parts = source_parts(source_root, args.max_rows_per_split)
    print(f"Source root : {source_root}")
    print(f"Target root : {target_root}")
    print(f"Rows        : {sum(part.rows for part in parts):,}")
    if args.max_rows_per_split is not None:
        print(f"Smoke limit : {args.max_rows_per_split:,} rows per split")
    print("Loading rarity base columns...", flush=True)
    rarity_base = load_rarity_base(parts, args.batch_size)
    print("Computing causal rarity and multi-scale features...", flush=True)
    rarity_features = compute_rarity_features(rarity_base)
    del rarity_base
    print("Writing enriched rarity dataset...", flush=True)
    materialize_enriched(source_root, target_root, parts, rarity_features, args.batch_size)
    write_metadata(source_root, target_root, args, source_features, new_features)
    print("Done")


if __name__ == "__main__":
    main()