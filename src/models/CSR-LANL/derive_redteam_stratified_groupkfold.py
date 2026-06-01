#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

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


@dataclass
class SplitPolicyStats:
    rows: int = 0
    window_start_min: Optional[int] = None
    window_start_max: Optional[int] = None
    binary_counts: Dict[str, int] = field(default_factory=dict)
    multiclass_counts: Dict[str, int] = field(default_factory=dict)
    redteam_exact_windows: int = 0
    entities: Set[str] = field(default_factory=set)
    redteam_entities: Set[str] = field(default_factory=set)
    redteam_days: Set[int] = field(default_factory=set)

    def update(self, frame: pd.DataFrame) -> None:
        if frame.empty:
            return
        self.rows += int(len(frame))
        window_start = pd.to_numeric(frame["window_start"], errors="coerce").dropna()
        if not window_start.empty:
            current_min = int(window_start.min())
            current_max = int(window_start.max())
            self.window_start_min = current_min if self.window_start_min is None else min(self.window_start_min, current_min)
            self.window_start_max = current_max if self.window_start_max is None else max(self.window_start_max, current_max)
        for label, count in frame["binary_target"].astype(str).value_counts(dropna=False).items():
            self.binary_counts[str(label)] = self.binary_counts.get(str(label), 0) + int(count)
        for label, count in frame["multiclass_target"].astype(str).value_counts(dropna=False).items():
            self.multiclass_counts[str(label)] = self.multiclass_counts.get(str(label), 0) + int(count)
        entities = frame["entity"].dropna().astype(str).str.strip()
        self.entities.update(entities[entities != ""].tolist())
        redteam_mask = frame["redteam_exact"].astype(bool)
        self.redteam_exact_windows += int(redteam_mask.sum())
        if redteam_mask.any():
            redteam_entities = frame.loc[redteam_mask, "entity"].dropna().astype(str).str.strip()
            self.redteam_entities.update(redteam_entities[redteam_entities != ""].tolist())
            redteam_starts = pd.to_numeric(frame.loc[redteam_mask, "window_start"], errors="coerce").dropna().astype(int)
            self.redteam_days.update((redteam_starts // 86_400).astype(int).tolist())

    def to_json(self) -> Dict[str, Any]:
        return {
            "rows": int(self.rows),
            "window_start_min": self.window_start_min,
            "window_start_max": self.window_start_max,
            "binary_counts": dict(sorted(self.binary_counts.items(), key=lambda item: item[1], reverse=True)),
            "multiclass_counts": dict(sorted(self.multiclass_counts.items(), key=lambda item: item[1], reverse=True)),
            "redteam_exact_windows": int(self.redteam_exact_windows),
            "redteam_entities": int(len(self.redteam_entities)),
            "redteam_days": int(len(self.redteam_days)),
            "entities": int(len(self.entities)),
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Derive CSR-LANL redteam_stratified_groupkfold from an existing materialized split.")
    parser.add_argument("--datasets_base", default="src/models/CSR-LANL/datasets_redteam")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--source_split_mode", default="date")
    parser.add_argument("--target_split_mode", default="redteam_stratified_groupkfold")
    parser.add_argument("--n_folds", type=int, default=5)
    parser.add_argument("--fold", type=int, default=0)
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--batch_size", type=int, default=200_000)
    return parser.parse_args()


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def parquet_paths(source_root: Path) -> List[Path]:
    paths: List[Path] = []
    for split in SPLITS:
        folder = source_root / SOURCE_SPLIT_FOLDERS[split]
        paths.extend(sorted(path for path in folder.glob("*.parquet") if path.is_file()))
    if not paths:
        raise FileNotFoundError(f"No source binary parquet files under {source_root}")
    return paths


def iter_parquet_batches(paths: Sequence[Path], columns: Optional[Sequence[str]], batch_size: int) -> Iterable[pd.DataFrame]:
    for path in paths:
        parquet_file = pq.ParquetFile(path)
        for batch in parquet_file.iter_batches(batch_size=batch_size, columns=columns):
            yield batch.to_pandas()


def entity_summary(paths: Sequence[Path], batch_size: int) -> pd.DataFrame:
    rows_by_entity: Dict[str, int] = defaultdict(int)
    attacks_by_entity: Dict[str, int] = defaultdict(int)
    for frame in iter_parquet_batches(paths, columns=["entity", "binary_target"], batch_size=batch_size):
        frame["entity"] = frame["entity"].astype(str)
        frame["is_attack"] = frame["binary_target"].astype(str).str.upper() != "BENIGN"
        grouped = frame.groupby("entity", sort=False).agg(rows=("entity", "size"), attack_windows=("is_attack", "sum"))
        for entity, row in grouped.iterrows():
            entity_text = str(entity)
            rows_by_entity[entity_text] += int(row["rows"])
            attacks_by_entity[entity_text] += int(row["attack_windows"])
    return pd.DataFrame(
        {
            "entity": list(rows_by_entity.keys()),
            "rows": [rows_by_entity[entity] for entity in rows_by_entity],
            "attack_windows": [attacks_by_entity[entity] for entity in rows_by_entity],
        }
    )


def add_entity_to_fold(fold: Dict[str, Any], entity: str, rows: int, attack_windows: int) -> None:
    fold["entities"].add(str(entity))
    if int(attack_windows) > 0:
        fold["redteam_entities"] += 1
    fold["rows"] += int(rows)
    fold["attack_windows"] += int(attack_windows)


def assign_folds(summary: pd.DataFrame, n_folds: int, min_redteam_entities_per_fold: int = 5) -> List[Set[str]]:
    if n_folds < 3:
        raise SystemExit("redteam_stratified_groupkfold requires at least three folds")
    redteam_summary = summary[summary["attack_windows"] > 0].copy()
    if len(redteam_summary) < 3:
        raise SystemExit("Need at least three red-team entities to derive redteam_stratified_groupkfold")
    fold_count = min(int(n_folds), int(len(redteam_summary)), int(len(summary)))
    folds = [{"entities": set(), "rows": 0, "attack_windows": 0, "redteam_entities": 0} for _ in range(fold_count)]
    target_min_redteam_entities = min(int(min_redteam_entities_per_fold), max(1, int(len(redteam_summary) // fold_count)))

    redteam_summary = redteam_summary.sort_values(["attack_windows", "rows", "entity"], ascending=[False, False, True])
    redteam_rows = list(redteam_summary.itertuples(index=False))
    remaining_redteam_rows = []
    for index, row in enumerate(redteam_rows):
        if index < fold_count:
            add_entity_to_fold(folds[index], str(row.entity), int(row.rows), int(row.attack_windows))
        else:
            remaining_redteam_rows.append(row)

    remaining_redteam_rows.sort(key=lambda row: (int(row.attack_windows), int(row.rows), str(row.entity)))
    while remaining_redteam_rows and any(fold["redteam_entities"] < target_min_redteam_entities for fold in folds):
        target_fold = min(
            range(fold_count),
            key=lambda index: (folds[index]["redteam_entities"], -folds[index]["attack_windows"], folds[index]["rows"], index),
        )
        row = remaining_redteam_rows.pop(0)
        add_entity_to_fold(folds[target_fold], str(row.entity), int(row.rows), int(row.attack_windows))

    remaining_redteam_rows.sort(key=lambda row: (int(row.attack_windows), int(row.rows), str(row.entity)), reverse=True)
    for row in remaining_redteam_rows:
        target_fold = min(range(fold_count), key=lambda index: (folds[index]["attack_windows"], folds[index]["rows"], index))
        add_entity_to_fold(folds[target_fold], str(row.entity), int(row.rows), int(row.attack_windows))

    benign_summary = summary[summary["attack_windows"] == 0].sort_values(["rows", "entity"], ascending=[False, True])
    for row in benign_summary.itertuples(index=False):
        target_fold = min(range(fold_count), key=lambda index: (folds[index]["rows"], len(folds[index]["entities"]), index))
        add_entity_to_fold(folds[target_fold], str(row.entity), int(row.rows), 0)
    return [set(fold["entities"]) for fold in folds]


def split_for_entities(folds: Sequence[Set[str]], fold: int, all_entities: Set[str]) -> Dict[str, Set[str]]:
    mapped_fold = int(fold) % len(folds)
    test_entities = set(folds[mapped_fold])
    val_entities = set(folds[(mapped_fold + 1) % len(folds)])
    train_entities = set(all_entities) - test_entities - val_entities
    return {"train": train_entities, "val": val_entities, "test": test_entities}


def clear_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def output_frame(frame: pd.DataFrame, target_column: str) -> pd.DataFrame:
    out = frame.copy()
    out["target"] = out[target_column].astype(str).to_numpy(copy=True)
    return out


def write_part(folder: Path, split: str, frame: pd.DataFrame, counters: Dict[str, int]) -> None:
    if frame.empty:
        return
    folder.mkdir(parents=True, exist_ok=True)
    part = counters[split]
    counters[split] += 1
    frame.to_parquet(folder / f"part-{part:05d}.parquet", index=False)


def write_label_map(path: Path, labels: Sequence[str], binary: bool) -> None:
    ordered = sorted(set(map(str, labels)))
    if binary and {"BENIGN", "ATTACK"}.issubset(set(ordered)):
        ordered = ["BENIGN", "ATTACK"]
    write_json(path, {label: index for index, label in enumerate(ordered)})


def derive_fold(
    source_root: Path,
    target_root: Path,
    source_paths: Sequence[Path],
    split_entities: Dict[str, Set[str]],
    batch_size: int,
) -> Tuple[Dict[str, Dict[str, LabelStats]], Dict[str, SplitPolicyStats]]:
    clear_dir(target_root)
    pipeline_stats = {
        "binary": {split: LabelStats() for split in SPLITS},
        "multiclass": {split: LabelStats() for split in SPLITS},
        "anomaly": {split: LabelStats() for split in SPLITS},
    }
    split_policy_stats = {split: SplitPolicyStats() for split in SPLITS}
    part_counters = {"binary_train": 0, "binary_val": 0, "binary_test": 0, "multiclass_train": 0, "multiclass_val": 0, "multiclass_test": 0, "anomaly_train": 0, "anomaly_val": 0, "anomaly_test": 0}

    for frame in iter_parquet_batches(source_paths, columns=None, batch_size=batch_size):
        frame["entity"] = frame["entity"].astype(str)
        for split_name, entities in split_entities.items():
            split_frame = frame[frame["entity"].isin(entities)].copy()
            if split_frame.empty:
                continue

            split_policy_stats[split_name].update(split_frame)

            binary_frame = output_frame(split_frame, "binary_target")
            write_part(target_root / "binary" / split_name, f"binary_{split_name}", binary_frame, part_counters)
            pipeline_stats["binary"][split_name].update(binary_frame["target"])

            multiclass_frame = output_frame(split_frame, "multiclass_target")
            write_part(target_root / "multiclass" / split_name, f"multiclass_{split_name}", multiclass_frame, part_counters)
            pipeline_stats["multiclass"][split_name].update(multiclass_frame["target"])

            if split_name == "train":
                anomaly_source = split_frame[(split_frame["binary_target"].astype(str) == "BENIGN") & (~split_frame["redteam_near"].astype(bool))].copy()
            else:
                anomaly_source = split_frame
            anomaly_frame = output_frame(anomaly_source, "binary_target")
            anomaly_split_folder = ANOMALY_SPLIT_FOLDERS[split_name]
            write_part(target_root / "anomaly" / anomaly_split_folder, f"anomaly_{split_name}", anomaly_frame, part_counters)
            pipeline_stats["anomaly"][split_name].update(anomaly_frame["target"])

    if pipeline_stats["anomaly"]["train"].rows == 0:
        raise SystemExit("Derived anomaly train split has no eligible benign rows")
    for pipeline, stats_by_split in pipeline_stats.items():
        write_json(target_root / pipeline / "stats.json", {split: stats.to_json() for split, stats in stats_by_split.items()})

    binary_labels = set()
    multiclass_labels = set()
    for split in SPLITS:
        binary_labels.update(pipeline_stats["binary"][split].label_counts.keys())
        multiclass_labels.update(pipeline_stats["multiclass"][split].label_counts.keys())
    write_label_map(target_root / "binary" / "label_map.json", sorted(binary_labels), binary=True)
    write_label_map(target_root / "multiclass" / "label_map.json", sorted(multiclass_labels), binary=False)
    return pipeline_stats, split_policy_stats


def write_metadata(
    source_root: Path,
    target_root: Path,
    target_mode_root: Path,
    args: argparse.Namespace,
    fold: int,
    split_policy_stats: Dict[str, SplitPolicyStats],
    summary: pd.DataFrame,
    folds: Sequence[Set[str]],
) -> None:
    for name in ["feature_columns.json", "category_maps.json", "source_manifest.json", "redteam_policy.json"]:
        source_path = source_root / name
        if source_path.exists():
            shutil.copy2(source_path, target_root / name)
            if name == "feature_columns.json":
                shutil.copy2(source_path, target_mode_root / name)

    source_profile = read_json(source_root / "dataset_profile.json")
    source_manifest = read_json(source_root / "source_manifest.json") if (source_root / "source_manifest.json").exists() else source_profile.get("source_manifest", {})
    redteam_policy = read_json(source_root / "redteam_policy.json") if (source_root / "redteam_policy.json").exists() else source_profile.get("redteam_policy", {})
    feature_columns = read_json(source_root / "feature_columns.json")
    split_policy = {
        "split_mode": args.target_split_mode,
        "group_key": "entity",
        "source_split_mode": args.source_split_mode,
        "fold": int(fold),
        "n_folds": int(args.n_folds),
        "fold_entity_counts": [int(len(item)) for item in folds],
        "fold_redteam_windows": [int(summary[summary["entity"].isin(item)]["attack_windows"].sum()) for item in folds],
        "fold_redteam_entities": [int((summary[summary["entity"].isin(item)]["attack_windows"] > 0).sum()) for item in folds],
        "splits": {split: stats.to_json() for split, stats in split_policy_stats.items()},
    }
    source_config = source_profile.get("config", {}) if isinstance(source_profile, dict) else {}
    profile_config = dict(source_config)
    profile_config.update(
        {
            "split_mode": args.target_split_mode,
            "source_split_mode": args.source_split_mode,
            "n_folds": int(args.n_folds),
            "fold": int(fold),
            "derived_from": str(source_root),
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
    source_summary = source_profile.get("summary", {}) if isinstance(source_profile, dict) else {}
    derived_summary = dict(source_summary)
    derived_summary.update(
        {
            "split_mode": args.target_split_mode,
            "source_split_mode": args.source_split_mode,
            "fold": int(fold),
            "n_folds": int(args.n_folds),
            "derivation": "materialized_from_existing_prepared_date_binary_parquets",
        }
    )
    write_json(target_root / "split_policy.json", split_policy)
    write_json(target_root / "dataset_profile.json", {
        "dataset": args.dataset,
        "profile_version": 2,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sampling_profile": source_profile.get("sampling_profile", "redteam_centered"),
        "config": profile_config,
        "source_manifest": source_manifest,
        "redteam_policy": redteam_policy,
        "split_policy": split_policy,
        "summary": derived_summary,
        "config_fingerprint": config_fingerprint,
    })
    write_json(target_root / "prepare_dataset_summary.json", derived_summary)


def main() -> None:
    args = parse_args()
    datasets_base = resolve_from_root(args.datasets_base)
    source_root = datasets_base / args.source_split_mode / args.dataset
    target_mode_root = datasets_base / args.target_split_mode / args.dataset
    if not source_root.exists():
        raise FileNotFoundError(f"Missing source dataset root: {source_root}")
    source_paths = parquet_paths(source_root)
    print(f"Source root : {source_root}")
    print(f"Target mode : {target_mode_root}")
    print("Scanning entity summary from materialized parquet...")
    summary = entity_summary(source_paths, args.batch_size)
    folds = assign_folds(summary, args.n_folds)
    all_entities = set(summary["entity"].astype(str).tolist())
    folds_to_write = range(args.n_folds) if args.all_folds else [args.fold]
    target_mode_root.mkdir(parents=True, exist_ok=True)
    for fold in folds_to_write:
        target_root = target_mode_root / f"fold_{fold}"
        split_entities = split_for_entities(folds, int(fold), all_entities)
        print(f"Writing {args.target_split_mode} fold_{fold}: {target_root}")
        _, split_policy_stats = derive_fold(source_root, target_root, source_paths, split_entities, args.batch_size)
        write_metadata(source_root, target_root, target_mode_root, args, int(fold), split_policy_stats, summary, folds)
    print("Done")


if __name__ == "__main__":
    main()