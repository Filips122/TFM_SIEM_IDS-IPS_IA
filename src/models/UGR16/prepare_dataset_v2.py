#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd

from prepare_dataset import (
    DEFAULT_IN_DIR,
    DEFAULT_OUT_DIR,
    Stats,
    _ensure_pyarrow,
    anomaly_split_name,
    build_date_assignments,
    count_labels,
    discover_main_archives,
    expected_feature_columns,
    list_parquets,
    materialize_binary_pipeline,
    process_archive_fixed_split,
    repo_root,
    resolve_from_root,
    safe_mkdir,
    select_archives,
    update_stats,
    write_feature_columns,
    write_stats,
    write_subset_manifest,
    write_supervised_label_maps,
)

DEFAULT_RESUME_FROM_ARCHIVE = "may_week2"
DATASET_NAME = "UGR16"
PIPELINES = ("binary_raw", "binary", "multiclass", "anomaly")
SPLITS = ("train", "val", "test")


def normalize_archive_marker(value: str) -> str:
    marker = str(value).strip().lower()
    if marker.endswith(".tar.gz"):
        marker = marker[: -len(".tar.gz")]
    if marker.endswith("_csv"):
        marker = marker[: -len("_csv")]
    return marker


def split_archives_for_resume(archives: List[Path], resume_from: str) -> Tuple[List[Path], List[Path]]:
    normalized_resume = normalize_archive_marker(resume_from)
    for index, archive in enumerate(archives):
        if normalize_archive_marker(archive.name) == normalized_resume:
            return archives[:index], archives[index:]
    raise SystemExit(f"Resume archive not found in selected subset: {resume_from}")


def missing_previous_raw_outputs(out_dir: Path, assignments: Dict[Path, str], previous_archives: List[Path]) -> List[str]:
    missing: List[str] = []
    for archive in previous_archives:
        split_name = assignments.get(archive)
        if split_name is None:
            continue
        archive_stem = archive.name.replace(".tar.gz", "")
        raw_dir = out_dir / "binary_raw" / split_name
        if not any(raw_dir.glob(f"{archive_stem}__part*.parquet")):
            missing.append(archive.name)
    return missing


def clear_resume_outputs(out_dir: Path, assignments: Dict[Path, str], resume_archives: List[Path]) -> int:
    removed = 0
    for archive in resume_archives:
        split_name = assignments.get(archive)
        if split_name is None:
            continue
        archive_stem = archive.name.replace(".tar.gz", "")
        folders = [
            out_dir / "binary_raw" / split_name,
            out_dir / "multiclass" / split_name,
            out_dir / "anomaly" / anomaly_split_name(split_name),
        ]
        for folder in folders:
            for parquet_path in folder.glob(f"{archive_stem}__part*.parquet"):
                parquet_path.unlink(missing_ok=True)
                removed += 1
    return removed


def split_folder(base_dir: Path, pipeline: str, split_name: str) -> Path:
    if pipeline == "anomaly":
        return base_dir / "anomaly" / anomaly_split_name(split_name)
    return base_dir / pipeline / split_name


def collect_stats_from_disk(base_dir: Path) -> Dict[str, Dict[str, Stats]]:
    stats: Dict[str, Dict[str, Stats]] = {
        "binary_raw": {"train": Stats(), "val": Stats(), "test": Stats()},
        "binary": {"train": Stats(), "val": Stats(), "test": Stats()},
        "multiclass": {"train": Stats(), "val": Stats(), "test": Stats()},
        "anomaly": {"train": Stats(), "val": Stats(), "test": Stats()},
    }

    for pipeline_name in PIPELINES:
        binary_view = pipeline_name != "multiclass"
        for split_name in SPLITS:
            for parquet_path in list_parquets(split_folder(base_dir, pipeline_name, split_name)):
                target_df = pd.read_parquet(parquet_path, columns=["target"])
                counts = count_labels(target_df["target"].to_numpy())
                update_stats(stats[pipeline_name][split_name], counts, binary_view=binary_view)
    return stats


def write_split_policy(out_dir: Path, assignments: Dict[Path, str]) -> None:
    payload = {
        str(path.resolve().relative_to(repo_root().resolve())): split
        for path, split in assignments.items()
    }
    (out_dir / "split_policy.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_dir", type=str, default=str(DEFAULT_IN_DIR))
    ap.add_argument("--out_dir", type=str, default=str(DEFAULT_OUT_DIR))
    ap.add_argument("--split_mode", type=str, default="date", choices=["date"])
    ap.add_argument("--subset", type=str, default="thesis_v1", choices=["thesis_v1", "all_main"])
    ap.add_argument("--binary_balance", type=str, default="stratified_downsample", choices=["stratified_downsample", "none"])
    ap.add_argument("--chunksize", type=int, default=250_000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--resume_from_archive", type=str, default=DEFAULT_RESUME_FROM_ARCHIVE)
    args = ap.parse_args()

    _ensure_pyarrow()

    in_dir = resolve_from_root(args.in_dir)
    out_base = resolve_from_root(args.out_dir)
    out_mode = out_base / args.split_mode / DATASET_NAME
    safe_mkdir(out_mode)

    if not in_dir.exists() or not in_dir.is_dir():
        raise SystemExit(f"Input folder does not exist: {in_dir}")

    archives_all = discover_main_archives(in_dir)
    archives = select_archives(archives_all, in_dir, args.subset)
    if not archives:
        raise SystemExit(f"No UGR16 archives selected in: {in_dir}")

    assignments = build_date_assignments(archives, in_dir)
    previous_archives, resume_archives = split_archives_for_resume(archives, args.resume_from_archive)
    missing_previous = missing_previous_raw_outputs(out_mode, assignments, previous_archives)
    if missing_previous:
        raise SystemExit(
            "prepare_dataset_v2.py expects previous date outputs to already exist before the resume point. "
            f"Missing binary_raw parquet files for: {missing_previous}"
        )

    removed_files = clear_resume_outputs(out_mode, assignments, resume_archives)

    write_subset_manifest(out_mode, args.subset, archives, repo_root())
    write_feature_columns(out_mode, expected_feature_columns())
    write_split_policy(out_mode, assignments)

    print("== prepare_dataset_v2 (UGR16 date resume) ==")
    print(f"Repo root       : {repo_root()}")
    print(f"Input dir       : {in_dir}")
    print(f"Split mode      : {args.split_mode}")
    print(f"Subset          : {args.subset}")
    print(f"Binary bal      : {args.binary_balance}")
    print(f"Out dir         : {out_mode}")
    print(f"Chunksize       : {args.chunksize}")
    print(f"Resume from     : {args.resume_from_archive}")
    print(f"Cleared files   : {removed_files}")
    print(f"Existing archives: {[p.name for p in previous_archives]}")
    print(f"Resume archives : {[p.name for p in resume_archives]}")

    for archive in resume_archives:
        split_name = assignments.get(archive)
        if split_name is None:
            continue
        process_archive_fixed_split(archive, split_name, out_mode, args.chunksize, in_dir)

    materialize_binary_pipeline(out_mode, args.binary_balance, args.seed)
    stats = collect_stats_from_disk(out_mode)
    write_supervised_label_maps(out_mode, stats)
    write_stats(out_mode, stats)


if __name__ == "__main__":
    main()