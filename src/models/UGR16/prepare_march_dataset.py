#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Dict, List

from prepare_dataset import (  # type: ignore
    DEFAULT_IN_DIR,
    DEFAULT_OUT_DIR,
    Stats,
    _ensure_pyarrow,
    archive_context,
    clear_generated_dir,
    discover_main_archives,
    expected_feature_columns,
    materialize_binary_pipeline,
    repo_root,
    resolve_from_root,
    update_stats,
    write_feature_columns,
    write_stats,
    write_subset_manifest,
    write_supervised_label_maps,
)
from prepare_dataset_v3.build import (  # type: ignore
    folder_size_bytes,
    gb_from_bytes,
    process_archive_sampled,
    write_json,
)


DATASET_NAME = "UGR16_MARCH"
TRAIN_SPLITS = ("train", "val", "test")
MARCH_SPLIT_BY_WEEK = {
    "March - Week #3": "train",
    "March - Week #4": "val",
    "March - Week #5": "test",
}


def select_march_archives(input_dir: Path) -> List[Path]:
    archives = []
    for archive_path in discover_main_archives(input_dir):
        month, week, _ = archive_context(archive_path, input_dir)
        if month == "March 2016" and week in MARCH_SPLIT_BY_WEEK:
            archives.append(archive_path)
    archives.sort(key=lambda path: archive_context(path, input_dir)[1])
    return archives


def build_march_assignments(archives: List[Path], input_dir: Path) -> Dict[Path, str]:
    assignments: Dict[Path, str] = {}
    for archive_path in archives:
        _, week, _ = archive_context(archive_path, input_dir)
        split_name = MARCH_SPLIT_BY_WEEK.get(week)
        if split_name is not None:
            assignments[archive_path] = split_name
    return assignments


def new_stats(include_multiclass: bool) -> Dict[str, Dict[str, Stats]]:
    stats: Dict[str, Dict[str, Stats]] = {
        "binary_raw": {split_name: Stats() for split_name in TRAIN_SPLITS},
        "binary": {split_name: Stats() for split_name in TRAIN_SPLITS},
        "anomaly": {split_name: Stats() for split_name in TRAIN_SPLITS},
    }
    if include_multiclass:
        stats["multiclass"] = {split_name: Stats() for split_name in TRAIN_SPLITS}
    return stats


def write_split_policy(out_dir: Path, assignments: Dict[Path, str]) -> None:
    payload = {
        str(archive_path.resolve().relative_to(repo_root().resolve())): split_name
        for archive_path, split_name in assignments.items()
    }
    write_json(out_dir / "split_policy.json", payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in_dir", type=str, default=str(DEFAULT_IN_DIR))
    parser.add_argument("--out_dir", type=str, default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--dataset", type=str, default=DATASET_NAME)
    parser.add_argument("--sample_fraction", type=float, default=0.02)
    parser.add_argument("--binary_balance", type=str, default="stratified_downsample", choices=["stratified_downsample", "none"])
    parser.add_argument("--chunksize", type=int, default=250_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--metadata_mode", type=str, default="minimal", choices=["minimal", "full"])
    parser.add_argument("--include_multiclass", action="store_true")
    parser.add_argument("--keep_binary_raw", action="store_true")
    parser.add_argument("--progress_every_chunks", type=int, default=20)
    args = parser.parse_args()

    if not (0.0 < args.sample_fraction <= 1.0):
        raise SystemExit("sample_fraction must be in (0, 1]")
    if args.progress_every_chunks <= 0:
        raise SystemExit("progress_every_chunks must be > 0")

    _ensure_pyarrow()

    input_dir = resolve_from_root(args.in_dir)
    output_base = resolve_from_root(args.out_dir)
    output_dir = output_base / "date" / args.dataset

    if not input_dir.exists() or not input_dir.is_dir():
        raise SystemExit(f"Input folder does not exist: {input_dir}")

    archives = select_march_archives(input_dir)
    if len(archives) != 3:
        names = [str(path) for path in archives]
        raise SystemExit(f"Expected exactly three March main archives, found {len(archives)}: {names}")

    assignments = build_march_assignments(archives, input_dir)
    missing_splits = sorted(set(TRAIN_SPLITS) - set(assignments.values()))
    if missing_splits:
        raise SystemExit(f"Missing required March splits: {missing_splits}")

    clear_generated_dir(output_dir)
    write_subset_manifest(output_dir, "march_only", archives, repo_root())
    write_feature_columns(output_dir, expected_feature_columns())
    write_split_policy(output_dir, assignments)

    print("== prepare_march_dataset (UGR16) ==")
    print(f"Repo root      : {repo_root()}")
    print(f"Input dir      : {input_dir}")
    print(f"Output dir     : {output_dir}")
    print(f"Dataset        : {args.dataset}")
    print(f"Sample fraction: {args.sample_fraction}")
    print(f"Binary balance : {args.binary_balance}")
    print(f"Metadata mode  : {args.metadata_mode}")
    print(f"Multiclass     : {args.include_multiclass}")
    print(f"Keep binary_raw: {args.keep_binary_raw}")
    print(f"Archives       : {[path.name for path in archives]}")
    print(flush=True)

    stats = new_stats(args.include_multiclass)
    for index, archive_path in enumerate(archives, start=1):
        split_name = assignments[archive_path]
        print(f"[march {index}/{len(archives)}] start {archive_path.name} split={split_name}", flush=True)
        counts = process_archive_sampled(
            archive_path=archive_path,
            split_name=split_name,
            root=input_dir,
            out_dir=output_dir,
            chunksize=args.chunksize,
            metadata_mode=args.metadata_mode,
            include_multiclass=args.include_multiclass,
            sample_fraction=float(args.sample_fraction),
            seed=args.seed,
            progress_every_chunks=args.progress_every_chunks,
        )
        update_stats(stats["binary_raw"][split_name], counts["binary_raw"], binary_view=True)
        update_stats(stats["anomaly"][split_name], counts["anomaly"], binary_view=True)
        if args.include_multiclass:
            update_stats(stats["multiclass"][split_name], counts["multiclass"], binary_view=False)

    binary_counts = materialize_binary_pipeline(output_dir, args.binary_balance, args.seed)
    for split_name, counts in binary_counts.items():
        update_stats(stats["binary"][split_name], counts, binary_view=True)

    if not args.keep_binary_raw:
        shutil.rmtree(output_dir / "binary_raw", ignore_errors=True)
        stats.pop("binary_raw", None)

    write_supervised_label_maps(output_dir, stats)
    write_stats(output_dir, stats)

    summary = {
        "dataset": args.dataset,
        "source": "March 2016 main UGR16 archives only",
        "split_policy": {
            "train": "March - Week #3",
            "val": "March - Week #4",
            "test": "March - Week #5",
        },
        "sample_fraction": args.sample_fraction,
        "binary_balance": args.binary_balance,
        "include_multiclass": args.include_multiclass,
        "keep_binary_raw": args.keep_binary_raw,
        "metadata_mode": args.metadata_mode,
        "actual_size_bytes": folder_size_bytes(output_dir),
    }
    summary["actual_size_gb"] = gb_from_bytes(int(summary["actual_size_bytes"]))
    write_json(output_dir / "prepare_march_dataset_summary.json", summary)

    print(f"Actual output size: {summary['actual_size_gb']} GiB")
    print(f"Prepared dataset: {output_dir}")


if __name__ == "__main__":
    main()