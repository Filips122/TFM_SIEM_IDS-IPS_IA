#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List

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


DATASET_PREFIX = "UGR16_MARAPR"
TRAIN_SPLITS = ("train", "val", "test")
FEATURE_PROFILES = ("flow", "oracle", "hybrid")

SPLIT_BY_MONTH_WEEK = {
    ("March 2016", "March - Week #3"): "train",
    ("March 2016", "March - Week #4"): "train",
    ("March 2016", "March - Week #5"): "train",
    ("April 2016", "April - Week #2"): "train",
    ("April 2016", "April - Week #3"): "val",
    ("April 2016", "April - Week #4"): "test",
    ("April 2016", "April - Week #5"): "test",
}

FLOW_FEATURE_COLUMNS = [
    "duration",
    "src_port",
    "dst_port",
    "ttl",
    "packets",
    "bytes",
    "bytes_per_packet",
    "packets_per_second",
    "bytes_per_second",
    "flag_has_ack",
    "flag_has_psh",
    "flag_has_syn",
    "flag_has_fin",
    "flag_has_rst",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "proto_gre",
    "proto_esp",
    "proto_ipip",
    "proto_ipv6",
    "proto_other",
]


def normalize_profiles(values: List[str]) -> List[str]:
    profiles: List[str] = []
    for value in values:
        for part in str(value).split(","):
            candidate = part.strip().lower()
            if not candidate:
                continue
            if candidate == "all":
                profiles.extend(FEATURE_PROFILES)
                continue
            if candidate not in FEATURE_PROFILES:
                raise SystemExit(f"Invalid feature profile: {candidate}. Allowed: all, {', '.join(FEATURE_PROFILES)}")
            profiles.append(candidate)
    return list(dict.fromkeys(profiles))


def feature_columns_for_profile(profile: str) -> List[str]:
    all_columns = expected_feature_columns()
    if profile == "oracle":
        return all_columns
    if profile == "hybrid":
        return [column for column in all_columns if not column.startswith("timeline_")]
    if profile == "flow":
        available = set(all_columns)
        return [column for column in FLOW_FEATURE_COLUMNS if column in available]
    raise ValueError(f"Unsupported profile: {profile}")


def profile_description(profile: str) -> str:
    if profile == "oracle":
        return "Flow features plus timeline_* ground-truth attack context; useful only as enriched/oracle upper-bound baseline."
    if profile == "hybrid":
        return "Flow features plus operational context available from SIEM/IDS telemetry; excludes timeline_* ground-truth columns."
    if profile == "flow":
        return "Flow-only baseline without timeline_* and without temporal or port-role context features."
    raise ValueError(f"Unsupported profile: {profile}")


def profile_dataset_name(prefix: str, profile: str) -> str:
    return f"{prefix}_{profile.upper()}"


def select_march_april_archives(input_dir: Path) -> List[Path]:
    archives = []
    for archive_path in discover_main_archives(input_dir):
        month, week, _ = archive_context(archive_path, input_dir)
        if (month, week) in SPLIT_BY_MONTH_WEEK:
            archives.append(archive_path)
    archives.sort(key=lambda path: list(SPLIT_BY_MONTH_WEEK).index(archive_context(path, input_dir)[:2]))
    return archives


def build_assignments(archives: List[Path], input_dir: Path) -> Dict[Path, str]:
    assignments: Dict[Path, str] = {}
    for archive_path in archives:
        month, week, _ = archive_context(archive_path, input_dir)
        split_name = SPLIT_BY_MONTH_WEEK.get((month, week))
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


def clone_tree(source_dir: Path, target_dir: Path, copy_mode: str) -> Dict[str, int]:
    clear_generated_dir(target_dir)
    counts = {"hardlinked": 0, "copied": 0}
    for source_path in source_dir.rglob("*"):
        relative_path = source_path.relative_to(source_dir)
        target_path = target_dir / relative_path
        if source_path.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
            continue

        target_path.parent.mkdir(parents=True, exist_ok=True)
        if copy_mode == "hardlink" and source_path.suffix.lower() == ".parquet":
            try:
                os.link(source_path, target_path)
                counts["hardlinked"] += 1
                continue
            except OSError:
                pass
        shutil.copy2(source_path, target_path)
        counts["copied"] += 1
    return counts


def write_profile_metadata(dataset_dir: Path, profile: str, base_summary: Dict[str, Any], clone_counts: Dict[str, int] | None = None) -> None:
    feature_columns = feature_columns_for_profile(profile)
    timeline_columns = [column for column in feature_columns if column.startswith("timeline_")]
    write_feature_columns(dataset_dir, feature_columns)

    profile_payload = {
        "feature_profile": profile,
        "description": profile_description(profile),
        "feature_count": len(feature_columns),
        "feature_columns": feature_columns,
        "timeline_feature_columns": timeline_columns,
        "uses_oracle_timeline_context": bool(timeline_columns),
        "clone_counts": clone_counts or {"hardlinked": 0, "copied": 0},
    }
    write_json(dataset_dir / "feature_profile.json", profile_payload)

    summary = dict(base_summary)
    summary.update(
        {
            "dataset": dataset_dir.name,
            "feature_profile": profile,
            "feature_profile_description": profile_description(profile),
            "feature_count": len(feature_columns),
            "timeline_feature_columns": timeline_columns,
            "uses_oracle_timeline_context": bool(timeline_columns),
            "actual_size_bytes": folder_size_bytes(dataset_dir),
        }
    )
    summary["actual_size_gb"] = gb_from_bytes(int(summary["actual_size_bytes"]))
    write_json(dataset_dir / "prepare_march_april_dataset_summary.json", summary)


def build_source_dataset(
    output_dir: Path,
    input_dir: Path,
    archives: List[Path],
    assignments: Dict[Path, str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    clear_generated_dir(output_dir)
    write_subset_manifest(output_dir, "march_april", archives, repo_root())
    write_split_policy(output_dir, assignments)
    write_feature_columns(output_dir, feature_columns_for_profile("oracle"))

    print("== prepare_march_april_feature_datasets (UGR16 source) ==")
    print(f"Repo root      : {repo_root()}")
    print(f"Input dir      : {input_dir}")
    print(f"Output dir     : {output_dir}")
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
        print(f"[marapr {index}/{len(archives)}] start {archive_path.name} split={split_name}", flush=True)
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

    return {
        "source": "March and April 2016 main UGR16 archives only",
        "split_policy": {
            "train": ["March - Week #3", "March - Week #4", "March - Week #5", "April - Week #2"],
            "val": ["April - Week #3"],
            "test": ["April - Week #4", "April - Week #5"],
        },
        "sample_fraction": args.sample_fraction,
        "binary_balance": args.binary_balance,
        "include_multiclass": args.include_multiclass,
        "keep_binary_raw": args.keep_binary_raw,
        "metadata_mode": args.metadata_mode,
        "copy_mode": args.copy_mode,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in_dir", type=str, default=str(DEFAULT_IN_DIR))
    parser.add_argument("--out_dir", type=str, default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--dataset_prefix", type=str, default=DATASET_PREFIX)
    parser.add_argument("--profiles", nargs="+", default=["all"])
    parser.add_argument("--sample_fraction", type=float, default=0.05)
    parser.add_argument("--binary_balance", type=str, default="stratified_downsample", choices=["stratified_downsample", "none"])
    parser.add_argument("--chunksize", type=int, default=250_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--metadata_mode", type=str, default="minimal", choices=["minimal", "full"])
    parser.add_argument("--include_multiclass", action="store_true")
    parser.add_argument("--keep_binary_raw", action="store_true")
    parser.add_argument("--copy_mode", type=str, default="hardlink", choices=["hardlink", "copy"])
    parser.add_argument("--progress_every_chunks", type=int, default=20)
    args = parser.parse_args()

    profiles = normalize_profiles(args.profiles)
    if not profiles:
        raise SystemExit("At least one feature profile is required")
    if not (0.0 < args.sample_fraction <= 1.0):
        raise SystemExit("sample_fraction must be in (0, 1]")
    if args.progress_every_chunks <= 0:
        raise SystemExit("progress_every_chunks must be > 0")

    _ensure_pyarrow()

    input_dir = resolve_from_root(args.in_dir)
    output_base = resolve_from_root(args.out_dir)
    if not input_dir.exists() or not input_dir.is_dir():
        raise SystemExit(f"Input folder does not exist: {input_dir}")

    archives = select_march_april_archives(input_dir)
    expected_count = len(SPLIT_BY_MONTH_WEEK)
    if len(archives) != expected_count:
        names = [str(path) for path in archives]
        raise SystemExit(f"Expected {expected_count} March+April main archives, found {len(archives)}: {names}")

    assignments = build_assignments(archives, input_dir)
    missing_splits = sorted(set(TRAIN_SPLITS) - set(assignments.values()))
    if missing_splits:
        raise SystemExit(f"Missing required splits: {missing_splits}")

    oracle_dir = output_base / "date" / profile_dataset_name(args.dataset_prefix, "oracle")
    base_summary = build_source_dataset(oracle_dir, input_dir, archives, assignments, args)
    write_profile_metadata(oracle_dir, "oracle", base_summary)

    for profile in profiles:
        if profile == "oracle":
            continue
        profile_dir = output_base / "date" / profile_dataset_name(args.dataset_prefix, profile)
        clone_counts = clone_tree(oracle_dir, profile_dir, args.copy_mode)
        write_profile_metadata(profile_dir, profile, base_summary, clone_counts)

    print("\nPrepared feature-profile datasets:")
    for profile in profiles:
        dataset_name = profile_dataset_name(args.dataset_prefix, profile)
        dataset_dir = output_base / "date" / dataset_name
        print(f"- {dataset_name}: {dataset_dir}")


if __name__ == "__main__":
    main()