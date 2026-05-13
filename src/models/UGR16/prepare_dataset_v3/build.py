from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd


CURRENT_DIR = Path(__file__).resolve().parent
UGR16_DIR = CURRENT_DIR.parent
if str(UGR16_DIR) not in sys.path:
    sys.path.insert(0, str(UGR16_DIR))

from prepare_dataset import (  # type: ignore
    DEFAULT_IN_DIR,
    DEFAULT_OUT_DIR,
    RAW_COLUMNS,
    Stats,
    _ensure_pyarrow,
    _table_no_meta,
    archive_context,
    archive_members,
    build_date_assignments,
    clear_generated_dir,
    count_labels,
    discover_main_archives,
    expected_feature_columns,
    load_attack_timeline,
    materialize_binary_pipeline,
    matching_attack_ts,
    normalize_label,
    pq,
    preprocess_chunk,
    repo_root,
    resolve_from_root,
    select_archives,
    update_stats,
    write_feature_columns,
    write_parquet,
    write_stats,
    write_subset_manifest,
    write_supervised_label_maps,
)


DEFAULT_TARGET_SIZE_GB = 80.0
DEFAULT_MAX_SIZE_GB = 95.0
DEFAULT_SAFETY_MARGIN = 0.92
DEFAULT_PLAN_SAMPLE_CHUNKS = 2
DEFAULT_ESTIMATE_SAMPLE_ROWS = 25_000
DEFAULT_PROGRESS_EVERY_CHUNKS = 20

TRAIN_SPLITS = ("train", "val", "test")

MINIMAL_META_COLUMNS = [
    "event_ts",
    "label_raw",
    "timeline_primary_family_meta",
    "timeline_hour_attack_active_meta",
    "archive_name_meta",
    "split_name_meta",
    "week_key_meta",
]
FULL_META_EXTRA_COLUMNS = [
    "minute_window_meta",
    "hour_window_meta",
    "src_ip_meta",
    "dst_ip_meta",
    "protocol_raw_meta",
    "flags_raw_meta",
    "timeline_attack_active_meta",
    "timeline_hour_primary_family_meta",
]

UINT16_FEATURES = {
    "src_port",
    "dst_port",
    "ttl",
}
UINT8_FEATURES = {
    "timeline_minute_is_attack",
    "timeline_hour_is_attack",
    "timeline_hour_attack_minutes",
    "hour",
    "minute",
    "day_of_week",
    "month_num",
    "iso_week",
    "src_port_is_system",
    "dst_port_is_system",
    "src_port_is_ephemeral",
    "dst_port_is_ephemeral",
    "src_port_is_zero",
    "dst_port_is_zero",
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
}
FLOAT32_FEATURES = set(expected_feature_columns()) - UINT16_FEATURES - UINT8_FEATURES


@dataclass
class SplitScanStats:
    total_rows: int = 0
    benign_rows: int = 0
    attack_rows: int = 0


@dataclass
class ArchiveScanSummary:
    archive: str
    split: str
    total_rows: int
    benign_rows: int
    attack_rows: int


@dataclass
class SampleFrames:
    binary: List[pd.DataFrame] = field(default_factory=list)
    anomaly: List[pd.DataFrame] = field(default_factory=list)
    multiclass: List[pd.DataFrame] = field(default_factory=list)


def bytes_from_gb(value: float) -> int:
    return int(float(value) * (1024**3))


def gb_from_bytes(value: int) -> float:
    return round(int(value) / (1024**3), 2)


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def acquire_build_lock(lock_path: Path, dataset_name: str) -> None:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "dataset_name": dataset_name,
        "pid": os.getpid(),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise SystemExit(
            "prepare_dataset_v3 is already running for this dataset or a previous run left a stale lock. "
            f"Lock file: {lock_path}"
        ) from exc

    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def release_build_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink(missing_ok=True)
    except Exception:
        pass


def stable_seed(base_seed: int, *parts: object) -> int:
    joined = "|".join(str(part) for part in parts)
    digest = hashlib.blake2b(joined.encode("utf-8"), digest_size=8).digest()
    return int(base_seed + int.from_bytes(digest, byteorder="little", signed=False)) & 0x7FFFFFFF


def string_category(series: pd.Series) -> pd.Series:
    return series.where(series.notna(), "NA").astype(str).astype("category")


def selected_meta_columns(metadata_mode: str) -> List[str]:
    if metadata_mode == "full":
        return MINIMAL_META_COLUMNS + FULL_META_EXTRA_COLUMNS
    return list(MINIMAL_META_COLUMNS)


def compact_base_frame(base: pd.DataFrame, metadata_mode: str) -> pd.DataFrame:
    keep = [column for column in expected_feature_columns() + selected_meta_columns(metadata_mode) if column in base.columns]
    compact = base.loc[:, keep].copy()

    for column in compact.columns:
        if column in UINT16_FEATURES:
            values = pd.to_numeric(compact[column], errors="coerce").fillna(0).clip(lower=0, upper=65535)
            compact[column] = values.astype(np.uint16)
        elif column in UINT8_FEATURES:
            values = pd.to_numeric(compact[column], errors="coerce").fillna(0).clip(lower=0, upper=255)
            compact[column] = values.astype(np.uint8)
        elif column in FLOAT32_FEATURES:
            compact[column] = pd.to_numeric(compact[column], errors="coerce").fillna(0.0).astype(np.float32)
        elif column == "event_ts":
            compact[column] = pd.to_datetime(compact[column], errors="coerce")
        elif column in {"minute_window_meta", "hour_window_meta"}:
            compact[column] = pd.to_datetime(compact[column], errors="coerce")
        else:
            compact[column] = string_category(compact[column])

    return compact


def attach_target(base: pd.DataFrame, target: np.ndarray) -> pd.DataFrame:
    out = base.copy()
    out["target"] = pd.Categorical(np.asarray(target, dtype=object).astype(str))
    return out


def limit_rows(df: pd.DataFrame, max_rows: int) -> pd.DataFrame:
    if len(df) <= max_rows:
        return df.copy()
    return df.iloc[:max_rows].copy()


def concat_limited(frames: List[pd.DataFrame], max_rows: int) -> pd.DataFrame:
    if not frames:
        return pd.DataFrame()

    picked: List[pd.DataFrame] = []
    remaining = max_rows
    for frame in frames:
        if remaining <= 0:
            break
        take = frame if len(frame) <= remaining else frame.iloc[:remaining]
        picked.append(take.copy())
        remaining -= len(take)
    if not picked:
        return pd.DataFrame()
    return pd.concat(picked, ignore_index=True)


def estimate_parquet_bytes_per_row(df: pd.DataFrame) -> float:
    if df.empty:
        return 0.0
    if pq is None:
        raise SystemExit("Missing pyarrow parquet engine.")

    buffer = io.BytesIO()
    pq.write_table(_table_no_meta(df), buffer)
    return float(buffer.tell()) / float(len(df))


def count_clean_rows_and_labels(chunk: pd.DataFrame) -> tuple[int, int, int]:
    if chunk.empty:
        return 0, 0, 0

    work = chunk.iloc[:, :13].copy()
    work.columns = RAW_COLUMNS

    event_ts = pd.to_datetime(work["col_1"], errors="coerce")
    valid_mask = event_ts.notna()
    clean_rows = int(valid_mask.sum())
    if clean_rows == 0:
        return 0, 0, 0

    labels = work.loc[valid_mask, "col_13"].map(normalize_label)
    attack_rows = int((labels != "background").sum())
    benign_rows = int(clean_rows - attack_rows)
    return clean_rows, benign_rows, attack_rows


def list_output_files(folder: Path) -> List[Path]:
    if not folder.exists():
        return []
    return sorted([path for path in folder.rglob("*") if path.is_file()])


def folder_size_bytes(folder: Path) -> int:
    return int(sum(path.stat().st_size for path in list_output_files(folder)))


def write_split_policy(out_dir: Path, assignments: Dict[Path, str]) -> None:
    payload = {
        str(path.resolve().relative_to(repo_root().resolve())): split_name
        for path, split_name in assignments.items()
        if split_name in TRAIN_SPLITS
    }
    write_json(out_dir / "split_policy.json", payload)


def sample_mask(length: int, sample_fraction: float, seed: int, archive_stem: str, part_idx: int) -> np.ndarray:
    if sample_fraction >= 1.0:
        return np.ones(length, dtype=bool)
    rng = np.random.default_rng(stable_seed(seed, archive_stem, part_idx, length, sample_fraction))
    return rng.random(length) < sample_fraction


def collect_plan_samples(
    samples: SampleFrames,
    base: pd.DataFrame,
    binary_target: np.ndarray,
    multiclass_target: np.ndarray,
    split_name: str,
    metadata_mode: str,
    include_multiclass: bool,
    estimate_sample_rows: int,
) -> None:
    compact = compact_base_frame(limit_rows(base, estimate_sample_rows), metadata_mode)
    if compact.empty:
        return

    n_rows = len(compact)
    binary_df = attach_target(compact, binary_target[:n_rows])
    samples.binary.append(binary_df)

    anomaly_df = binary_df.copy()
    if split_name == "train":
        anomaly_df = anomaly_df.loc[anomaly_df["target"] == "BENIGN"].copy()
    if not anomaly_df.empty:
        samples.anomaly.append(anomaly_df)

    if include_multiclass:
        multi_df = attach_target(compact, multiclass_target[:n_rows])
        samples.multiclass.append(multi_df)


def scan_archives(
    archives: List[Path],
    assignments: Dict[Path, str],
    root: Path,
    chunksize: int,
    metadata_mode: str,
    include_multiclass: bool,
    sample_chunks_per_split: int,
    estimate_sample_rows: int,
    progress_every_chunks: int,
) -> tuple[Dict[str, SplitScanStats], List[ArchiveScanSummary], SampleFrames]:
    split_stats: Dict[str, SplitScanStats] = {split_name: SplitScanStats() for split_name in TRAIN_SPLITS}
    archive_summaries: List[ArchiveScanSummary] = []
    sample_quota = {split_name: int(sample_chunks_per_split) for split_name in TRAIN_SPLITS}
    samples = SampleFrames()

    total_archives = len(archives)
    for archive_index, archive_path in enumerate(archives, start=1):
        split_name = assignments.get(archive_path)
        if split_name not in TRAIN_SPLITS:
            continue

        archive_total = 0
        archive_benign = 0
        archive_attack = 0
        chunk_idx = 0
        archive_stem = archive_path.name.replace(".tar.gz", "")
        _, _, week_key = archive_context(archive_path, root)
        timeline_context = load_attack_timeline(matching_attack_ts(archive_path))

        print(f"[plan {archive_index}/{total_archives}] start {archive_path.name} split={split_name}", flush=True)

        with tarfile.open(archive_path, "r:gz") as tf:
            for member in archive_members(tf):
                file_obj = tf.extractfile(member)
                if file_obj is None:
                    continue

                reader = pd.read_csv(
                    file_obj,
                    header=None,
                    names=RAW_COLUMNS,
                    usecols=list(range(13)),
                    chunksize=chunksize,
                    low_memory=False,
                    on_bad_lines="skip",
                )
                for chunk in reader:
                    chunk_idx += 1
                    clean_rows, benign_rows, attack_rows = count_clean_rows_and_labels(chunk)
                    if clean_rows == 0:
                        continue

                    split_stats[split_name].total_rows += clean_rows
                    split_stats[split_name].benign_rows += benign_rows
                    split_stats[split_name].attack_rows += attack_rows

                    archive_total += clean_rows
                    archive_benign += benign_rows
                    archive_attack += attack_rows

                    if sample_quota[split_name] <= 0:
                        if progress_every_chunks > 0 and chunk_idx % progress_every_chunks == 0:
                            print(
                                f"[plan {archive_index}/{total_archives}] chunk={chunk_idx} clean_rows={archive_total:,}",
                                flush=True,
                            )
                        continue

                    base, binary_target, multiclass_target = preprocess_chunk(
                        chunk=chunk,
                        archive_name=archive_stem,
                        split_name=split_name,
                        week_key=week_key,
                        timeline_context=timeline_context,
                    )
                    if base.empty:
                        continue

                    collect_plan_samples(
                        samples=samples,
                        base=base,
                        binary_target=binary_target,
                        multiclass_target=multiclass_target,
                        split_name=split_name,
                        metadata_mode=metadata_mode,
                        include_multiclass=include_multiclass,
                        estimate_sample_rows=estimate_sample_rows,
                    )
                    sample_quota[split_name] -= 1

                    if progress_every_chunks > 0 and chunk_idx % progress_every_chunks == 0:
                        print(
                            f"[plan {archive_index}/{total_archives}] chunk={chunk_idx} clean_rows={archive_total:,}",
                            flush=True,
                        )

        archive_summaries.append(
            ArchiveScanSummary(
                archive=str(archive_path.resolve().relative_to(repo_root().resolve())),
                split=split_name,
                total_rows=archive_total,
                benign_rows=archive_benign,
                attack_rows=archive_attack,
            )
        )
        print(
            f"[plan {archive_index}/{total_archives}] done rows={archive_total:,} benign={archive_benign:,} attack={archive_attack:,}",
            flush=True,
        )

    return split_stats, archive_summaries, samples


def projected_pipeline_rows(
    split_stats: Dict[str, SplitScanStats],
    include_multiclass: bool,
    keep_binary_raw: bool,
    binary_balance: str,
) -> Dict[str, int]:
    total_rows = int(sum(stats.total_rows for stats in split_stats.values()))
    binary_rows = total_rows
    if binary_balance == "stratified_downsample":
        binary_rows = int(sum(2 * min(stats.benign_rows, stats.attack_rows) for stats in split_stats.values()))

    anomaly_rows = int(
        split_stats["train"].benign_rows
        + split_stats["val"].total_rows
        + split_stats["test"].total_rows
    )

    rows = {
        "binary": binary_rows,
        "anomaly": anomaly_rows,
    }
    if include_multiclass:
        rows["multiclass"] = total_rows
    if keep_binary_raw:
        rows["binary_raw"] = total_rows
    return rows


def estimate_pipeline_bytes(samples: SampleFrames, include_multiclass: bool, keep_binary_raw: bool) -> Dict[str, float]:
    binary_sample = concat_limited(samples.binary, max_rows=100_000)
    anomaly_sample = concat_limited(samples.anomaly, max_rows=100_000)
    multiclass_sample = concat_limited(samples.multiclass, max_rows=100_000)

    binary_bpr = estimate_parquet_bytes_per_row(binary_sample)
    anomaly_bpr = estimate_parquet_bytes_per_row(anomaly_sample) if not anomaly_sample.empty else binary_bpr
    rows = {
        "binary": binary_bpr,
        "anomaly": anomaly_bpr,
    }
    if include_multiclass:
        rows["multiclass"] = estimate_parquet_bytes_per_row(multiclass_sample)
    if keep_binary_raw:
        rows["binary_raw"] = binary_bpr
    return rows


def compute_sampling_plan(
    split_stats: Dict[str, SplitScanStats],
    archive_summaries: List[ArchiveScanSummary],
    samples: SampleFrames,
    dataset_name: str,
    target_size_gb: float,
    max_size_gb: float,
    safety_margin: float,
    include_multiclass: bool,
    keep_binary_raw: bool,
    binary_balance: str,
    metadata_mode: str,
) -> Dict[str, Any]:
    target_size_bytes = bytes_from_gb(target_size_gb)
    max_size_bytes = bytes_from_gb(max_size_gb)
    plan_budget_bytes = int(target_size_bytes * safety_margin)

    per_row_bytes = estimate_pipeline_bytes(samples, include_multiclass, keep_binary_raw)
    pipeline_rows = projected_pipeline_rows(split_stats, include_multiclass, keep_binary_raw, binary_balance)

    estimated_full_bytes = int(sum(int(pipeline_rows.get(name, 0)) * float(per_row_bytes.get(name, 0.0)) for name in pipeline_rows))
    sample_fraction = 1.0 if estimated_full_bytes <= 0 else min(1.0, float(plan_budget_bytes) / float(estimated_full_bytes))
    estimated_output_bytes = int(estimated_full_bytes * sample_fraction)

    split_payload = {
        split_name: {
            "total_rows": stats.total_rows,
            "benign_rows": stats.benign_rows,
            "attack_rows": stats.attack_rows,
        }
        for split_name, stats in split_stats.items()
    }

    return {
        "dataset_name": dataset_name,
        "date_split_only": True,
        "target_size_gb": target_size_gb,
        "max_size_gb": max_size_gb,
        "target_size_bytes": target_size_bytes,
        "max_size_bytes": max_size_bytes,
        "safety_margin": safety_margin,
        "plan_budget_bytes": plan_budget_bytes,
        "metadata_mode": metadata_mode,
        "binary_balance": binary_balance,
        "include_multiclass": include_multiclass,
        "keep_binary_raw": keep_binary_raw,
        "sample_fraction": sample_fraction,
        "estimated_full_bytes": estimated_full_bytes,
        "estimated_output_bytes": estimated_output_bytes,
        "estimated_full_gb": gb_from_bytes(estimated_full_bytes),
        "estimated_output_gb": gb_from_bytes(estimated_output_bytes),
        "bytes_per_row": {key: round(value, 4) for key, value in per_row_bytes.items()},
        "projected_pipeline_rows": pipeline_rows,
        "split_stats": split_payload,
        "archives": [summary.__dict__ for summary in archive_summaries],
    }


def process_archive_sampled(
    archive_path: Path,
    split_name: str,
    root: Path,
    out_dir: Path,
    chunksize: int,
    metadata_mode: str,
    include_multiclass: bool,
    sample_fraction: float,
    seed: int,
    progress_every_chunks: int,
) -> Dict[str, Dict[str, int]]:
    archive_stem = archive_path.name.replace(".tar.gz", "")
    _, _, week_key = archive_context(archive_path, root)
    timeline_context = load_attack_timeline(matching_attack_ts(archive_path))

    counts: Dict[str, Dict[str, int]] = {
        "binary_raw": {},
        "anomaly": {},
    }
    if include_multiclass:
        counts["multiclass"] = {}

    part_idx = 0
    chunk_idx = 0
    sampled_rows_written = 0

    with tarfile.open(archive_path, "r:gz") as tf:
        for member in archive_members(tf):
            file_obj = tf.extractfile(member)
            if file_obj is None:
                continue

            reader = pd.read_csv(
                file_obj,
                header=None,
                names=RAW_COLUMNS,
                usecols=list(range(13)),
                chunksize=chunksize,
                low_memory=False,
                on_bad_lines="skip",
            )
            for chunk in reader:
                chunk_idx += 1
                base, binary_target, multiclass_target = preprocess_chunk(
                    chunk=chunk,
                    archive_name=archive_stem,
                    split_name=split_name,
                    week_key=week_key,
                    timeline_context=timeline_context,
                )
                if base.empty:
                    continue

                compact = compact_base_frame(base, metadata_mode)
                if compact.empty:
                    continue

                mask = sample_mask(len(compact), sample_fraction, seed, archive_stem, part_idx)
                if not bool(mask.any()):
                    if progress_every_chunks > 0 and chunk_idx % progress_every_chunks == 0:
                        print(
                            f"[build {split_name}] {archive_path.name} chunk={chunk_idx} sampled_rows={sampled_rows_written:,}",
                            flush=True,
                        )
                    part_idx += 1
                    continue

                compact = compact.loc[mask].reset_index(drop=True)
                binary_keep = binary_target[mask]
                multiclass_keep = multiclass_target[mask]
                sampled_rows_written += int(len(compact))

                raw_df = attach_target(compact, binary_keep)
                raw_path = out_dir / "binary_raw" / split_name / f"{archive_stem}__part{part_idx:05d}.parquet"
                write_parquet(raw_df, raw_path)
                for label, value in count_labels(binary_keep).items():
                    counts["binary_raw"][label] = counts["binary_raw"].get(label, 0) + int(value)

                if include_multiclass:
                    multi_df = attach_target(compact, multiclass_keep)
                    multi_path = out_dir / "multiclass" / split_name / f"{archive_stem}__part{part_idx:05d}.parquet"
                    write_parquet(multi_df, multi_path)
                    for label, value in count_labels(multiclass_keep).items():
                        counts["multiclass"][label] = counts["multiclass"].get(label, 0) + int(value)

                anomaly_df = raw_df.copy()
                if split_name == "train":
                    anomaly_df = anomaly_df.loc[anomaly_df["target"] == "BENIGN"].copy()
                if not anomaly_df.empty:
                    anomaly_dir = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}[split_name]
                    anomaly_path = out_dir / "anomaly" / anomaly_dir / f"{archive_stem}__part{part_idx:05d}.parquet"
                    write_parquet(anomaly_df, anomaly_path)
                    anomaly_counts = count_labels(anomaly_df["target"].to_numpy())
                    for label, value in anomaly_counts.items():
                        counts["anomaly"][label] = counts["anomaly"].get(label, 0) + int(value)

                part_idx += 1

                if progress_every_chunks > 0 and chunk_idx % progress_every_chunks == 0:
                    print(
                        f"[build {split_name}] {archive_path.name} chunk={chunk_idx} sampled_rows={sampled_rows_written:,}",
                        flush=True,
                    )

    print(f"[{split_name}] {archive_path.name} -> sampled_parts={part_idx}, sampled_rows={sampled_rows_written:,}", flush=True)
    return counts


def print_plan(plan: Dict[str, Any]) -> None:
    print("== prepare_dataset_v3 plan ==")
    print(f"Dataset name       : {plan['dataset_name']}")
    print(f"Sample fraction    : {plan['sample_fraction']:.6f}")
    print(f"Estimated full size: {plan['estimated_full_gb']} GiB")
    print(f"Estimated output   : {plan['estimated_output_gb']} GiB")
    print(f"Target size        : {plan['target_size_gb']} GiB")
    print(f"Max size           : {plan['max_size_gb']} GiB")
    print(f"Metadata mode      : {plan['metadata_mode']}")
    print(f"Include multiclass : {plan['include_multiclass']}")
    print(f"Keep binary_raw    : {plan['keep_binary_raw']}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_dir", type=str, default=str(DEFAULT_IN_DIR))
    ap.add_argument("--out_dir", type=str, default=str(DEFAULT_OUT_DIR))
    ap.add_argument("--subset", type=str, default="thesis_v1", choices=["thesis_v1", "all_main"])
    ap.add_argument("--dataset_name", type=str, default=None)
    ap.add_argument("--target_size_gb", type=float, default=DEFAULT_TARGET_SIZE_GB)
    ap.add_argument("--max_size_gb", type=float, default=DEFAULT_MAX_SIZE_GB)
    ap.add_argument("--safety_margin", type=float, default=DEFAULT_SAFETY_MARGIN)
    ap.add_argument("--binary_balance", type=str, default="stratified_downsample", choices=["stratified_downsample", "none"])
    ap.add_argument("--chunksize", type=int, default=250_000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--metadata_mode", type=str, default="minimal", choices=["minimal", "full"])
    ap.add_argument("--include_multiclass", action="store_true")
    ap.add_argument("--keep_binary_raw", action="store_true")
    ap.add_argument("--plan_only", action="store_true")
    ap.add_argument("--plan_sample_chunks", type=int, default=DEFAULT_PLAN_SAMPLE_CHUNKS)
    ap.add_argument("--estimate_sample_rows", type=int, default=DEFAULT_ESTIMATE_SAMPLE_ROWS)
    ap.add_argument("--progress_every_chunks", type=int, default=DEFAULT_PROGRESS_EVERY_CHUNKS)
    args = ap.parse_args()

    if not (50.0 <= args.target_size_gb <= 100.0):
        raise SystemExit("target_size_gb must stay within the requested 50-100 GB range")
    if not (50.0 <= args.max_size_gb <= 100.0):
        raise SystemExit("max_size_gb must stay within the requested 50-100 GB range")
    if args.target_size_gb > args.max_size_gb:
        raise SystemExit("target_size_gb cannot be larger than max_size_gb")
    if not (0.1 <= args.safety_margin <= 1.0):
        raise SystemExit("safety_margin must be in [0.1, 1.0]")
    if args.plan_sample_chunks <= 0:
        raise SystemExit("plan_sample_chunks must be > 0")
    if args.estimate_sample_rows <= 0:
        raise SystemExit("estimate_sample_rows must be > 0")
    if args.progress_every_chunks <= 0:
        raise SystemExit("progress_every_chunks must be > 0")

    _ensure_pyarrow()

    in_dir = resolve_from_root(args.in_dir)
    out_base = resolve_from_root(args.out_dir)
    dataset_name = args.dataset_name or f"UGR16_V3_{int(round(args.target_size_gb))}GB"
    out_mode = out_base / "date" / dataset_name
    lock_path = out_base / "date" / f".{dataset_name}.prepare_dataset_v3.lock"

    if not in_dir.exists() or not in_dir.is_dir():
        raise SystemExit(f"Input folder does not exist: {in_dir}")

    archives_all = discover_main_archives(in_dir)
    archives = select_archives(archives_all, in_dir, args.subset)
    if not archives:
        raise SystemExit(f"No UGR16 archives selected in: {in_dir}")

    assignments = build_date_assignments(archives, in_dir)
    selected_archives = [archive for archive in archives if assignments.get(archive) in TRAIN_SPLITS]
    if not selected_archives:
        raise SystemExit("No selected archives were assigned to date split train/val/test")
    acquire_build_lock(lock_path, dataset_name)
    try:
        print("== prepare_dataset_v3 planning scan ==")
        print(f"Repo root        : {repo_root()}")
        print(f"Input dir        : {in_dir}")
        print(f"Output dir       : {out_mode}")
        print(f"Selected archives: {len(selected_archives)}")
        print(f"Subset           : {args.subset}")
        print(f"Metadata mode    : {args.metadata_mode}")
        print(f"Progress chunks  : {args.progress_every_chunks}")
        print(f"Dataset lock     : {lock_path}")
        print(flush=True)

        split_stats, archive_summaries, samples = scan_archives(
            archives=selected_archives,
            assignments=assignments,
            root=in_dir,
            chunksize=args.chunksize,
            metadata_mode=args.metadata_mode,
            include_multiclass=args.include_multiclass,
            sample_chunks_per_split=args.plan_sample_chunks,
            estimate_sample_rows=args.estimate_sample_rows,
            progress_every_chunks=args.progress_every_chunks,
        )
        plan = compute_sampling_plan(
            split_stats=split_stats,
            archive_summaries=archive_summaries,
            samples=samples,
            dataset_name=dataset_name,
            target_size_gb=args.target_size_gb,
            max_size_gb=args.max_size_gb,
            safety_margin=args.safety_margin,
            include_multiclass=args.include_multiclass,
            keep_binary_raw=args.keep_binary_raw,
            binary_balance=args.binary_balance,
            metadata_mode=args.metadata_mode,
        )
        print_plan(plan)

        clear_generated_dir(out_mode)
        write_json(out_mode / "prepare_dataset_v3_plan.json", plan)
        write_subset_manifest(out_mode, args.subset, selected_archives, repo_root())
        write_feature_columns(out_mode, expected_feature_columns())
        write_split_policy(out_mode, assignments)

        if args.plan_only:
            print(f"Plan written to: {out_mode / 'prepare_dataset_v3_plan.json'}")
            return

        stats: Dict[str, Dict[str, Stats]] = {
            "binary_raw": {split_name: Stats() for split_name in TRAIN_SPLITS},
            "binary": {split_name: Stats() for split_name in TRAIN_SPLITS},
            "anomaly": {split_name: Stats() for split_name in TRAIN_SPLITS},
        }
        if args.include_multiclass:
            stats["multiclass"] = {split_name: Stats() for split_name in TRAIN_SPLITS}

        print("== prepare_dataset_v3 build ==")
        print(f"Repo root    : {repo_root()}")
        print(f"Input dir    : {in_dir}")
        print(f"Output dir   : {out_mode}")
        print(f"Subset       : {args.subset}")
        print(f"Sample frac  : {plan['sample_fraction']:.6f}")
        print(f"Binary bal   : {args.binary_balance}")
        print(f"Multiclass   : {args.include_multiclass}")
        print(f"Keep raw     : {args.keep_binary_raw}")
        print(flush=True)

        total_archives = len(selected_archives)
        for archive_index, archive_path in enumerate(selected_archives, start=1):
            split_name = assignments.get(archive_path)
            if split_name not in TRAIN_SPLITS:
                continue
            print(f"[build {archive_index}/{total_archives}] start {archive_path.name} split={split_name}", flush=True)
            counts = process_archive_sampled(
                archive_path=archive_path,
                split_name=split_name,
                root=in_dir,
                out_dir=out_mode,
                chunksize=args.chunksize,
                metadata_mode=args.metadata_mode,
                include_multiclass=args.include_multiclass,
                sample_fraction=float(plan["sample_fraction"]),
                seed=args.seed,
                progress_every_chunks=args.progress_every_chunks,
            )
            update_stats(stats["binary_raw"][split_name], counts["binary_raw"], binary_view=True)
            update_stats(stats["anomaly"][split_name], counts["anomaly"], binary_view=True)
            if args.include_multiclass:
                update_stats(stats["multiclass"][split_name], counts["multiclass"], binary_view=False)

        binary_counts = materialize_binary_pipeline(out_mode, args.binary_balance, args.seed)
        for split_name, counts in binary_counts.items():
            update_stats(stats["binary"][split_name], counts, binary_view=True)

        if not args.keep_binary_raw:
            shutil.rmtree(out_mode / "binary_raw", ignore_errors=True)
            stats.pop("binary_raw", None)

        write_supervised_label_maps(out_mode, stats)
        write_stats(out_mode, stats)

        actual_size_bytes = folder_size_bytes(out_mode)
        summary = {
            "dataset_name": dataset_name,
            "actual_size_bytes": actual_size_bytes,
            "actual_size_gb": gb_from_bytes(actual_size_bytes),
            "max_size_gb": args.max_size_gb,
            "target_size_gb": args.target_size_gb,
            "sample_fraction": plan["sample_fraction"],
            "include_multiclass": args.include_multiclass,
            "keep_binary_raw": args.keep_binary_raw,
            "metadata_mode": args.metadata_mode,
        }
        write_json(out_mode / "prepare_dataset_v3_summary.json", summary)

        print(f"Actual output size: {summary['actual_size_gb']} GiB")
        if actual_size_bytes > bytes_from_gb(args.max_size_gb):
            raise SystemExit(
                "prepare_dataset_v3 produced a dataset larger than the configured max_size_gb. "
                f"Actual={summary['actual_size_gb']} GiB, max={args.max_size_gb} GiB"
            )
    finally:
        release_build_lock(lock_path)


if __name__ == "__main__":
    main()