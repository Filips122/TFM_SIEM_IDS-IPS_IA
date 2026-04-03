#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except Exception:
    pa = None
    pq = None


def repo_root() -> Path:
    # <root>/src/models/UGR16/prepare_dataset.py
    return Path(__file__).resolve().parents[3]


def resolve_from_root(p: str | Path) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


DEFAULT_IN_DIR = Path("out/UGR16")
DEFAULT_OUT_DIR = Path("src/models/UGR16/datasets")

RAW_COLUMNS = [f"col_{i}" for i in range(1, 14)]
MONTH_ORDER = {
    "March 2016": 3,
    "April 2016": 4,
    "May 2016": 5,
    "June 2016": 6,
    "July 2016": 7,
    "August 2016": 8,
}
MAIN_ARCHIVE_PREFIXES = ("march_", "april_", "may_", "june_", "july_", "august_")
THESIS_INCLUDED_WEEKS = {
    ("March 2016", "March - Week #3"),
    ("March 2016", "March - Week #4"),
    ("March 2016", "March - Week #5"),
    ("April 2016", "April - Week #2"),
    ("April 2016", "April - Week #3"),
    ("April 2016", "April - Week #4"),
    ("April 2016", "April - Week #5"),
    ("May 2016", "May - Week #1"),
    ("May 2016", "May - Week #2"),
    ("May 2016", "May - Week #3"),
    ("May 2016", "May - Week #4"),
    ("May 2016", "May - Week #5"),
    ("May 2016", "May - Week #6"),
    ("June 2016", "June - Week #1"),
    ("June 2016", "June - Week #2"),
    ("June 2016", "June - Week #3"),
    ("June 2016", "June - Week #4"),
    ("July 2016", "July - Week #5"),
    ("August 2016", "August - Week #1"),
    ("August 2016", "August - Week #2"),
    ("August 2016", "August - Week #3"),
    ("August 2016", "August - Week #5"),
}
PROTOCOL_COLUMNS = ["TCP", "UDP", "ICMP", "GRE", "ESP", "IPIP", "IPV6"]
FAMILY_PRIORITY = [
    "anomaly-spam",
    "anomaly-sshscan",
    "anomaly-udpscan",
    "nerisbotnet",
    "dos",
    "scan11",
    "scan44",
    "blacklist",
]


def _ensure_pyarrow() -> None:
    if pa is None or pq is None:
        raise SystemExit("Missing pyarrow. Install with: pip install pyarrow")


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _table_no_meta(df: pd.DataFrame) -> Any:
    return pa.Table.from_pandas(df, preserve_index=False).replace_schema_metadata(None)


def week_sort_key(month: str, week: str) -> Tuple[int, int, str]:
    week_match = re.search(r"Week\s*#(\d+)", week)
    week_num = int(week_match.group(1)) if week_match else 99
    return MONTH_ORDER.get(month, 99), week_num, f"{month}|{week}"


def archive_context(path: Path, root: Path) -> Tuple[str, str, str]:
    rel = path.resolve().relative_to(root.resolve())
    parts = rel.parts
    month = parts[0] if len(parts) >= 1 else "UnknownMonth"
    week = parts[1] if len(parts) >= 2 else "UnknownWeek"
    return month, week, f"{month} | {week}"


def discover_main_archives(root: Path) -> List[Path]:
    archives: List[Path] = []
    for p in sorted(root.rglob("*_csv.tar.gz")):
        if not p.is_file():
            continue
        name = p.name.lower()
        if name.startswith(MAIN_ARCHIVE_PREFIXES):
            archives.append(p)
    archives.sort(key=lambda p: week_sort_key(*archive_context(p, root)[:2]))
    return archives


def select_archives(archives: List[Path], root: Path, subset: str) -> List[Path]:
    if subset == "all_main":
        return archives
    if subset != "thesis_v1":
        raise SystemExit(f"Unsupported subset: {subset}")

    selected = []
    for p in archives:
        month, week, _ = archive_context(p, root)
        if (month, week) in THESIS_INCLUDED_WEEKS:
            selected.append(p)
    return selected


def matching_attack_ts(archive_path: Path) -> Optional[Path]:
    matches = sorted(archive_path.parent.glob("attack_ts_*.csv"))
    return matches[0] if matches else None


def normalize_label(value: object) -> str:
    s = str(value or "").strip().lower()
    if s in {"", "nan", "none", "null", "?", "-"}:
        return "background"
    return s


def normalize_protocol(value: object) -> str:
    s = str(value or "").strip().upper()
    return s if s else "UNKNOWN"


def pick_primary_family(row: pd.Series, family_cols: List[str]) -> str:
    active = {str(c).strip().lower(): float(row[c]) for c in family_cols if pd.notna(row[c]) and float(row[c]) > 0.0}
    if not active:
        return "none"
    for family in FAMILY_PRIORITY:
        if family in active:
            return family
    return sorted(active.keys())[0]


def load_attack_timeline(path: Optional[Path]) -> Tuple[Dict[pd.Timestamp, bool], Dict[pd.Timestamp, str]]:
    if path is None or not path.exists():
        return {}, {}

    df = pd.read_csv(path)
    if df.empty:
        return {}, {}

    ts_col = df.columns[0]
    family_cols = [c for c in df.columns if c not in {ts_col, "counter(mins)"}]
    if not family_cols:
        return {}, {}

    df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce")
    df = df[df[ts_col].notna()].copy()
    if df.empty:
        return {}, {}

    numeric = df[family_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    active_any = numeric.gt(0.0).any(axis=1)
    primary_family = numeric.apply(lambda row: pick_primary_family(row, family_cols), axis=1)

    minute_series = df[ts_col].dt.floor("min")
    active_map = {minute: bool(is_active) for minute, is_active in zip(minute_series, active_any)}
    family_map = {minute: family for minute, family in zip(minute_series, primary_family)}
    return active_map, family_map


def build_protocol_indicators(protocol: pd.Series) -> Dict[str, pd.Series]:
    out: Dict[str, pd.Series] = {}
    known_mask = pd.Series(False, index=protocol.index)
    for proto_name in PROTOCOL_COLUMNS:
        key = proto_name.lower().replace("6", "6")
        mask = protocol == proto_name
        out[f"proto_{key}"] = mask.astype(np.float64)
        known_mask = known_mask | mask
    out["proto_other"] = (~known_mask).astype(np.float64)
    return out


def preprocess_chunk(
    chunk: pd.DataFrame,
    archive_name: str,
    split_name: str,
    week_key: str,
    timeline_active_map: Dict[pd.Timestamp, bool],
    timeline_family_map: Dict[pd.Timestamp, str],
) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    if chunk.empty:
        return pd.DataFrame(), np.empty((0,), dtype=object), np.empty((0,), dtype=object)

    work = chunk.iloc[:, :13].copy()
    work.columns = RAW_COLUMNS

    event_ts = pd.to_datetime(work["col_1"], errors="coerce")
    work = work[event_ts.notna()].copy()
    event_ts = event_ts[event_ts.notna()]
    if work.empty:
        return pd.DataFrame(), np.empty((0,), dtype=object), np.empty((0,), dtype=object)

    duration = pd.to_numeric(work["col_2"], errors="coerce").fillna(0.0).clip(lower=0.0)
    src_port = pd.to_numeric(work["col_5"], errors="coerce").fillna(0.0).clip(lower=0.0)
    dst_port = pd.to_numeric(work["col_6"], errors="coerce").fillna(0.0).clip(lower=0.0)
    ttl = pd.to_numeric(work["col_10"], errors="coerce").fillna(0.0).clip(lower=0.0)
    packets = pd.to_numeric(work["col_11"], errors="coerce").fillna(0.0).clip(lower=0.0)
    bytes_ = pd.to_numeric(work["col_12"], errors="coerce").fillna(0.0).clip(lower=0.0)

    protocol = work["col_7"].map(normalize_protocol)
    flags = work["col_8"].astype(str).fillna("")
    raw_label = work["col_13"].map(normalize_label)

    minute_key = event_ts.dt.floor("min")
    timeline_active = minute_key.map(timeline_active_map).fillna(False)
    timeline_family = minute_key.map(timeline_family_map).fillna("none")

    safe_duration = duration.where(duration > 0.0, 1.0)
    bytes_per_packet = np.divide(bytes_, packets.where(packets > 0.0, 1.0))
    packets_per_second = np.divide(packets, safe_duration)
    bytes_per_second = np.divide(bytes_, safe_duration)
    iso_week = event_ts.dt.isocalendar().week.astype(np.int64)

    data: Dict[str, Any] = {
        "duration": duration.astype(np.float64),
        "src_port": src_port.astype(np.float64),
        "dst_port": dst_port.astype(np.float64),
        "ttl": ttl.astype(np.float64),
        "packets": packets.astype(np.float64),
        "bytes": bytes_.astype(np.float64),
        "bytes_per_packet": pd.Series(bytes_per_packet, index=work.index, dtype=np.float64),
        "packets_per_second": pd.Series(packets_per_second, index=work.index, dtype=np.float64),
        "bytes_per_second": pd.Series(bytes_per_second, index=work.index, dtype=np.float64),
        "hour": event_ts.dt.hour.astype(np.float64),
        "minute": event_ts.dt.minute.astype(np.float64),
        "day_of_week": event_ts.dt.dayofweek.astype(np.float64),
        "month_num": event_ts.dt.month.astype(np.float64),
        "iso_week": iso_week.astype(np.float64),
        "src_port_is_system": (src_port < 1024).astype(np.float64),
        "dst_port_is_system": (dst_port < 1024).astype(np.float64),
        "src_port_is_ephemeral": (src_port >= 49152).astype(np.float64),
        "dst_port_is_ephemeral": (dst_port >= 49152).astype(np.float64),
        "src_port_is_zero": (src_port == 0).astype(np.float64),
        "dst_port_is_zero": (dst_port == 0).astype(np.float64),
        "flag_has_ack": flags.str.contains("A", regex=False).astype(np.float64),
        "flag_has_psh": flags.str.contains("P", regex=False).astype(np.float64),
        "flag_has_syn": flags.str.contains("S", regex=False).astype(np.float64),
        "flag_has_fin": flags.str.contains("F", regex=False).astype(np.float64),
        "flag_has_rst": flags.str.contains("R", regex=False).astype(np.float64),
    }
    data.update(build_protocol_indicators(protocol))

    base = pd.DataFrame(data)
    base["event_ts"] = event_ts.to_numpy(copy=False)
    base["src_ip_meta"] = work["col_3"].astype(str)
    base["dst_ip_meta"] = work["col_4"].astype(str)
    base["protocol_raw_meta"] = protocol.astype(str)
    base["flags_raw_meta"] = flags.astype(str)
    base["label_raw"] = raw_label.astype(str)
    base["timeline_attack_active_meta"] = np.where(timeline_active.to_numpy(), "YES", "NO")
    base["timeline_primary_family_meta"] = timeline_family.astype(str)
    base["archive_name_meta"] = archive_name
    base["split_name_meta"] = split_name
    base["week_key_meta"] = week_key

    binary_target = np.where(raw_label.to_numpy() != "background", "ATTACK", "BENIGN")
    multiclass_target = np.where(raw_label.to_numpy() != "background", raw_label.to_numpy(), "BENIGN")
    return base, binary_target.astype(object), multiclass_target.astype(object)


@dataclass
class Stats:
    rows: int = 0
    benign: int = 0
    attack: int = 0
    label_counts: Dict[str, int] = None

    def __post_init__(self):
        if self.label_counts is None:
            self.label_counts = {}


def count_labels(values: np.ndarray) -> Dict[str, int]:
    if len(values) == 0:
        return {}
    series = pd.Series(values.astype(str))
    vc = series.value_counts(dropna=False)
    return {str(k): int(v) for k, v in vc.items()}


def update_stats(st: Stats, counts: Dict[str, int], binary_view: bool) -> None:
    st.rows += int(sum(counts.values()))
    for label, value in counts.items():
        st.label_counts[label] = st.label_counts.get(label, 0) + int(value)

    if binary_view:
        st.benign += int(counts.get("BENIGN", 0))
        st.attack += int(counts.get("ATTACK", 0))
    else:
        benign = int(counts.get("BENIGN", 0))
        st.benign += benign
        st.attack += int(sum(counts.values()) - benign)


def write_stats(base_dir: Path, stats: Dict[str, Dict[str, Stats]]) -> None:
    for pipeline_name, splits in stats.items():
        out = base_dir / pipeline_name / "stats.json"
        safe_mkdir(out.parent)
        payload = {}
        for split, st in splits.items():
            payload[split] = {
                "rows": st.rows,
                "benign": st.benign,
                "attack": st.attack,
                "label_counts": dict(sorted(st.label_counts.items(), key=lambda x: x[1], reverse=True)),
            }
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_parquet(df: pd.DataFrame, out_path: Path) -> None:
    safe_mkdir(out_path.parent)
    pq.write_table(_table_no_meta(df), out_path)


def anomaly_split_name(split_name: str) -> str:
    return {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}[split_name]


def process_base_chunk(
    base: pd.DataFrame,
    binary_target: np.ndarray,
    multiclass_target: np.ndarray,
    out_base: Path,
    split_name: str,
    archive_stem: str,
    part_idx: int,
) -> Dict[str, Dict[str, int]]:
    counts: Dict[str, Dict[str, int]] = {
        "binary": {},
        "multiclass": {},
        "anomaly": {},
    }

    binary_df = base.copy()
    binary_df["target"] = binary_target
    counts["binary"] = count_labels(binary_target)
    write_parquet(binary_df, out_base / "binary" / split_name / f"{archive_stem}__part{part_idx:05d}.parquet")

    multiclass_df = base.copy()
    multiclass_df["target"] = multiclass_target
    counts["multiclass"] = count_labels(multiclass_target)
    write_parquet(multiclass_df, out_base / "multiclass" / split_name / f"{archive_stem}__part{part_idx:05d}.parquet")

    anomaly_df = base.copy()
    anomaly_df["target"] = binary_target
    if split_name == "train":
        anomaly_df = anomaly_df[anomaly_df["target"] == "BENIGN"].copy()
    if not anomaly_df.empty:
        counts["anomaly"] = count_labels(anomaly_df["target"].to_numpy())
        write_parquet(
            anomaly_df,
            out_base / "anomaly" / anomaly_split_name(split_name) / f"{archive_stem}__part{part_idx:05d}.parquet",
        )

    return counts


def process_archive_fixed_split(
    archive_path: Path,
    split_name: str,
    out_dataset_dir: Path,
    chunksize: int,
    root: Path,
) -> Dict[str, Dict[str, int]]:
    archive_stem = archive_path.name.replace(".tar.gz", "")
    month, week, week_key = archive_context(archive_path, root)
    attack_ts_path = matching_attack_ts(archive_path)
    timeline_active_map, timeline_family_map = load_attack_timeline(attack_ts_path)

    combined_counts = {"binary": {}, "multiclass": {}, "anomaly": {}}
    part_idx = 0

    with tarfile.open(archive_path, "r:gz") as tf:
        members = [m for m in tf.getmembers() if m.isfile() and m.name.lower().endswith(".csv")]
        for member in members:
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
                base, binary_target, multiclass_target = preprocess_chunk(
                    chunk=chunk,
                    archive_name=archive_stem,
                    split_name=split_name,
                    week_key=week_key,
                    timeline_active_map=timeline_active_map,
                    timeline_family_map=timeline_family_map,
                )
                if base.empty:
                    continue
                chunk_counts = process_base_chunk(
                    base=base,
                    binary_target=binary_target,
                    multiclass_target=multiclass_target,
                    out_base=out_dataset_dir,
                    split_name=split_name,
                    archive_stem=archive_stem,
                    part_idx=part_idx,
                )
                for pipeline_name, counts in chunk_counts.items():
                    for label, value in counts.items():
                        combined_counts[pipeline_name][label] = combined_counts[pipeline_name].get(label, 0) + int(value)
                part_idx += 1

    print(f"[{split_name}] {archive_path.name} -> parts={part_idx}")
    return combined_counts


def process_archive_random(
    archive_path: Path,
    out_dataset_dir: Path,
    chunksize: int,
    rng: np.random.Generator,
    train_ratio: float,
    val_ratio: float,
    root: Path,
) -> Dict[str, Dict[str, Dict[str, int]]]:
    archive_stem = archive_path.name.replace(".tar.gz", "")
    _, _, week_key = archive_context(archive_path, root)
    attack_ts_path = matching_attack_ts(archive_path)
    timeline_active_map, timeline_family_map = load_attack_timeline(attack_ts_path)

    counts: Dict[str, Dict[str, Dict[str, int]]] = {
        "binary": {"train": {}, "val": {}, "test": {}},
        "multiclass": {"train": {}, "val": {}, "test": {}},
        "anomaly": {"train": {}, "val": {}, "test": {}},
    }
    part_idx = 0

    with tarfile.open(archive_path, "r:gz") as tf:
        members = [m for m in tf.getmembers() if m.isfile() and m.name.lower().endswith(".csv")]
        for member in members:
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
                base, binary_target, multiclass_target = preprocess_chunk(
                    chunk=chunk,
                    archive_name=archive_stem,
                    split_name="random",
                    week_key=week_key,
                    timeline_active_map=timeline_active_map,
                    timeline_family_map=timeline_family_map,
                )
                if base.empty:
                    continue

                r = rng.random(len(base))
                train_mask = r < train_ratio
                val_mask = (r >= train_ratio) & (r < train_ratio + val_ratio)
                test_mask = ~(train_mask | val_mask)
                masks = {
                    "train": train_mask,
                    "val": val_mask,
                    "test": test_mask,
                }

                for split_name, mask in masks.items():
                    if int(mask.sum()) == 0:
                        continue
                    split_base = base.loc[mask].copy()
                    split_binary = binary_target[mask]
                    split_multi = multiclass_target[mask]
                    chunk_counts = process_base_chunk(
                        base=split_base,
                        binary_target=split_binary,
                        multiclass_target=split_multi,
                        out_base=out_dataset_dir,
                        split_name=split_name,
                        archive_stem=archive_stem,
                        part_idx=part_idx,
                    )
                    for pipeline_name, label_counts in chunk_counts.items():
                        for label, value in label_counts.items():
                            counts[pipeline_name][split_name][label] = counts[pipeline_name][split_name].get(label, 0) + int(value)
                part_idx += 1

    print(f"[random] {archive_path.name} -> parts={part_idx}")
    return counts


def write_subset_manifest(out_dir: Path, subset: str, archives: List[Path], root: Path) -> None:
    payload = {
        "subset": subset,
        "archives": [str(p.resolve().relative_to(root.resolve())) for p in archives],
        "matching_attack_ts": [
            str(matching_attack_ts(p).resolve().relative_to(root.resolve())) if matching_attack_ts(p) is not None else None
            for p in archives
        ],
    }
    (out_dir / "subset_manifest.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_feature_columns(out_dir: Path, columns: List[str]) -> None:
    (out_dir / "feature_columns.json").write_text(json.dumps(columns, ensure_ascii=False, indent=2), encoding="utf-8")


def expected_feature_columns() -> List[str]:
    return [
        "duration",
        "src_port",
        "dst_port",
        "ttl",
        "packets",
        "bytes",
        "bytes_per_packet",
        "packets_per_second",
        "bytes_per_second",
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
    ]


def build_date_assignments(archives: List[Path], root: Path) -> Dict[Path, str]:
    assignments: Dict[Path, str] = {}
    for archive in archives:
        month, week, _ = archive_context(archive, root)
        if month in {"March 2016", "April 2016", "May 2016", "June 2016"}:
            assignments[archive] = "train"
        elif (month, week) == ("July 2016", "July - Week #5"):
            assignments[archive] = "val"
        elif month == "August 2016":
            assignments[archive] = "test"
    return assignments


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_dir", type=str, default=str(DEFAULT_IN_DIR))
    ap.add_argument("--out_dir", type=str, default=str(DEFAULT_OUT_DIR))
    ap.add_argument("--split_mode", type=str, default="date", choices=["date", "random", "groupkfold"])
    ap.add_argument("--subset", type=str, default="thesis_v1", choices=["thesis_v1", "all_main"])
    ap.add_argument("--chunksize", type=int, default=250_000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--train_ratio", type=float, default=0.70)
    ap.add_argument("--val_ratio", type=float, default=0.15)
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)
    ap.add_argument("--n_folds", type=int, default=8)
    args = ap.parse_args()

    _ensure_pyarrow()

    in_dir = resolve_from_root(args.in_dir)
    out_base = resolve_from_root(args.out_dir)
    out_mode = out_base / args.split_mode / "UGR16"
    safe_mkdir(out_mode)

    if not in_dir.exists() or not in_dir.is_dir():
        raise SystemExit(f"Input folder does not exist: {in_dir}")

    archives_all = discover_main_archives(in_dir)
    archives = select_archives(archives_all, in_dir, args.subset)
    if not archives:
        raise SystemExit(f"No UGR16 archives selected in: {in_dir}")

    write_subset_manifest(out_mode, args.subset, archives, repo_root())
    write_feature_columns(out_mode, expected_feature_columns())

    print("== prepare_dataset (UGR16) ==")
    print(f"Repo root : {repo_root()}")
    print(f"Input dir : {in_dir}")
    print(f"Split mode: {args.split_mode}")
    print(f"Subset    : {args.subset}")
    print(f"Out dir   : {out_mode}")
    print(f"Chunksize : {args.chunksize}")
    print(f"Archives  : {[p.name for p in archives]}")

    stats: Dict[str, Dict[str, Stats]] = {
        "binary": {"train": Stats(), "val": Stats(), "test": Stats()},
        "multiclass": {"train": Stats(), "val": Stats(), "test": Stats()},
        "anomaly": {"train": Stats(), "val": Stats(), "test": Stats()},
    }

    if args.split_mode == "date":
        assignments = build_date_assignments(archives, in_dir)
        (out_mode / "split_policy.json").write_text(
            json.dumps({str(p.resolve().relative_to(repo_root().resolve())): split for p, split in assignments.items()}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        for archive in archives:
            split_name = assignments.get(archive)
            if split_name is None:
                continue
            c = process_archive_fixed_split(archive, split_name, out_mode, args.chunksize, in_dir)
            update_stats(stats["binary"][split_name], c["binary"], binary_view=True)
            update_stats(stats["multiclass"][split_name], c["multiclass"], binary_view=False)
            update_stats(stats["anomaly"][split_name], c["anomaly"], binary_view=True)
        write_stats(out_mode, stats)
        return

    if args.split_mode == "random":
        if not (0.0 < args.train_ratio < 1.0) or not (0.0 <= args.val_ratio < 1.0) or not (args.train_ratio + args.val_ratio < 1.0):
            raise SystemExit("Invalid random ratios: requires 0<train<1, 0<=val<1, train+val<1")

        rng = np.random.default_rng(args.seed)
        for archive in archives:
            c = process_archive_random(archive, out_mode, args.chunksize, rng, args.train_ratio, args.val_ratio, in_dir)
            for split_name in ["train", "val", "test"]:
                update_stats(stats["binary"][split_name], c["binary"][split_name], binary_view=True)
                update_stats(stats["multiclass"][split_name], c["multiclass"][split_name], binary_view=False)
                update_stats(stats["anomaly"][split_name], c["anomaly"][split_name], binary_view=True)
        write_stats(out_mode, stats)
        return

    if args.n_folds < 2:
        raise SystemExit("n_folds must be >= 2")

    if (not args.all_folds) and (args.fold is None):
        args.fold = 0
    folds = list(range(args.n_folds)) if args.all_folds else [args.fold]
    n_groups = len(archives)

    for fold in folds:
        if fold is None or fold < 0 or fold >= args.n_folds:
            raise SystemExit(f"Invalid fold: {fold}")

        fold_dir = out_mode / f"fold_{fold}"
        safe_mkdir(fold_dir)

        mapped = fold % n_groups
        test_file = archives[mapped]
        val_file = archives[(mapped + 1) % n_groups]
        train_files = [p for p in archives if p not in {test_file, val_file}]

        print(f"\n== [groupkfold] fold_{fold} ==")
        print(f"test : {test_file.name}")
        print(f"val  : {val_file.name}")
        print(f"train: {[p.name for p in train_files]}")

        (fold_dir / "split_policy.json").write_text(
            json.dumps(
                {
                    "train": [str(p.resolve().relative_to(repo_root().resolve())) for p in train_files],
                    "val": str(val_file.resolve().relative_to(repo_root().resolve())),
                    "test": str(test_file.resolve().relative_to(repo_root().resolve())),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        fold_stats: Dict[str, Dict[str, Stats]] = {
            "binary": {"train": Stats(), "val": Stats(), "test": Stats()},
            "multiclass": {"train": Stats(), "val": Stats(), "test": Stats()},
            "anomaly": {"train": Stats(), "val": Stats(), "test": Stats()},
        }

        for archive in train_files:
            c = process_archive_fixed_split(archive, "train", fold_dir, args.chunksize, in_dir)
            update_stats(fold_stats["binary"]["train"], c["binary"], binary_view=True)
            update_stats(fold_stats["multiclass"]["train"], c["multiclass"], binary_view=False)
            update_stats(fold_stats["anomaly"]["train"], c["anomaly"], binary_view=True)

        c = process_archive_fixed_split(val_file, "val", fold_dir, args.chunksize, in_dir)
        update_stats(fold_stats["binary"]["val"], c["binary"], binary_view=True)
        update_stats(fold_stats["multiclass"]["val"], c["multiclass"], binary_view=False)
        update_stats(fold_stats["anomaly"]["val"], c["anomaly"], binary_view=True)

        c = process_archive_fixed_split(test_file, "test", fold_dir, args.chunksize, in_dir)
        update_stats(fold_stats["binary"]["test"], c["binary"], binary_view=True)
        update_stats(fold_stats["multiclass"]["test"], c["multiclass"], binary_view=False)
        update_stats(fold_stats["anomaly"]["test"], c["anomaly"], binary_view=True)

        write_stats(fold_dir, fold_stats)


if __name__ == "__main__":
    main()
