#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import shutil
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, MutableMapping, Sequence, Tuple

import numpy as np
import pandas as pd


try:
    import pyarrow  # noqa: F401
except Exception:
    pyarrow = None


DATASET_NAME = "CSR-LANL"
DEFAULT_IN_DIR = Path("out/CSR-LANL")
DEFAULT_OUT_DIR = Path("src/models/CSR-LANL/datasets")
SPLITS = ("train", "val", "test")

SOURCE_SCHEMAS: Dict[str, List[str]] = {
    "auth": [
        "time",
        "src_user",
        "dst_user",
        "src_computer",
        "dst_computer",
        "auth_type",
        "logon_type",
        "auth_orient",
        "result",
    ],
    "dns": ["time", "src_computer", "dst_computer"],
    "flows": [
        "time",
        "duration",
        "src_computer",
        "src_port",
        "dst_computer",
        "dst_port",
        "protocol",
        "packet_count",
        "byte_count",
    ],
    "proc": ["time", "user", "computer", "process", "event_type"],
    "redteam": ["time", "user", "src_computer", "dst_computer"],
}

SOURCE_FILES = {
    "auth": "auth.txt.gz",
    "dns": "dns.txt.gz",
    "flows": "flows.txt.gz",
    "proc": "proc.txt.gz",
    "redteam": "redteam.txt.gz",
}

SOURCE_SETS = {
    "auth": ["auth"],
    "auth_flow": ["auth", "flows"],
    "auth_flow_dns": ["auth", "flows", "dns"],
    "all": ["auth", "flows", "dns", "proc"],
}

TimeInterval = Tuple[int, int]

MISSING_TOKENS = {"", "?", "-", "na", "n/a", "null", "none", "nan"}

FEATURE_COLUMNS = [
    "auth_event_count",
    "auth_success_count",
    "auth_fail_count",
    "auth_failure_ratio",
    "auth_logon_count",
    "auth_logoff_count",
    "auth_tgs_count",
    "auth_tgt_count",
    "auth_authmap_count",
    "auth_network_logon_count",
    "auth_interactive_logon_count",
    "auth_service_logon_count",
    "auth_batch_logon_count",
    "auth_type_unique_count",
    "logon_type_unique_count",
    "unique_src_user_count",
    "unique_dst_user_count",
    "auth_unique_dst_computer_count",
    "machine_account_count",
    "anonymous_logon_count",
    "flow_event_count",
    "flow_duration_sum",
    "flow_duration_mean",
    "flow_duration_max",
    "flow_packet_sum",
    "flow_byte_sum",
    "flow_byte_mean",
    "flow_unique_dst_computer_count",
    "flow_unique_dst_port_count",
    "flow_tcp_count",
    "flow_udp_count",
    "flow_icmp_count",
    "flow_privileged_dst_port_count",
    "dns_event_count",
    "dns_unique_dst_computer_count",
    "proc_event_count",
    "proc_unique_user_count",
    "proc_unique_process_count",
    "proc_start_count",
    "proc_end_count",
    "active_source_count",
    "total_event_count",
    "auth_to_flow_ratio",
    "fail_to_flow_ratio",
    "proc_to_auth_ratio",
    "has_new_src_user",
    "has_new_dst_computer",
    "has_new_process",
    "day_index",
    "hour_index",
    "minute_of_day",
]

META_COLUMNS = [
    "window_start",
    "window_end",
    "entity",
    "binary_target",
    "multiclass_target_raw",
    "multiclass_target",
    "redteam_exact",
    "redteam_near",
    "redteam_roles",
    "source_families",
]


@dataclass
class Stats:
    rows: int = 0
    benign: int = 0
    attack: int = 0
    label_counts: Dict[str, int] | None = None

    def __post_init__(self) -> None:
        if self.label_counts is None:
            self.label_counts = {}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_from_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root() / candidate).resolve()


def ensure_pyarrow() -> None:
    if pyarrow is None:
        raise SystemExit("Missing pyarrow. Install with: pip install pyarrow")


def clear_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def clean_text(value: object, default: str = "Unknown") -> str:
    if value is None:
        return default
    text = str(value).strip()
    if text.lower() in MISSING_TOKENS:
        return default
    return text


def clean_series(series: pd.Series, default: str = "Unknown") -> pd.Series:
    out = series.astype(str).str.strip()
    out = out.mask(out.str.lower().isin(MISSING_TOKENS), default)
    return out.fillna(default)


def lower_clean_series(series: pd.Series, default: str = "unknown") -> pd.Series:
    return clean_series(series, default=default).str.lower()


def safe_numeric(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series, errors="coerce")


def is_machine_account(value: str) -> bool:
    name = clean_text(value, default="")
    if not name:
        return False
    left = name.split("@", 1)[0]
    return left.endswith("$") or left.startswith("C") and "$" in left


def source_set_to_sources(source_set: str) -> List[str]:
    if source_set not in SOURCE_SETS:
        raise SystemExit(f"Unsupported source_set={source_set!r}. Choose one of: {sorted(SOURCE_SETS)}")
    return SOURCE_SETS[source_set]


def hours_to_seconds(hours: float) -> int:
    return int(round(float(hours) * 3600.0))


def merge_time_intervals(intervals: Sequence[TimeInterval]) -> List[TimeInterval]:
    cleaned = sorted((max(0, int(start)), int(end)) for start, end in intervals if int(end) >= int(start))
    if not cleaned:
        return []

    merged: List[TimeInterval] = []
    current_start, current_end = cleaned[0]
    for start, end in cleaned[1:]:
        if start <= current_end + 1:
            current_end = max(current_end, end)
        else:
            merged.append((current_start, current_end))
            current_start, current_end = start, end
    merged.append((current_start, current_end))
    return merged


def intersect_intervals_with_bounds(intervals: Sequence[TimeInterval], time_min: int | None, time_max: int | None) -> List[TimeInterval]:
    bounded: List[TimeInterval] = []
    for start, end in intervals:
        if time_min is not None:
            start = max(start, int(time_min))
        if time_max is not None:
            end = min(end, int(time_max))
        if end >= start:
            bounded.append((start, end))
    return merge_time_intervals(bounded)


def read_redteam_event_times(input_dir: Path) -> List[int]:
    path = input_dir / SOURCE_FILES["redteam"]
    if not path.exists():
        raise SystemExit(f"Missing CSR-LANL source file: {path}")
    df = pd.read_csv(path, compression="gzip", header=None, names=SOURCE_SCHEMAS["redteam"], dtype=str, na_filter=False)
    times = pd.to_numeric(df["time"], errors="coerce").dropna().astype(np.int64).tolist()
    return sorted(int(value) for value in times)


def derive_time_intervals(args: argparse.Namespace, input_dir: Path) -> List[TimeInterval] | None:
    intervals: List[TimeInterval] = []

    if args.time_window_hours is not None:
        duration_seconds = hours_to_seconds(args.time_window_hours)
        if args.time_min is None:
            redteam_times = read_redteam_event_times(input_dir)
            if not redteam_times:
                raise SystemExit("--time_window_hours without --time_min requires at least one redteam event")
            anchor = int(redteam_times[0])
            print(f"Time window : --time_min not provided; using first redteam time {anchor:,} as anchor", flush=True)
        else:
            anchor = int(args.time_min)
        intervals.append((anchor, anchor + duration_seconds - 1))

    if args.redteam_window_hours is not None:
        radius_seconds = hours_to_seconds(args.redteam_window_hours)
        redteam_times = [
            int(value)
            for value in read_redteam_event_times(input_dir)
            if (args.time_min is None or int(value) >= int(args.time_min)) and (args.time_max is None or int(value) <= int(args.time_max))
        ]
        if args.redteam_window_limit > 0:
            redteam_times = redteam_times[: args.redteam_window_limit]
        if not redteam_times:
            raise SystemExit("No redteam events available for --redteam_window_hours after applying optional time bounds")
        intervals.extend((event_time - radius_seconds, event_time + radius_seconds) for event_time in redteam_times)

    if not intervals:
        return None

    effective = intersect_intervals_with_bounds(merge_time_intervals(intervals), args.time_min, args.time_max)
    if not effective:
        raise SystemExit("The derived hour windows are empty after applying time bounds")
    return effective


def format_time_intervals(intervals: Sequence[TimeInterval], max_items: int = 5) -> str:
    shown = [f"[{start:,}, {end:,}]" for start, end in intervals[:max_items]]
    suffix = "" if len(intervals) <= max_items else f" ... (+{len(intervals) - max_items} more)"
    return ", ".join(shown) + suffix


def interval_mask(event_time: pd.Series, intervals: Sequence[TimeInterval]) -> pd.Series:
    mask = pd.Series(False, index=event_time.index)
    chunk_min = event_time.min() if event_time.notna().any() else None
    chunk_max = event_time.max() if event_time.notna().any() else None
    for start, end in intervals:
        if chunk_max is not None and chunk_max < start:
            break
        if chunk_min is not None and chunk_min > end:
            continue
        mask |= (event_time >= start) & (event_time <= end)
    return mask


def progress_interval_hit(chunks_seen: int, rows_seen: int, last_report_rows: int, every_chunks: int, every_rows: int) -> bool:
    if chunks_seen == 1:
        return True
    if every_chunks > 0 and chunks_seen % every_chunks == 0:
        return True
    if every_rows > 0 and rows_seen - last_report_rows >= every_rows:
        return True
    return False


def print_scan_progress(
    source: str,
    chunks_seen: int,
    rows_seen: int,
    rows_kept: int,
    chunk_time_min: int | None,
    chunk_time_max: int | None,
    elapsed_seconds: float,
    suffix: str = "",
) -> None:
    time_part = ""
    if chunk_time_min is not None and chunk_time_max is not None:
        time_part = f" chunk_time=[{chunk_time_min:,}, {chunk_time_max:,}]"
    message = (
        f"[{source}] scan chunks={chunks_seen:,} raw_rows={rows_seen:,} "
        f"kept_rows={rows_kept:,}{time_part} elapsed={elapsed_seconds:,.1f}s"
    )
    if suffix:
        message = f"{message} {suffix}"
    print(message, flush=True)


def empty_acc(window_start: int, window_seconds: int, entity: str) -> Dict[str, Any]:
    acc: Dict[str, Any] = {name: 0.0 for name in FEATURE_COLUMNS}
    acc.update(
        {
            "window_start": int(window_start),
            "window_end": int(window_start + window_seconds),
            "entity": entity,
            "_src_users": set(),
            "_dst_users": set(),
            "_auth_dst_computers": set(),
            "_auth_types": set(),
            "_logon_types": set(),
            "_flow_dst_computers": set(),
            "_flow_dst_ports": set(),
            "_dns_dst_computers": set(),
            "_proc_users": set(),
            "_processes": set(),
        }
    )
    return acc


def get_acc(accumulators: MutableMapping[Tuple[int, str], Dict[str, Any]], window_start: int, window_seconds: int, entity: str) -> Dict[str, Any]:
    key = (int(window_start), entity)
    if key not in accumulators:
        accumulators[key] = empty_acc(int(window_start), window_seconds, entity)
    return accumulators[key]


def iter_source_chunks(
    input_dir: Path,
    source: str,
    chunksize: int,
    max_rows: int | None,
    time_min: int | None,
    time_max: int | None,
    time_intervals: Sequence[TimeInterval] | None = None,
    show_progress: bool = True,
    progress_every_chunks: int = 4,
    progress_every_rows: int = 1_000_000,
) -> Iterable[pd.DataFrame]:
    path = input_dir / SOURCE_FILES[source]
    if not path.exists():
        raise SystemExit(f"Missing CSR-LANL source file: {path}")

    names = SOURCE_SCHEMAS[source]
    effective_time_min = time_intervals[0][0] if time_intervals else time_min
    effective_time_max = time_intervals[-1][1] if time_intervals else time_max
    started_at = time.monotonic()
    chunks_seen = 0
    rows_seen = 0
    rows_yielded = 0
    last_report_rows = 0

    if show_progress:
        print(f"[{source}] starting scan: {path.name}", flush=True)

    for chunk in pd.read_csv(
        path,
        compression="gzip",
        header=None,
        names=names,
        dtype=str,
        chunksize=chunksize,
        na_filter=False,
    ):
        chunks_seen += 1
        rows_seen += int(len(chunk))
        event_time = safe_numeric(chunk["time"])
        chunk_time_min = int(event_time.min()) if event_time.notna().any() else None
        chunk_time_max = int(event_time.max()) if event_time.notna().any() else None

        if show_progress and progress_interval_hit(chunks_seen, rows_seen, last_report_rows, progress_every_chunks, progress_every_rows):
            print_scan_progress(
                source=source,
                chunks_seen=chunks_seen,
                rows_seen=rows_seen,
                rows_kept=rows_yielded,
                chunk_time_min=chunk_time_min,
                chunk_time_max=chunk_time_max,
                elapsed_seconds=time.monotonic() - started_at,
            )
            last_report_rows = rows_seen

        if effective_time_max is not None and event_time.notna().any() and float(event_time.min()) > float(effective_time_max):
            if show_progress:
                print_scan_progress(
                    source=source,
                    chunks_seen=chunks_seen,
                    rows_seen=rows_seen,
                    rows_kept=rows_yielded,
                    chunk_time_min=chunk_time_min,
                    chunk_time_max=chunk_time_max,
                    elapsed_seconds=time.monotonic() - started_at,
                    suffix="stopped: chunk starts after last requested time window",
                )
            break
        mask = event_time.notna()
        if time_intervals:
            mask &= interval_mask(event_time, time_intervals)
        else:
            if effective_time_min is not None:
                mask &= event_time >= effective_time_min
            if effective_time_max is not None:
                mask &= event_time <= effective_time_max
        if not mask.any():
            continue
        filtered = chunk.loc[mask].copy()
        if max_rows is not None:
            remaining = max_rows - rows_yielded
            if remaining <= 0:
                break
            filtered = filtered.head(remaining).copy()
        filtered["time"] = event_time.loc[mask].astype(np.int64)
        rows_yielded += int(len(filtered))
        yield filtered
        if max_rows is not None and rows_yielded >= max_rows:
            if show_progress:
                print_scan_progress(
                    source=source,
                    chunks_seen=chunks_seen,
                    rows_seen=rows_seen,
                    rows_kept=rows_yielded,
                    chunk_time_min=chunk_time_min,
                    chunk_time_max=chunk_time_max,
                    elapsed_seconds=time.monotonic() - started_at,
                    suffix="stopped: max_rows_per_source reached",
                )
            break

    if show_progress:
        print_scan_progress(
            source=source,
            chunks_seen=chunks_seen,
            rows_seen=rows_seen,
            rows_kept=rows_yielded,
            chunk_time_min=None,
            chunk_time_max=None,
            elapsed_seconds=time.monotonic() - started_at,
            suffix="done",
        )


def update_auth(accumulators: MutableMapping[Tuple[int, str], Dict[str, Any]], chunk: pd.DataFrame, window_seconds: int) -> int:
    chunk = chunk.copy()
    chunk["entity"] = clean_series(chunk["src_computer"], default="")
    chunk = chunk[chunk["entity"] != ""]
    if chunk.empty:
        return 0
    chunk["window_start"] = (chunk["time"] // window_seconds) * window_seconds
    chunk["result_norm"] = lower_clean_series(chunk["result"])
    chunk["orient_norm"] = lower_clean_series(chunk["auth_orient"])
    chunk["logon_norm"] = lower_clean_series(chunk["logon_type"], default="unknown")
    chunk["auth_type_norm"] = lower_clean_series(chunk["auth_type"], default="unknown")
    chunk["src_user_norm"] = clean_series(chunk["src_user"], default="")
    chunk["dst_user_norm"] = clean_series(chunk["dst_user"], default="")
    chunk["dst_computer_norm"] = clean_series(chunk["dst_computer"], default="")

    for (window_start, entity), group in chunk.groupby(["window_start", "entity"], sort=False):
        acc = get_acc(accumulators, int(window_start), window_seconds, str(entity))
        count = int(len(group))
        acc["auth_event_count"] += count
        acc["auth_success_count"] += int((group["result_norm"] == "success").sum())
        acc["auth_fail_count"] += int((group["result_norm"] == "fail").sum())
        acc["auth_logon_count"] += int((group["orient_norm"] == "logon").sum())
        acc["auth_logoff_count"] += int((group["orient_norm"] == "logoff").sum())
        acc["auth_tgs_count"] += int((group["orient_norm"] == "tgs").sum())
        acc["auth_tgt_count"] += int((group["orient_norm"] == "tgt").sum())
        acc["auth_authmap_count"] += int((group["orient_norm"] == "authmap").sum())
        acc["auth_network_logon_count"] += int((group["logon_norm"] == "network").sum())
        acc["auth_interactive_logon_count"] += int((group["logon_norm"] == "interactive").sum())
        acc["auth_service_logon_count"] += int((group["logon_norm"] == "service").sum())
        acc["auth_batch_logon_count"] += int((group["logon_norm"] == "batch").sum())
        acc["machine_account_count"] += int(group["src_user_norm"].map(is_machine_account).sum())
        acc["anonymous_logon_count"] += int(group["src_user_norm"].str.upper().str.startswith("ANONYMOUS LOGON").sum())
        acc["_src_users"].update(v for v in group["src_user_norm"] if v)
        acc["_dst_users"].update(v for v in group["dst_user_norm"] if v)
        acc["_auth_dst_computers"].update(v for v in group["dst_computer_norm"] if v)
        acc["_auth_types"].update(v for v in group["auth_type_norm"] if v and v != "unknown")
        acc["_logon_types"].update(v for v in group["logon_norm"] if v and v != "unknown")
    return int(len(chunk))


def update_flows(accumulators: MutableMapping[Tuple[int, str], Dict[str, Any]], chunk: pd.DataFrame, window_seconds: int) -> int:
    chunk = chunk.copy()
    chunk["entity"] = clean_series(chunk["src_computer"], default="")
    chunk = chunk[chunk["entity"] != ""]
    if chunk.empty:
        return 0
    chunk["window_start"] = (chunk["time"] // window_seconds) * window_seconds
    chunk["duration_num"] = safe_numeric(chunk["duration"]).fillna(0.0)
    chunk["packet_num"] = safe_numeric(chunk["packet_count"]).fillna(0.0)
    chunk["byte_num"] = safe_numeric(chunk["byte_count"]).fillna(0.0)
    chunk["dst_port_num"] = safe_numeric(chunk["dst_port"])
    chunk["protocol_norm"] = lower_clean_series(chunk["protocol"], default="unknown")
    chunk["dst_computer_norm"] = clean_series(chunk["dst_computer"], default="")

    for (window_start, entity), group in chunk.groupby(["window_start", "entity"], sort=False):
        acc = get_acc(accumulators, int(window_start), window_seconds, str(entity))
        count = int(len(group))
        durations = group["duration_num"].to_numpy(dtype=np.float64)
        packets = group["packet_num"].to_numpy(dtype=np.float64)
        bytes_ = group["byte_num"].to_numpy(dtype=np.float64)
        dst_ports = group["dst_port_num"]
        acc["flow_event_count"] += count
        acc["flow_duration_sum"] += float(np.sum(durations))
        acc["flow_duration_max"] = max(float(acc["flow_duration_max"]), float(np.max(durations)) if len(durations) else 0.0)
        acc["flow_packet_sum"] += float(np.sum(packets))
        acc["flow_byte_sum"] += float(np.sum(bytes_))
        acc["flow_tcp_count"] += int((group["protocol_norm"] == "tcp").sum())
        acc["flow_udp_count"] += int((group["protocol_norm"] == "udp").sum())
        acc["flow_icmp_count"] += int((group["protocol_norm"] == "icmp").sum())
        acc["flow_privileged_dst_port_count"] += int(((dst_ports > 0) & (dst_ports < 1024)).sum())
        acc["_flow_dst_computers"].update(v for v in group["dst_computer_norm"] if v)
        acc["_flow_dst_ports"].update(str(int(v)) for v in dst_ports.dropna().tolist())
    return int(len(chunk))


def update_dns(accumulators: MutableMapping[Tuple[int, str], Dict[str, Any]], chunk: pd.DataFrame, window_seconds: int) -> int:
    chunk = chunk.copy()
    chunk["entity"] = clean_series(chunk["src_computer"], default="")
    chunk = chunk[chunk["entity"] != ""]
    if chunk.empty:
        return 0
    chunk["window_start"] = (chunk["time"] // window_seconds) * window_seconds
    chunk["dst_computer_norm"] = clean_series(chunk["dst_computer"], default="")
    for (window_start, entity), group in chunk.groupby(["window_start", "entity"], sort=False):
        acc = get_acc(accumulators, int(window_start), window_seconds, str(entity))
        acc["dns_event_count"] += int(len(group))
        acc["_dns_dst_computers"].update(v for v in group["dst_computer_norm"] if v)
    return int(len(chunk))


def update_proc(accumulators: MutableMapping[Tuple[int, str], Dict[str, Any]], chunk: pd.DataFrame, window_seconds: int) -> int:
    chunk = chunk.copy()
    chunk["entity"] = clean_series(chunk["computer"], default="")
    chunk = chunk[chunk["entity"] != ""]
    if chunk.empty:
        return 0
    chunk["window_start"] = (chunk["time"] // window_seconds) * window_seconds
    chunk["user_norm"] = clean_series(chunk["user"], default="")
    chunk["process_norm"] = clean_series(chunk["process"], default="")
    chunk["event_norm"] = lower_clean_series(chunk["event_type"], default="unknown")
    for (window_start, entity), group in chunk.groupby(["window_start", "entity"], sort=False):
        acc = get_acc(accumulators, int(window_start), window_seconds, str(entity))
        acc["proc_event_count"] += int(len(group))
        acc["proc_start_count"] += int(group["event_norm"].str.contains("start", regex=False).sum())
        acc["proc_end_count"] += int(group["event_norm"].str.contains("end", regex=False).sum())
        acc["_proc_users"].update(v for v in group["user_norm"] if v)
        acc["_processes"].update(v for v in group["process_norm"] if v)
    return int(len(chunk))


def load_redteam(
    input_dir: Path,
    window_seconds: int,
    time_min: int | None,
    time_max: int | None,
    time_intervals: Sequence[TimeInterval] | None,
    show_progress: bool,
    progress_every_chunks: int,
    progress_every_rows: int,
) -> Dict[str, Any]:
    exact: set[Tuple[int, str]] = set()
    roles: Dict[Tuple[int, str], set[str]] = defaultdict(set)
    event_rows = 0
    unique_events: set[Tuple[int, str, str, str]] = set()

    for chunk in iter_source_chunks(
        input_dir,
        "redteam",
        chunksize=100_000,
        max_rows=None,
        time_min=time_min,
        time_max=time_max,
        time_intervals=time_intervals,
        show_progress=show_progress,
        progress_every_chunks=progress_every_chunks,
        progress_every_rows=progress_every_rows,
    ):
        chunk = chunk.copy()
        chunk["window_start"] = (chunk["time"] // window_seconds) * window_seconds
        chunk["src_computer_norm"] = clean_series(chunk["src_computer"], default="")
        chunk["dst_computer_norm"] = clean_series(chunk["dst_computer"], default="")
        chunk["user_norm"] = clean_series(chunk["user"], default="")
        for row in chunk.itertuples(index=False):
            event_rows += 1
            src = str(row.src_computer_norm)
            dst = str(row.dst_computer_norm)
            user = str(row.user_norm)
            window = int(row.window_start)
            unique_events.add((int(row.time), user, src, dst))
            if src:
                key = (window, src)
                exact.add(key)
                roles[key].add("src")
            if dst:
                key = (window, dst)
                exact.add(key)
                roles[key].add("dst")

    return {"exact": exact, "roles": roles, "event_rows": event_rows, "unique_events": unique_events}


def redteam_near_lookup(exact: set[Tuple[int, str]], exclusion_windows: int, window_seconds: int) -> set[Tuple[int, str]]:
    if exclusion_windows <= 0:
        return set(exact)
    near: set[Tuple[int, str]] = set()
    for window_start, entity in exact:
        for offset in range(-exclusion_windows, exclusion_windows + 1):
            near.add((int(window_start + offset * window_seconds), entity))
    return near


def evidence_class(row: pd.Series) -> str:
    if not bool(row["redteam_exact"]):
        return "BENIGN"
    families = str(row["source_families"]).split("+") if row["source_families"] else []
    families = [family for family in families if family]
    if len(families) > 1:
        return "RedTeamMixed"
    if families == ["auth"]:
        return "RedTeamAuth"
    if families == ["flows"]:
        return "RedTeamFlow"
    if families == ["dns"]:
        return "RedTeamDNS"
    if families == ["proc"]:
        return "RedTeamProcess"
    return "RedTeamOther"


def build_category_map(values: Sequence[str]) -> Dict[str, int]:
    mapping = {"Unknown": 0}
    for value in sorted({clean_text(v) for v in values}):
        if value not in mapping:
            mapping[value] = len(mapping)
    return mapping


def finalize_windows(
    accumulators: MutableMapping[Tuple[int, str], Dict[str, Any]],
    redteam: Dict[str, Any],
    window_seconds: int,
    exclusion_windows: int,
) -> tuple[pd.DataFrame, Dict[str, Dict[str, int]], Dict[str, Any]]:
    exact = redteam["exact"]
    near = redteam_near_lookup(exact, exclusion_windows, window_seconds)
    rows: List[Dict[str, Any]] = []
    seen_src_users_by_entity: Dict[str, set[str]] = defaultdict(set)
    seen_dst_computers_by_entity: Dict[str, set[str]] = defaultdict(set)
    seen_processes_by_entity: Dict[str, set[str]] = defaultdict(set)
    matched_exact: set[Tuple[int, str]] = set()

    for key in sorted(accumulators):
        window_start, entity = key
        acc = accumulators[key]
        src_users = acc["_src_users"]
        dst_computers = set(acc["_auth_dst_computers"]) | set(acc["_flow_dst_computers"]) | set(acc["_dns_dst_computers"])
        processes = acc["_processes"]
        row: Dict[str, Any] = {name: float(acc.get(name, 0.0)) for name in FEATURE_COLUMNS}
        row["window_start"] = int(window_start)
        row["window_end"] = int(acc["window_end"])
        row["entity"] = entity
        row["unique_src_user_count"] = float(len(src_users))
        row["unique_dst_user_count"] = float(len(acc["_dst_users"]))
        row["auth_unique_dst_computer_count"] = float(len(acc["_auth_dst_computers"]))
        row["auth_type_unique_count"] = float(len(acc["_auth_types"]))
        row["logon_type_unique_count"] = float(len(acc["_logon_types"]))
        row["flow_unique_dst_computer_count"] = float(len(acc["_flow_dst_computers"]))
        row["flow_unique_dst_port_count"] = float(len(acc["_flow_dst_ports"]))
        row["dns_unique_dst_computer_count"] = float(len(acc["_dns_dst_computers"]))
        row["proc_unique_user_count"] = float(len(acc["_proc_users"]))
        row["proc_unique_process_count"] = float(len(processes))

        auth_count = float(row["auth_event_count"])
        flow_count = float(row["flow_event_count"])
        proc_count = float(row["proc_event_count"])
        row["auth_failure_ratio"] = float(row["auth_fail_count"] / auth_count) if auth_count else 0.0
        row["flow_duration_mean"] = float(row["flow_duration_sum"] / flow_count) if flow_count else 0.0
        row["flow_byte_mean"] = float(row["flow_byte_sum"] / flow_count) if flow_count else 0.0
        row["total_event_count"] = auth_count + flow_count + float(row["dns_event_count"]) + proc_count
        row["active_source_count"] = float(sum(1 for count in [auth_count, flow_count, row["dns_event_count"], proc_count] if float(count) > 0))
        row["auth_to_flow_ratio"] = float(auth_count / flow_count) if flow_count else auth_count
        row["fail_to_flow_ratio"] = float(row["auth_fail_count"] / flow_count) if flow_count else float(row["auth_fail_count"])
        row["proc_to_auth_ratio"] = float(proc_count / auth_count) if auth_count else proc_count
        row["has_new_src_user"] = float(bool(src_users - seen_src_users_by_entity[entity]))
        row["has_new_dst_computer"] = float(bool(dst_computers - seen_dst_computers_by_entity[entity]))
        row["has_new_process"] = float(bool(processes - seen_processes_by_entity[entity]))
        seen_src_users_by_entity[entity].update(src_users)
        seen_dst_computers_by_entity[entity].update(dst_computers)
        seen_processes_by_entity[entity].update(processes)

        row["day_index"] = float(int(window_start // 86400))
        row["hour_index"] = float(int(window_start // 3600))
        row["minute_of_day"] = float(int((window_start % 86400) // 60))
        redteam_exact = key in exact
        redteam_near = key in near
        if redteam_exact:
            matched_exact.add(key)
        families = []
        if auth_count:
            families.append("auth")
        if flow_count:
            families.append("flows")
        if row["dns_event_count"]:
            families.append("dns")
        if proc_count:
            families.append("proc")
        row["source_families"] = "+".join(families)
        row["redteam_exact"] = bool(redteam_exact)
        row["redteam_near"] = bool(redteam_near)
        row["redteam_roles"] = "+".join(sorted(redteam["roles"].get(key, set()))) if redteam_exact else ""
        row["binary_target"] = "ATTACK" if redteam_exact else "BENIGN"
        rows.append(row)

    if not rows:
        raise SystemExit("No CSR-LANL windows were generated. Check source_set, time filters, and max_rows_per_source.")

    df = pd.DataFrame(rows).sort_values(["window_start", "entity"]).reset_index(drop=True)
    df["multiclass_target"] = df.apply(evidence_class, axis=1)
    df["multiclass_target_raw"] = df["multiclass_target"].astype(str)
    maps = {"entity": build_category_map(df["entity"].astype(str).tolist())}
    for column in FEATURE_COLUMNS:
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0.0).astype(np.float32)

    redteam_policy = {
        "redteam_rows_read": int(redteam["event_rows"]),
        "redteam_unique_events": int(len(redteam["unique_events"])),
        "redteam_entity_windows": int(len(exact)),
        "matched_redteam_entity_windows": int(len(matched_exact)),
        "unmatched_redteam_entity_windows": int(max(0, len(exact) - len(matched_exact))),
        "exclusion_windows_each_side": int(exclusion_windows),
        "window_seconds": int(window_seconds),
        "label_policy": "ATTACK when an aggregated entity-window exactly matches redteam time/entity; BENIGN otherwise. Near redteam windows are excluded from anomaly train.",
    }
    return df, maps, redteam_policy


def collapse_rare_multiclass(df: pd.DataFrame, min_windows: int) -> Dict[str, int]:
    if min_windows <= 1:
        return {}
    counts = count_labels(df["multiclass_target"])
    rare = {label: count for label, count in counts.items() if label != "BENIGN" and count < min_windows}
    if rare:
        df.loc[df["multiclass_target"].isin(set(rare)), "multiclass_target"] = "RedTeamOther"
    return rare


def count_labels(values: Sequence[object]) -> Dict[str, int]:
    counts = pd.Series(list(map(str, values)), dtype=object).value_counts(dropna=False)
    return {str(key): int(value) for key, value in counts.items()}


def stratified_random_split(df: pd.DataFrame, seed: int, train_ratio: float, val_ratio: float) -> Dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    assignments: Dict[str, List[int]] = {split: [] for split in SPLITS}
    for _, group in df.groupby("binary_target", sort=True):
        indices = group.index.to_numpy(copy=True)
        rng.shuffle(indices)
        n = len(indices)
        if n < 3:
            assignments["train"].extend(indices.tolist())
            continue
        n_train = max(1, int(round(n * train_ratio)))
        n_val = max(1, int(round(n * val_ratio))) if n - n_train >= 2 else max(0, n - n_train)
        n_train = min(n_train, n)
        n_val = min(n_val, max(0, n - n_train))
        assignments["train"].extend(indices[:n_train].tolist())
        assignments["val"].extend(indices[n_train : n_train + n_val].tolist())
        assignments["test"].extend(indices[n_train + n_val :].tolist())
    return {split: np.array(sorted(values), dtype=int) for split, values in assignments.items()}


def date_split(df: pd.DataFrame, train_ratio: float, val_ratio: float) -> Dict[str, np.ndarray]:
    ordered_windows = np.array(sorted(df["window_start"].drop_duplicates().tolist()))
    if len(ordered_windows) < 3:
        raise SystemExit("Need at least three distinct windows for date split")
    train_end = max(1, int(round(len(ordered_windows) * train_ratio)))
    val_end = max(train_end + 1, int(round(len(ordered_windows) * (train_ratio + val_ratio))))
    val_end = min(val_end, len(ordered_windows) - 1)
    train_windows = set(ordered_windows[:train_end])
    val_windows = set(ordered_windows[train_end:val_end])
    test_windows = set(ordered_windows[val_end:])
    return {
        "train": df.index[df["window_start"].isin(train_windows)].to_numpy(dtype=int),
        "val": df.index[df["window_start"].isin(val_windows)].to_numpy(dtype=int),
        "test": df.index[df["window_start"].isin(test_windows)].to_numpy(dtype=int),
    }


def groupkfold_split(df: pd.DataFrame, fold: int, n_folds: int) -> Dict[str, np.ndarray]:
    groups = sorted(df["entity"].astype(str).unique().tolist())
    if len(groups) < 3:
        raise SystemExit("Need at least three entities for groupkfold split")
    n = min(n_folds, len(groups))
    mapped = fold % n
    test_group = groups[mapped]
    val_group = groups[(mapped + 1) % n]
    train_groups = set(groups) - {test_group, val_group}
    return {
        "train": df.index[df["entity"].isin(train_groups)].to_numpy(dtype=int),
        "val": df.index[df["entity"] == val_group].to_numpy(dtype=int),
        "test": df.index[df["entity"] == test_group].to_numpy(dtype=int),
    }


def update_stats(stats: Stats, counts: Dict[str, int], binary_view: bool) -> None:
    assert stats.label_counts is not None
    stats.rows += int(sum(counts.values()))
    for key, value in counts.items():
        stats.label_counts[key] = stats.label_counts.get(key, 0) + int(value)
    if binary_view:
        stats.benign += int(counts.get("BENIGN", 0))
        stats.attack += int(counts.get("ATTACK", 0))
    else:
        stats.benign += int(counts.get("BENIGN", 0))
        stats.attack += int(sum(value for key, value in counts.items() if key != "BENIGN"))


def write_stats(base_dir: Path, stats: Dict[str, Dict[str, Stats]]) -> None:
    for pipeline_name, split_stats in stats.items():
        payload: Dict[str, Any] = {}
        for split_name, stat in split_stats.items():
            payload[split_name] = {
                "rows": stat.rows,
                "benign": stat.benign,
                "attack": stat.attack,
                "label_counts": dict(sorted((stat.label_counts or {}).items(), key=lambda item: item[1], reverse=True)),
            }
        write_json(base_dir / pipeline_name / "stats.json", payload)


def write_label_map(path: Path, labels: Sequence[str], binary: bool) -> None:
    ordered = sorted(set(map(str, labels)))
    if binary and {"BENIGN", "ATTACK"}.issubset(set(ordered)):
        ordered = ["BENIGN", "ATTACK"]
    write_json(path, {label: index for index, label in enumerate(ordered)})


def frame_for_target(df: pd.DataFrame, target_column: str) -> pd.DataFrame:
    columns = FEATURE_COLUMNS + META_COLUMNS
    out = df.loc[:, columns].copy()
    out["target"] = df[target_column].astype(str).to_numpy(copy=True)
    return out


def write_parquet_split(base_dir: Path, pipeline: str, split_name: str, df: pd.DataFrame) -> None:
    if df.empty:
        return
    folder = base_dir / pipeline / split_name
    folder.mkdir(parents=True, exist_ok=True)
    df.to_parquet(folder / "part-00000.parquet", index=False)


def materialize(base_dir: Path, df: pd.DataFrame, split_indices: Dict[str, np.ndarray]) -> Dict[str, Dict[str, Stats]]:
    stats: Dict[str, Dict[str, Stats]] = {
        "binary": {split: Stats() for split in SPLITS},
        "multiclass": {split: Stats() for split in SPLITS},
        "anomaly": {split: Stats() for split in SPLITS},
    }

    for split_name, indices in split_indices.items():
        split_df = df.loc[indices].copy()
        if split_df.empty:
            raise SystemExit(f"Split {split_name} is empty")

        binary_df = frame_for_target(split_df, "binary_target")
        write_parquet_split(base_dir, "binary", split_name, binary_df)
        update_stats(stats["binary"][split_name], count_labels(binary_df["target"]), binary_view=True)

        multiclass_df = frame_for_target(split_df, "multiclass_target")
        write_parquet_split(base_dir, "multiclass", split_name, multiclass_df)
        update_stats(stats["multiclass"][split_name], count_labels(multiclass_df["target"]), binary_view=False)

        if split_name == "train":
            anomaly_source = split_df[(split_df["binary_target"] == "BENIGN") & (~split_df["redteam_near"].astype(bool))]
        else:
            anomaly_source = split_df
        anomaly_dir = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}[split_name]
        anomaly_df = frame_for_target(anomaly_source, "binary_target")
        write_parquet_split(base_dir, "anomaly", anomaly_dir, anomaly_df)
        update_stats(stats["anomaly"][split_name], count_labels(anomaly_df["target"]), binary_view=True)

    if stats["anomaly"]["train"].rows == 0:
        raise SystemExit("Anomaly train split has no eligible benign windows")

    write_label_map(base_dir / "binary" / "label_map.json", df["binary_target"].astype(str).unique(), binary=True)
    write_label_map(base_dir / "multiclass" / "label_map.json", df["multiclass_target"].astype(str).unique(), binary=False)
    write_stats(base_dir, stats)
    return stats


def split_policy_payload(split_mode: str, split_indices: Dict[str, np.ndarray], df: pd.DataFrame, group_key: str) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"split_mode": split_mode, "group_key": group_key, "splits": {}}
    for split_name, indices in split_indices.items():
        split_df = df.loc[indices]
        payload["splits"][split_name] = {
            "rows": int(len(split_df)),
            "window_start_min": None if split_df.empty else int(split_df["window_start"].min()),
            "window_start_max": None if split_df.empty else int(split_df["window_start"].max()),
            "binary_counts": count_labels(split_df["binary_target"]),
            "multiclass_counts": count_labels(split_df["multiclass_target"]),
            "redteam_exact_windows": int(split_df["redteam_exact"].sum()) if not split_df.empty else 0,
            "entities": int(split_df["entity"].nunique()) if not split_df.empty else 0,
        }
    return payload


def write_dataset_metadata(
    base_dir: Path,
    df: pd.DataFrame,
    maps: Dict[str, Dict[str, int]],
    args: argparse.Namespace,
    split_mode: str,
    split_indices: Dict[str, np.ndarray],
    rare_classes: Dict[str, int],
    source_counts: Dict[str, int],
    redteam_policy: Dict[str, Any],
) -> None:
    write_json(base_dir / "feature_columns.json", FEATURE_COLUMNS)
    write_json(base_dir / "category_maps.json", maps)
    write_json(base_dir / "source_manifest.json", {"source_set": args.source_set, "sources": source_set_to_sources(args.source_set), "rows_read": source_counts})
    write_json(base_dir / "redteam_policy.json", redteam_policy)
    write_json(base_dir / "split_policy.json", split_policy_payload(split_mode, split_indices, df, group_key="entity"))
    write_json(
        base_dir / "prepare_dataset_summary.json",
        {
            "dataset": args.dataset,
            "input_dir": str(resolve_from_root(args.in_dir)),
            "rows": int(len(df)),
            "window_seconds": int(args.window_seconds),
            "source_set": args.source_set,
            "time_min": args.time_min,
            "time_max": args.time_max,
            "time_window_hours": args.time_window_hours,
            "redteam_window_hours": args.redteam_window_hours,
            "redteam_window_limit": args.redteam_window_limit,
            "effective_time_intervals": getattr(args, "effective_time_intervals", None),
            "max_rows_per_source": args.max_rows_per_source,
            "min_multiclass_windows": args.min_multiclass_windows,
            "collapsed_multiclass_classes": rare_classes,
            "binary_counts": count_labels(df["binary_target"]),
            "multiclass_counts": count_labels(df["multiclass_target"]),
            "feature_count": len(FEATURE_COLUMNS),
        },
    )


def build_split_indices(df: pd.DataFrame, args: argparse.Namespace, split_mode: str, fold: int | None = None) -> Dict[str, np.ndarray]:
    if split_mode == "random":
        return stratified_random_split(df, args.seed, args.train_ratio, args.val_ratio)
    if split_mode == "date":
        return date_split(df, args.train_ratio, args.val_ratio)
    if split_mode == "groupkfold":
        return groupkfold_split(df, int(fold or 0), args.n_folds)
    raise ValueError(f"Unsupported split mode: {split_mode}")


def prepare_mode(
    df: pd.DataFrame,
    maps: Dict[str, Dict[str, int]],
    args: argparse.Namespace,
    split_mode: str,
    rare_classes: Dict[str, int],
    source_counts: Dict[str, int],
    redteam_policy: Dict[str, Any],
    fold: int | None = None,
) -> None:
    out_base = resolve_from_root(args.out_dir) / split_mode / args.dataset
    if split_mode == "groupkfold":
        out_base = out_base / f"fold_{fold}"
    clear_dir(out_base)
    split_indices = build_split_indices(df, args, split_mode, fold=fold)
    materialize(out_base, df, split_indices)
    write_dataset_metadata(out_base, df, maps, args, split_mode, split_indices, rare_classes, source_counts, redteam_policy)
    print(f"Prepared {split_mode}{'' if fold is None else f' fold_{fold}'}: {out_base}")


def normalize_modes(values: List[str]) -> List[str]:
    modes: List[str] = []
    for value in values:
        for part in str(value).split(","):
            candidate = part.strip().lower()
            if not candidate:
                continue
            if candidate == "all":
                modes.extend(["date", "random", "groupkfold"])
            elif candidate in {"date", "random", "groupkfold"}:
                modes.append(candidate)
            else:
                raise SystemExit(f"Invalid split mode: {candidate}")
    return list(dict.fromkeys(modes))


def build_windows(args: argparse.Namespace) -> tuple[pd.DataFrame, Dict[str, Dict[str, int]], Dict[str, int], Dict[str, Any]]:
    input_dir = resolve_from_root(args.in_dir)
    sources = source_set_to_sources(args.source_set)
    accumulators: Dict[Tuple[int, str], Dict[str, Any]] = {}
    source_counts: Dict[str, int] = {}
    show_progress = not args.no_progress
    time_intervals = derive_time_intervals(args, input_dir)
    args.effective_time_intervals = time_intervals

    if time_intervals:
        total_seconds = sum(end - start + 1 for start, end in time_intervals)
        print(
            f"Hour windows : {len(time_intervals):,} interval(s), total_hours={total_seconds / 3600.0:,.2f}; "
            f"{format_time_intervals(time_intervals)}",
            flush=True,
        )

    redteam = load_redteam(
        input_dir,
        args.window_seconds,
        args.time_min,
        args.time_max,
        time_intervals=time_intervals,
        show_progress=show_progress,
        progress_every_chunks=args.progress_every_chunks,
        progress_every_rows=args.progress_every_rows,
    )
    for source in sources:
        total = 0
        filtered_chunks = 0
        if show_progress:
            print(f"[{source}] starting aggregation", flush=True)
        for chunk in iter_source_chunks(
            input_dir,
            source,
            args.chunk_size,
            args.max_rows_per_source,
            args.time_min,
            args.time_max,
            time_intervals=time_intervals,
            show_progress=show_progress,
            progress_every_chunks=args.progress_every_chunks,
            progress_every_rows=args.progress_every_rows,
        ):
            if source == "auth":
                total += update_auth(accumulators, chunk, args.window_seconds)
            elif source == "flows":
                total += update_flows(accumulators, chunk, args.window_seconds)
            elif source == "dns":
                total += update_dns(accumulators, chunk, args.window_seconds)
            elif source == "proc":
                total += update_proc(accumulators, chunk, args.window_seconds)
            else:
                raise SystemExit(f"Unsupported source: {source}")
            filtered_chunks += 1
            if show_progress and (filtered_chunks == 1 or (args.progress_every_chunks > 0 and filtered_chunks % args.progress_every_chunks == 0)):
                print(
                    f"[{source}] aggregate filtered_chunks={filtered_chunks:,} "
                    f"filtered_rows={total:,} windows={len(accumulators):,}",
                    flush=True,
                )
        source_counts[source] = int(total)
        print(f"Read {source:>5}: {total:,} filtered rows; windows={len(accumulators):,}", flush=True)

    df, maps, redteam_policy = finalize_windows(accumulators, redteam, args.window_seconds, args.redteam_exclusion_windows)
    return df, maps, source_counts, redteam_policy


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare CSR-LANL windowed Parquet datasets")
    parser.add_argument("--in_dir", default=str(DEFAULT_IN_DIR))
    parser.add_argument("--out_dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--dataset", default=DATASET_NAME)
    parser.add_argument("--split_mode", nargs="+", default=["date"], help="date, random, groupkfold, all, or comma-separated values")
    parser.add_argument("--source_set", default="auth", choices=sorted(SOURCE_SETS))
    parser.add_argument("--window_seconds", type=int, default=60)
    parser.add_argument("--train_ratio", type=float, default=0.70)
    parser.add_argument("--val_ratio", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n_folds", type=int, default=5)
    parser.add_argument("--fold", type=int, default=0)
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--chunk_size", type=int, default=250_000)
    parser.add_argument("--max_rows_per_source", type=int, default=None)
    parser.add_argument("--time_min", type=int, default=None)
    parser.add_argument("--time_max", type=int, default=None)
    parser.add_argument("--time_window_hours", type=float, default=None, help="Limit processing to N hours starting at --time_min; if --time_min is omitted, the first redteam time is used")
    parser.add_argument("--redteam_window_hours", type=float, default=None, help="Limit processing to +/- N hours around redteam events")
    parser.add_argument("--redteam_window_limit", type=int, default=1, help="Number of redteam events used with --redteam_window_hours; 0 means all matching events")
    parser.add_argument("--redteam_exclusion_windows", type=int, default=1)
    parser.add_argument("--min_multiclass_windows", type=int, default=5)
    parser.add_argument("--no_progress", action="store_true", help="Disable per-source progress messages")
    parser.add_argument("--progress_every_chunks", type=int, default=4, help="Print progress every N raw chunks per source")
    parser.add_argument("--progress_every_rows", type=int, default=1_000_000, help="Print progress every N raw rows scanned per source")
    args = parser.parse_args()

    ensure_pyarrow()
    split_modes = normalize_modes(args.split_mode)
    if args.window_seconds <= 0:
        raise SystemExit("window_seconds must be positive")
    if args.train_ratio <= 0 or args.val_ratio <= 0 or args.train_ratio + args.val_ratio >= 1:
        raise SystemExit("train_ratio and val_ratio must be positive and sum to less than 1")
    if args.progress_every_chunks < 0 or args.progress_every_rows < 0:
        raise SystemExit("progress_every_chunks and progress_every_rows must be zero or positive")
    if args.time_window_hours is not None and args.time_window_hours <= 0:
        raise SystemExit("time_window_hours must be positive")
    if args.redteam_window_hours is not None and args.redteam_window_hours <= 0:
        raise SystemExit("redteam_window_hours must be positive")
    if args.redteam_window_limit < 0:
        raise SystemExit("redteam_window_limit must be zero or positive")
    input_dir = resolve_from_root(args.in_dir)
    if not input_dir.exists() or not input_dir.is_dir():
        raise SystemExit(f"Input directory does not exist: {input_dir}")

    print("== prepare_dataset (CSR-LANL) ==")
    print(f"Input       : {input_dir}")
    print(f"Dataset     : {args.dataset}")
    print(f"Split modes : {split_modes}")
    print(f"Source set  : {args.source_set}")
    print(f"Window sec  : {args.window_seconds}")
    if args.time_min is not None or args.time_max is not None:
        print(f"Time filter : [{args.time_min}, {args.time_max}]")
    if args.time_window_hours is not None:
        print(f"Time window : {args.time_window_hours:g} hour(s) from anchor", flush=True)
    if args.redteam_window_hours is not None:
        limit_text = "all redteam events" if args.redteam_window_limit == 0 else f"first {args.redteam_window_limit} redteam event(s)"
        print(f"Redteam win : +/- {args.redteam_window_hours:g} hour(s) around {limit_text}", flush=True)
    if args.max_rows_per_source is not None:
        print(f"Row cap     : {args.max_rows_per_source:,} per source")
    if not args.no_progress:
        print(f"Progress    : every {args.progress_every_chunks:,} chunks or {args.progress_every_rows:,} raw rows", flush=True)

    windows, maps, source_counts, redteam_policy = build_windows(args)
    rare_classes = collapse_rare_multiclass(windows, args.min_multiclass_windows)
    print(f"Windows     : {len(windows):,}")
    print(f"Binary      : {count_labels(windows['binary_target'])}")
    print(f"Multiclass  : {count_labels(windows['multiclass_target'])}")
    print(f"Redteam     : matched {redteam_policy['matched_redteam_entity_windows']:,}/{redteam_policy['redteam_entity_windows']:,} entity-windows")
    if rare_classes:
        print(f"Collapsed rare multiclass labels into RedTeamOther: {rare_classes}")

    for split_mode in split_modes:
        if split_mode == "groupkfold":
            folds = range(args.n_folds) if args.all_folds else [args.fold]
            mode_root = resolve_from_root(args.out_dir) / split_mode / args.dataset
            mode_root.mkdir(parents=True, exist_ok=True)
            write_json(mode_root / "feature_columns.json", FEATURE_COLUMNS)
            for fold in folds:
                prepare_mode(windows, maps, args, split_mode, rare_classes, source_counts, redteam_policy, fold=int(fold))
        else:
            prepare_mode(windows, maps, args, split_mode, rare_classes, source_counts, redteam_policy)


if __name__ == "__main__":
    main()