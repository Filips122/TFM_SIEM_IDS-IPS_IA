#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import gzip
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

import numpy as np
import pandas as pd


try:
    import pyarrow  # noqa: F401
except Exception:
    pyarrow = None


DEFAULT_IN_FILE = Path("out/COWRIE_FULL/cowrie_full.jsonl.gz")
DEFAULT_OUT_DIR = Path("src/models/COWRIE_FULL/datasets")
DATASET_NAME = "COWRIE_FULL"
SPLITS = ("train", "val", "test")

FEATURE_COLUMNS = [
    "event_count",
    "unique_session_count",
    "unique_sensor_count",
    "unique_dst_ip_count",
    "unique_dst_port_count",
    "unique_src_port_count",
    "connect_count",
    "closed_count",
    "client_version_count",
    "client_kex_count",
    "client_fingerprint_count",
    "client_size_count",
    "client_var_count",
    "session_params_count",
    "log_closed_count",
    "login_failed_count",
    "login_success_count",
    "command_input_count",
    "command_success_count",
    "command_failed_count",
    "file_download_count",
    "file_upload_count",
    "file_download_failed_count",
    "direct_tcpip_request_count",
    "direct_tcpip_data_count",
    "ssh_count",
    "telnet_count",
    "dst_port_22_count",
    "dst_port_23_count",
    "duration_count",
    "duration_sum",
    "duration_mean",
    "duration_max",
    "username_present_count",
    "password_present_count",
    "unique_username_count",
    "unique_password_count",
    "version_present_count",
    "unique_version_count",
    "input_count",
    "input_length_sum",
    "input_length_mean",
    "input_length_max",
    "size_count",
    "size_sum",
    "size_mean",
    "has_new_src_ip",
    "has_new_session",
    "has_new_username",
    "has_new_password",
    "event_hour",
    "event_minute",
    "day_of_week",
    "sensor_code",
    "protocol_code",
    "top_eventid_code",
    "top_dst_port_code",
]

FEATURE_PROFILES = ("full", "operational_no_label_proxy")

LABEL_PROXY_EXCLUSIONS = {
    "connect_count": "Event-id count can proxy the weak-label interaction class.",
    "closed_count": "Event-id count can proxy the weak-label interaction class.",
    "client_version_count": "Client fingerprint event counts are part of weak-label class construction.",
    "client_kex_count": "Client fingerprint event counts are part of weak-label class construction.",
    "client_fingerprint_count": "Client fingerprint event counts are part of weak-label class construction.",
    "client_size_count": "Client fingerprint event counts are part of weak-label class construction.",
    "client_var_count": "Client fingerprint event counts are part of weak-label class construction.",
    "session_params_count": "Session metadata event counts are part of weak-label class construction.",
    "log_closed_count": "Event-id count can proxy the weak-label interaction class.",
    "login_failed_count": "Login failure threshold is part of the weak-label policy.",
    "login_success_count": "Login success directly defines attack interaction depth.",
    "command_input_count": "Command events directly define command-execution labels.",
    "command_success_count": "Command events directly define command-execution labels.",
    "command_failed_count": "Command events directly define command-execution labels.",
    "file_download_count": "File transfer events directly define file-transfer labels.",
    "file_upload_count": "File transfer events directly define file-transfer labels.",
    "file_download_failed_count": "File transfer events directly define file-transfer labels.",
    "direct_tcpip_request_count": "Direct TCP/IP events directly define tunnel/proxy labels.",
    "direct_tcpip_data_count": "Direct TCP/IP events directly define tunnel/proxy labels.",
    "username_present_count": "Credential fields are close proxies for login activity.",
    "password_present_count": "Credential fields are close proxies for login activity.",
    "unique_username_count": "Credential fields are close proxies for login activity.",
    "unique_password_count": "Credential fields are close proxies for login activity.",
    "input_count": "Command input presence is a direct proxy for command execution.",
    "input_length_sum": "Command input length is a direct proxy for command execution.",
    "input_length_mean": "Command input length is a direct proxy for command execution.",
    "input_length_max": "Command input length is a direct proxy for command execution.",
    "has_new_username": "Credential novelty is close to credential activity labels.",
    "has_new_password": "Credential novelty is close to credential activity labels.",
    "top_eventid_code": "Top event id is a direct proxy for the weak-label class.",
}

META_COLUMNS = [
    "window_start",
    "src_ip",
    "top_sensor",
    "top_protocol",
    "top_eventid",
    "top_username",
    "top_dst_ip",
    "top_dst_port",
    "binary_target",
    "multiclass_target_raw",
    "multiclass_target",
]

COMMAND_EVENTIDS = {"cowrie.command.input", "cowrie.command.success", "cowrie.command.failed"}
FILE_EVENTIDS = {"cowrie.session.file_download", "cowrie.session.file_upload", "cowrie.session.file_download.failed"}
DIRECT_TCPIP_EVENTIDS = {"cowrie.direct-tcpip.request", "cowrie.direct-tcpip.data"}
FINGERPRINT_EVENTIDS = {
    "cowrie.client.version",
    "cowrie.client.kex",
    "cowrie.client.fingerprint",
    "cowrie.client.size",
    "cowrie.client.var",
    "cowrie.session.params",
}
SESSION_EVENTIDS = {"cowrie.session.connect", "cowrie.session.closed", "cowrie.log.closed"}


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


def feature_columns_for_profile(profile: str) -> List[str]:
    if profile == "full":
        return list(FEATURE_COLUMNS)
    if profile == "operational_no_label_proxy":
        excluded = set(LABEL_PROXY_EXCLUSIONS)
        return [column for column in FEATURE_COLUMNS if column not in excluded]
    raise ValueError(f"Unsupported feature profile: {profile}")


def feature_profile_payload(profile: str) -> Dict[str, Any]:
    selected = feature_columns_for_profile(profile)
    excluded = {column: reason for column, reason in LABEL_PROXY_EXCLUSIONS.items() if column in FEATURE_COLUMNS and column not in selected}
    return {
        "feature_profile": profile,
        "description": "All engineered COWRIE_FULL features." if profile == "full" else "Operational COWRIE_FULL profile excluding direct weak-label proxy features.",
        "feature_count": len(selected),
        "feature_columns": selected,
        "excluded_feature_count": len(excluded),
        "excluded_features": excluded,
    }


def normalize_text(value: object, default: str = "Unknown") -> str:
    if value is None:
        return default
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return default
    return text


def normalize_optional_text(value: object) -> str:
    return normalize_text(value, default="")


def safe_float(value: object, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        out = float(value)
    except Exception:
        return default
    return out if np.isfinite(out) else default


def top_value(series: pd.Series, default: str = "Unknown") -> str:
    clean = series.map(lambda value: normalize_text(value, default=default))
    clean = clean[clean != default]
    if clean.empty:
        return default
    counts = clean.value_counts(sort=True)
    return str(counts.index[0])


def count_labels(values: Sequence[object]) -> Dict[str, int]:
    counts = pd.Series(list(map(str, values)), dtype=object).value_counts(dropna=False)
    return {str(key): int(value) for key, value in counts.items()}


def build_category_map(values: Iterable[object]) -> Dict[str, int]:
    mapping = {"Unknown": 0}
    for value in sorted({normalize_text(value) for value in values}):
        if value not in mapping:
            mapping[value] = len(mapping)
    return mapping


def open_text_input(path: Path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def parse_jsonl(input_file: Path, max_events: int | None = None) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    bad_lines = 0

    with open_text_input(input_file) as handle:
        for line_number, line in enumerate(handle, start=1):
            if max_events is not None and len(rows) >= max_events:
                break
            raw = line.strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                bad_lines += 1
                continue

            eventid = normalize_text(event.get("eventid"))
            src_ip = normalize_text(event.get("src_ip"))
            session = normalize_text(event.get("session"))
            protocol = normalize_optional_text(event.get("protocol")).lower()
            dst_port = safe_float(event.get("dst_port"), default=0.0)
            src_port = safe_float(event.get("src_port"), default=0.0)
            duration = safe_float(event.get("duration"), default=np.nan)
            size = safe_float(event.get("size"), default=np.nan)
            input_text = normalize_optional_text(event.get("input"))

            rows.append(
                {
                    "line_number": line_number,
                    "timestamp": normalize_optional_text(event.get("timestamp")),
                    "eventid": eventid,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": normalize_optional_text(event.get("dst_ip")),
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "session": session,
                    "sensor": normalize_text(event.get("sensor")),
                    "username": normalize_optional_text(event.get("username")),
                    "password": normalize_optional_text(event.get("password")),
                    "version": normalize_optional_text(event.get("version")),
                    "input": input_text,
                    "input_length": float(len(input_text)),
                    "duration": duration,
                    "size": size,
                    "has_duration": bool(np.isfinite(duration)),
                    "has_size": bool(np.isfinite(size)),
                }
            )

    df = pd.DataFrame(rows)
    if df.empty:
        raise SystemExit(f"No valid Cowrie JSON events found in {input_file}. Bad lines: {bad_lines}")
    df["event_ts"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df[df["event_ts"].notna()].copy()
    if df.empty:
        raise SystemExit("No Cowrie events had parseable timestamps")
    df.sort_values(["event_ts", "line_number"], inplace=True)
    return df.reset_index(drop=True)


def event_class_from_counts(event_counts: pd.Series, failed_login_threshold: int) -> str:
    if sum(int(event_counts.get(eventid, 0)) for eventid in FILE_EVENTIDS) > 0:
        return "FileTransfer"
    if sum(int(event_counts.get(eventid, 0)) for eventid in COMMAND_EVENTIDS) > 0:
        return "CommandExecution"
    if sum(int(event_counts.get(eventid, 0)) for eventid in DIRECT_TCPIP_EVENTIDS) > 0:
        return "TunnelOrProxy"
    if int(event_counts.get("cowrie.login.success", 0)) > 0:
        return "LoginSuccess"
    if int(event_counts.get("cowrie.login.failed", 0)) >= failed_login_threshold:
        return "CredentialAttack"
    if int(event_counts.get("cowrie.login.failed", 0)) > 0:
        return "CredentialAttemptLow"
    if sum(int(event_counts.get(eventid, 0)) for eventid in FINGERPRINT_EVENTIDS) > 0:
        return "Fingerprinting"
    if sum(int(event_counts.get(eventid, 0)) for eventid in SESSION_EVENTIDS) > 0:
        return "SessionScan"
    return "OtherActivity"


def binary_from_class(multiclass_target: str) -> str:
    high_confidence = {"CredentialAttack", "LoginSuccess", "CommandExecution", "FileTransfer", "TunnelOrProxy"}
    return "ATTACK" if multiclass_target in high_confidence else "BENIGN"


def aggregate_events(events: pd.DataFrame, window_size: str, failed_login_threshold: int) -> tuple[pd.DataFrame, Dict[str, Dict[str, int]]]:
    work = events.copy()
    work["window_start"] = work["event_ts"].dt.floor(window_size)

    seen_src_ips: set[str] = set()
    seen_sessions: set[str] = set()
    seen_usernames: set[str] = set()
    seen_passwords: set[str] = set()
    rows: List[Dict[str, Any]] = []

    grouped = work.groupby(["window_start", "src_ip"], sort=True, dropna=False)
    for (window_start, src_ip), group in grouped:
        event_counts = group["eventid"].astype(str).value_counts()
        protocol_counts = group["protocol"].astype(str).str.lower().value_counts()
        dst_ports = pd.to_numeric(group["dst_port"], errors="coerce").fillna(0.0)
        src_ports = pd.to_numeric(group["src_port"], errors="coerce").fillna(0.0)
        durations = pd.to_numeric(group["duration"], errors="coerce")
        sizes = pd.to_numeric(group["size"], errors="coerce")
        input_lengths = pd.to_numeric(group["input_length"], errors="coerce").fillna(0.0)

        usernames = {value for value in group["username"].astype(str) if value}
        passwords = {value for value in group["password"].astype(str) if value}
        sessions = {value for value in group["session"].astype(str) if value}

        has_new_src_ip = src_ip not in seen_src_ips
        has_new_session = bool(sessions - seen_sessions)
        has_new_username = bool(usernames - seen_usernames)
        has_new_password = bool(passwords - seen_passwords)
        seen_src_ips.add(str(src_ip))
        seen_sessions.update(sessions)
        seen_usernames.update(usernames)
        seen_passwords.update(passwords)

        multiclass_target = event_class_from_counts(event_counts, failed_login_threshold)
        binary_target = binary_from_class(multiclass_target)
        finite_durations = durations[np.isfinite(durations)]
        finite_sizes = sizes[np.isfinite(sizes)]

        row: Dict[str, Any] = {
            "window_start": window_start,
            "src_ip": normalize_text(src_ip),
            "top_sensor": top_value(group["sensor"]),
            "top_protocol": top_value(group["protocol"], default="Unknown"),
            "top_eventid": top_value(group["eventid"]),
            "top_username": top_value(group["username"], default=""),
            "top_dst_ip": top_value(group["dst_ip"], default=""),
            "top_dst_port": top_value(group["dst_port"], default="0"),
            "binary_target": binary_target,
            "multiclass_target": multiclass_target,
            "event_count": int(len(group)),
            "unique_session_count": int(group["session"].nunique()),
            "unique_sensor_count": int(group["sensor"].nunique()),
            "unique_dst_ip_count": int(group.loc[group["dst_ip"] != "", "dst_ip"].nunique()),
            "unique_dst_port_count": int(dst_ports[dst_ports > 0].nunique()),
            "unique_src_port_count": int(src_ports[src_ports > 0].nunique()),
            "connect_count": int(event_counts.get("cowrie.session.connect", 0)),
            "closed_count": int(event_counts.get("cowrie.session.closed", 0)),
            "client_version_count": int(event_counts.get("cowrie.client.version", 0)),
            "client_kex_count": int(event_counts.get("cowrie.client.kex", 0)),
            "client_fingerprint_count": int(event_counts.get("cowrie.client.fingerprint", 0)),
            "client_size_count": int(event_counts.get("cowrie.client.size", 0)),
            "client_var_count": int(event_counts.get("cowrie.client.var", 0)),
            "session_params_count": int(event_counts.get("cowrie.session.params", 0)),
            "log_closed_count": int(event_counts.get("cowrie.log.closed", 0)),
            "login_failed_count": int(event_counts.get("cowrie.login.failed", 0)),
            "login_success_count": int(event_counts.get("cowrie.login.success", 0)),
            "command_input_count": int(event_counts.get("cowrie.command.input", 0)),
            "command_success_count": int(event_counts.get("cowrie.command.success", 0)),
            "command_failed_count": int(event_counts.get("cowrie.command.failed", 0)),
            "file_download_count": int(event_counts.get("cowrie.session.file_download", 0)),
            "file_upload_count": int(event_counts.get("cowrie.session.file_upload", 0)),
            "file_download_failed_count": int(event_counts.get("cowrie.session.file_download.failed", 0)),
            "direct_tcpip_request_count": int(event_counts.get("cowrie.direct-tcpip.request", 0)),
            "direct_tcpip_data_count": int(event_counts.get("cowrie.direct-tcpip.data", 0)),
            "ssh_count": int(protocol_counts.get("ssh", 0)),
            "telnet_count": int(protocol_counts.get("telnet", 0)),
            "dst_port_22_count": int((dst_ports == 22).sum()),
            "dst_port_23_count": int((dst_ports == 23).sum()),
            "duration_count": int(finite_durations.count()),
            "duration_sum": float(finite_durations.sum()) if not finite_durations.empty else 0.0,
            "duration_mean": float(finite_durations.mean()) if not finite_durations.empty else 0.0,
            "duration_max": float(finite_durations.max()) if not finite_durations.empty else 0.0,
            "username_present_count": int((group["username"].astype(str) != "").sum()),
            "password_present_count": int((group["password"].astype(str) != "").sum()),
            "unique_username_count": int(len(usernames)),
            "unique_password_count": int(len(passwords)),
            "version_present_count": int((group["version"].astype(str) != "").sum()),
            "unique_version_count": int(group.loc[group["version"] != "", "version"].nunique()),
            "input_count": int((input_lengths > 0).sum()),
            "input_length_sum": float(input_lengths.sum()),
            "input_length_mean": float(input_lengths[input_lengths > 0].mean()) if (input_lengths > 0).any() else 0.0,
            "input_length_max": float(input_lengths.max()),
            "size_count": int(finite_sizes.count()),
            "size_sum": float(finite_sizes.sum()) if not finite_sizes.empty else 0.0,
            "size_mean": float(finite_sizes.mean()) if not finite_sizes.empty else 0.0,
            "has_new_src_ip": float(has_new_src_ip),
            "has_new_session": float(has_new_session),
            "has_new_username": float(has_new_username),
            "has_new_password": float(has_new_password),
            "event_hour": float(window_start.hour),
            "event_minute": float(window_start.minute),
            "day_of_week": float(window_start.dayofweek),
        }
        rows.append(row)

    df = pd.DataFrame(rows).sort_values(["window_start", "src_ip"]).reset_index(drop=True)
    maps = {
        "sensor": build_category_map(df["top_sensor"].astype(str).tolist()),
        "protocol": build_category_map(df["top_protocol"].astype(str).tolist()),
        "eventid": build_category_map(df["top_eventid"].astype(str).tolist()),
        "dst_port": build_category_map(df["top_dst_port"].astype(str).tolist()),
    }
    df["sensor_code"] = df["top_sensor"].map(maps["sensor"]).fillna(0).astype(np.float64)
    df["protocol_code"] = df["top_protocol"].map(maps["protocol"]).fillna(0).astype(np.float64)
    df["top_eventid_code"] = df["top_eventid"].map(maps["eventid"]).fillna(0).astype(np.float64)
    df["top_dst_port_code"] = df["top_dst_port"].map(maps["dst_port"]).fillna(0).astype(np.float64)

    for column in FEATURE_COLUMNS:
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0.0).astype(np.float32)
    return df, maps


def collapse_rare_multiclass(df: pd.DataFrame, min_windows: int) -> Dict[str, int]:
    df["multiclass_target_raw"] = df["multiclass_target"].astype(str)
    if min_windows <= 1:
        return {}
    counts = count_labels(df["multiclass_target"])
    rare = {label: count for label, count in counts.items() if count < min_windows and label != "OtherActivity"}
    if rare:
        df.loc[df["multiclass_target"].isin(rare.keys()), "multiclass_target"] = "OtherActivity"
    return rare


def stratified_random_split(df: pd.DataFrame, seed: int, train_ratio: float, val_ratio: float) -> Dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    assignments: Dict[str, List[int]] = {split: [] for split in SPLITS}
    for _, group in df.groupby("binary_target", sort=True):
        indices = group.index.to_numpy(copy=True)
        rng.shuffle(indices)
        n = len(indices)
        n_train = max(1, int(round(n * train_ratio))) if n >= 3 else n
        n_val = max(1, int(round(n * val_ratio))) if n - n_train >= 2 else max(0, n - n_train)
        n_train = min(n_train, n)
        n_val = min(n_val, max(0, n - n_train))
        assignments["train"].extend(indices[:n_train].tolist())
        assignments["val"].extend(indices[n_train : n_train + n_val].tolist())
        assignments["test"].extend(indices[n_train + n_val :].tolist())
    return {split: np.array(sorted(values), dtype=int) for split, values in assignments.items()}


def date_split(df: pd.DataFrame, train_ratio: float, val_ratio: float) -> Dict[str, np.ndarray]:
    ordered_times = np.array(sorted(df["window_start"].drop_duplicates().tolist()))
    if len(ordered_times) < 3:
        raise SystemExit("Need at least three distinct windows for date split")
    train_end = max(1, int(round(len(ordered_times) * train_ratio)))
    val_end = max(train_end + 1, int(round(len(ordered_times) * (train_ratio + val_ratio))))
    val_end = min(val_end, len(ordered_times) - 1)
    train_times = set(ordered_times[:train_end])
    val_times = set(ordered_times[train_end:val_end])
    test_times = set(ordered_times[val_end:])
    return {
        "train": df.index[df["window_start"].isin(train_times)].to_numpy(dtype=int),
        "val": df.index[df["window_start"].isin(val_times)].to_numpy(dtype=int),
        "test": df.index[df["window_start"].isin(test_times)].to_numpy(dtype=int),
    }


def groupkfold_split(df: pd.DataFrame, fold: int, n_folds: int) -> Dict[str, np.ndarray]:
    groups = sorted(df["src_ip"].astype(str).unique().tolist())
    if len(groups) < 3:
        raise SystemExit("Need at least three source IPs for groupkfold split")
    n = min(n_folds, len(groups))
    mapped = fold % n
    test_group = groups[mapped]
    val_group = groups[(mapped + 1) % n]
    train_groups = set(groups) - {test_group, val_group}
    return {
        "train": df.index[df["src_ip"].isin(train_groups)].to_numpy(dtype=int),
        "val": df.index[df["src_ip"] == val_group].to_numpy(dtype=int),
        "test": df.index[df["src_ip"] == test_group].to_numpy(dtype=int),
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
        benign_like = int(counts.get("SessionScan", 0) + counts.get("Fingerprinting", 0) + counts.get("CredentialAttemptLow", 0))
        stats.benign += benign_like
        stats.attack += int(sum(counts.values()) - benign_like)


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


def frame_for_target(df: pd.DataFrame, target_column: str, feature_columns: Sequence[str]) -> pd.DataFrame:
    columns = list(feature_columns) + META_COLUMNS
    out = df.loc[:, columns].copy()
    out["target"] = df[target_column].astype(str).to_numpy(copy=True)
    return out


def write_parquet_split(base_dir: Path, pipeline: str, split_name: str, df: pd.DataFrame) -> None:
    if df.empty:
        return
    folder = base_dir / pipeline / split_name
    folder.mkdir(parents=True, exist_ok=True)
    df.to_parquet(folder / "part-00000.parquet", index=False)


def materialize(base_dir: Path, df: pd.DataFrame, split_indices: Dict[str, np.ndarray], feature_columns: Sequence[str]) -> Dict[str, Dict[str, Stats]]:
    stats: Dict[str, Dict[str, Stats]] = {
        "binary": {split: Stats() for split in SPLITS},
        "multiclass": {split: Stats() for split in SPLITS},
        "anomaly": {split: Stats() for split in SPLITS},
    }

    for split_name, indices in split_indices.items():
        split_df = df.loc[indices].copy()
        if split_df.empty:
            raise SystemExit(f"Split {split_name} is empty")

        binary_df = frame_for_target(split_df, "binary_target", feature_columns)
        write_parquet_split(base_dir, "binary", split_name, binary_df)
        update_stats(stats["binary"][split_name], count_labels(binary_df["target"]), binary_view=True)

        multiclass_df = frame_for_target(split_df, "multiclass_target", feature_columns)
        write_parquet_split(base_dir, "multiclass", split_name, multiclass_df)
        update_stats(stats["multiclass"][split_name], count_labels(multiclass_df["target"]), binary_view=False)

        anomaly_source = split_df if split_name != "train" else split_df[split_df["binary_target"] == "BENIGN"]
        anomaly_dir = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}[split_name]
        anomaly_df = frame_for_target(anomaly_source, "binary_target", feature_columns)
        write_parquet_split(base_dir, "anomaly", anomaly_dir, anomaly_df)
        update_stats(stats["anomaly"][split_name], count_labels(anomaly_df["target"]), binary_view=True)

    if stats["anomaly"]["train"].rows == 0:
        raise SystemExit("Anomaly train split has no BENIGN low-interaction windows")

    write_label_map(base_dir / "binary" / "label_map.json", df["binary_target"].astype(str).unique(), binary=True)
    write_label_map(base_dir / "multiclass" / "label_map.json", df["multiclass_target"].astype(str).unique(), binary=False)
    write_stats(base_dir, stats)
    return stats


def split_policy_payload(split_mode: str, split_indices: Dict[str, np.ndarray], df: pd.DataFrame) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"split_mode": split_mode, "splits": {}}
    for split_name, indices in split_indices.items():
        split_df = df.loc[indices]
        payload["splits"][split_name] = {
            "rows": int(len(split_df)),
            "window_start_min": None if split_df.empty else str(split_df["window_start"].min()),
            "window_start_max": None if split_df.empty else str(split_df["window_start"].max()),
            "binary_counts": count_labels(split_df["binary_target"]),
            "multiclass_counts": count_labels(split_df["multiclass_target"]),
            "src_ips": int(split_df["src_ip"].astype(str).nunique()),
        }
    return payload


def write_dataset_metadata(base_dir: Path, df: pd.DataFrame, maps: Dict[str, Dict[str, int]], args: argparse.Namespace, split_mode: str, split_indices: Dict[str, np.ndarray], rare_classes: Dict[str, int], feature_columns: Sequence[str]) -> None:
    profile_payload = feature_profile_payload(args.feature_profile)
    write_json(base_dir / "feature_columns.json", list(feature_columns))
    write_json(base_dir / "feature_profile.json", profile_payload)
    write_json(base_dir / "category_maps.json", maps)
    write_json(base_dir / "split_policy.json", split_policy_payload(split_mode, split_indices, df))
    write_json(
        base_dir / "prepare_dataset_summary.json",
        {
            "dataset": args.dataset,
            "source": str(resolve_from_root(args.in_file)),
            "rows": int(len(df)),
            "window_size": args.window_size,
            "group_key": "src_ip",
            "target_policy": "Weak labels derived from Cowrie interaction depth. BENIGN means low-interaction baseline/probing windows, not verified legitimate traffic.",
            "failed_login_threshold": args.failed_login_threshold,
            "min_multiclass_windows": args.min_multiclass_windows,
            "collapsed_multiclass_classes": rare_classes,
            "binary_counts": count_labels(df["binary_target"]),
            "multiclass_counts": count_labels(df["multiclass_target"]),
            "feature_profile": args.feature_profile,
            "feature_profile_description": profile_payload["description"],
            "feature_count": len(feature_columns),
            "excluded_feature_count": profile_payload["excluded_feature_count"],
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


def prepare_mode(df: pd.DataFrame, maps: Dict[str, Dict[str, int]], args: argparse.Namespace, split_mode: str, rare_classes: Dict[str, int], fold: int | None = None) -> None:
    out_base = resolve_from_root(args.out_dir) / split_mode / args.dataset
    if split_mode == "groupkfold":
        out_base = out_base / f"fold_{fold}"
    clear_dir(out_base)
    split_indices = build_split_indices(df, args, split_mode, fold=fold)
    feature_columns = feature_columns_for_profile(args.feature_profile)
    materialize(out_base, df, split_indices, feature_columns)
    write_dataset_metadata(out_base, df, maps, args, split_mode, split_indices, rare_classes, feature_columns)
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in_file", default=str(DEFAULT_IN_FILE))
    parser.add_argument("--out_dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--dataset", default=DATASET_NAME)
    parser.add_argument("--split_mode", nargs="+", default=["date"], help="date, random, groupkfold, all, or comma-separated values")
    parser.add_argument("--window_size", default="1min")
    parser.add_argument("--train_ratio", type=float, default=0.70)
    parser.add_argument("--val_ratio", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n_folds", type=int, default=5)
    parser.add_argument("--fold", type=int, default=0)
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--min_multiclass_windows", type=int, default=30)
    parser.add_argument("--failed_login_threshold", type=int, default=3)
    parser.add_argument("--max_events", type=int, default=None)
    parser.add_argument("--feature_profile", default="full", choices=FEATURE_PROFILES)
    args = parser.parse_args()

    ensure_pyarrow()
    split_modes = normalize_modes(args.split_mode)
    if args.train_ratio <= 0 or args.val_ratio <= 0 or args.train_ratio + args.val_ratio >= 1:
        raise SystemExit("train_ratio and val_ratio must be positive and sum to less than 1")
    if args.failed_login_threshold < 1:
        raise SystemExit("failed_login_threshold must be >= 1")

    input_file = resolve_from_root(args.in_file)
    if not input_file.exists():
        raise SystemExit(f"Input file does not exist: {input_file}")

    print("== prepare_dataset (COWRIE_FULL) ==")
    print(f"Input       : {input_file}")
    print(f"Dataset     : {args.dataset}")
    print(f"Split modes : {split_modes}")
    print(f"Window size : {args.window_size}")
    print(f"Features    : {args.feature_profile}")

    events = parse_jsonl(input_file, max_events=args.max_events)
    windows, maps = aggregate_events(events, args.window_size, args.failed_login_threshold)
    rare_classes = collapse_rare_multiclass(windows, args.min_multiclass_windows)
    print(f"Events      : {len(events):,}")
    print(f"Windows     : {len(windows):,}")
    print(f"Binary      : {count_labels(windows['binary_target'])}")
    print(f"Multiclass  : {count_labels(windows['multiclass_target'])}")
    if rare_classes:
        print(f"Collapsed rare multiclass labels into OtherActivity: {rare_classes}")

    for split_mode in split_modes:
        if split_mode == "groupkfold":
            folds = range(args.n_folds) if args.all_folds else [args.fold]
            mode_root = resolve_from_root(args.out_dir) / split_mode / args.dataset
            mode_root.mkdir(parents=True, exist_ok=True)
            write_json(mode_root / "feature_columns.json", feature_columns_for_profile(args.feature_profile))
            write_json(mode_root / "feature_profile.json", feature_profile_payload(args.feature_profile))
            for fold in folds:
                prepare_mode(windows, maps, args, split_mode, rare_classes, fold=int(fold))
        else:
            prepare_mode(windows, maps, args, split_mode, rare_classes)


if __name__ == "__main__":
    main()
