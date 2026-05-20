#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import numpy as np
import pandas as pd


try:
    import pyarrow  # noqa: F401
except Exception:
    pyarrow = None


DEFAULT_IN_FILE = Path("out/LAB-ALERTS/alerts.json")
DEFAULT_OUT_DIR = Path("src/models/LAB-ALERTS/datasets")
DATASET_NAME = "LAB-ALERTS"
SPLITS = ("train", "val", "test")

ATTACK_GROUPS = {
    "authentication_failed",
    "authentication_failures",
    "invalid_login",
    "sshd",
    "pam",
    "attack",
    "recon",
    "web_scan",
    "access_control",
    "windows_security",
}
OPERATIONAL_GROUPS = {
    "local",
    "systemd",
    "docker",
    "docker-error",
    "dpkg",
    "config_changed",
    "syscheck",
    "syscheck_registry",
    "ossec",
    "windows_system",
    "windows_application",
}
ATTACK_TACTICS = {
    "credential access",
    "lateral movement",
    "reconnaissance",
    "initial access",
    "command and control",
    "execution",
    "privilege escalation",
    "defense evasion",
    "impact",
    "discovery",
    "persistence",
}

FEATURE_COLUMNS = [
    "alert_count",
    "unique_rule_count",
    "unique_src_ip_count",
    "unique_src_user_count",
    "unique_dst_user_count",
    "unique_decoder_count",
    "unique_program_count",
    "unique_location_count",
    "rule_level_mean",
    "rule_level_max",
    "rule_level_sum",
    "rule_level_std",
    "rule_firedtimes_mean",
    "rule_firedtimes_max",
    "rule_firedtimes_sum",
    "level_ge_7_count",
    "level_ge_10_count",
    "mitre_tagged_count",
    "mitre_tagged_ratio",
    "credential_tactic_count",
    "lateral_tactic_count",
    "recon_tactic_count",
    "auth_group_count",
    "sshd_group_count",
    "pam_group_count",
    "invalid_login_group_count",
    "systemd_group_count",
    "syscheck_group_count",
    "web_group_count",
    "docker_group_count",
    "windows_group_count",
    "dpkg_group_count",
    "src_ip_present_count",
    "src_port_present_count",
    "has_new_src_ip",
    "has_new_rule_id",
    "event_hour",
    "event_minute",
    "day_of_week",
    "agent_id_code",
    "decoder_code",
    "program_code",
    "location_code",
]

FEATURE_PROFILES = ("full", "operational_no_label_proxy")

LABEL_PROXY_EXCLUSIONS = {
    "rule_level_mean": "Wazuh severity is part of the weak-label policy.",
    "rule_level_max": "Wazuh severity is part of the weak-label policy.",
    "rule_level_sum": "Wazuh severity is part of the weak-label policy.",
    "rule_level_std": "Wazuh severity is part of the weak-label policy.",
    "rule_firedtimes_mean": "Rule firing statistics can proxy the generating detection rule.",
    "rule_firedtimes_max": "Rule firing statistics can proxy the generating detection rule.",
    "rule_firedtimes_sum": "Rule firing statistics can proxy the generating detection rule.",
    "level_ge_7_count": "Severity threshold features are close to the weak-label policy.",
    "level_ge_10_count": "Severity threshold features are close to the weak-label policy.",
    "mitre_tagged_count": "MITRE tags are used by the weak-label policy.",
    "mitre_tagged_ratio": "MITRE tags are used by the weak-label policy.",
    "credential_tactic_count": "MITRE tactic counts are used by the weak-label policy.",
    "lateral_tactic_count": "MITRE tactic counts are used by the weak-label policy.",
    "recon_tactic_count": "MITRE tactic counts are used by the weak-label policy.",
    "auth_group_count": "Rule group counts are used by the weak-label policy.",
    "sshd_group_count": "Rule group counts are used by the weak-label policy.",
    "pam_group_count": "Rule group counts are used by the weak-label policy.",
    "invalid_login_group_count": "Rule group counts are used by the weak-label policy.",
    "systemd_group_count": "Rule group counts are used by the weak-label policy.",
    "syscheck_group_count": "Rule group counts are used by the weak-label policy.",
    "web_group_count": "Rule group counts are used by the weak-label policy.",
    "docker_group_count": "Rule group counts are used by the weak-label policy.",
    "windows_group_count": "Rule group counts are used by the weak-label policy.",
    "dpkg_group_count": "Rule group counts are used by the weak-label policy.",
    "decoder_code": "Top decoder category can act as a label proxy.",
    "program_code": "Top program category can act as a label proxy.",
    "location_code": "Top location category can act as a label proxy.",
}

META_COLUMNS = [
    "window_start",
    "agent_id",
    "agent_name",
    "agent_ip",
    "top_rule_id",
    "top_rule_description",
    "top_decoder",
    "top_program",
    "top_location",
    "binary_target",
    "multiclass_target_raw",
    "multiclass_target",
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
        "description": "All engineered LAB-ALERTS features." if profile == "full" else "Operational LAB-ALERTS profile excluding direct weak-label proxy features.",
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


def as_list(value: object) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [normalize_text(item, default="") for item in value if normalize_text(item, default="")]
    text = normalize_text(value, default="")
    return [text] if text else []


def lower_set(values: Iterable[str]) -> set[str]:
    return {str(value).strip().lower() for value in values if str(value).strip()}


def safe_int(value: object, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(float(value))
    except Exception:
        return default


def top_value(series: pd.Series, default: str = "Unknown") -> str:
    clean = series.map(lambda value: normalize_text(value, default=default))
    clean = clean[clean != default]
    if clean.empty:
        return default
    return str(clean.value_counts().sort_values(ascending=False).index[0])


def event_class(groups: set[str], tactics: set[str], decoder_name: str, program_name: str) -> str:
    if "credential access" in tactics:
        return "CredentialAccess"
    if "lateral movement" in tactics:
        return "LateralMovement"
    if "reconnaissance" in tactics or "recon" in groups or "web_scan" in groups:
        return "Reconnaissance"
    if "web" in groups or "accesslog" in groups:
        return "WebAlert"
    if "syscheck" in groups or "syscheck_registry" in groups:
        return "IntegrityChange"
    if groups.intersection({"authentication_failed", "authentication_failures", "invalid_login", "sshd", "pam"}):
        return "AuthenticationFailure"
    if groups.intersection({"systemd", "docker", "docker-error", "dpkg"}) or decoder_name in {"systemd", "docker", "dpkg-decoder"}:
        return "ServiceFailure"
    if "windows" in groups or program_name.startswith("windows"):
        return "SystemAlert"
    return "OtherAlert"


def is_attack_event(groups: set[str], tactics: set[str], level: int) -> bool:
    if groups.intersection(ATTACK_GROUPS):
        return True
    if tactics.intersection(ATTACK_TACTICS):
        return True
    if level >= 8 and not groups.intersection(OPERATIONAL_GROUPS):
        return True
    return False


def is_operational_event(groups: set[str], decoder_name: str) -> bool:
    return bool(groups.intersection(OPERATIONAL_GROUPS) or decoder_name in {"systemd", "docker", "dpkg-decoder"})


def parse_jsonl(input_file: Path) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    bad_lines = 0

    with input_file.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                alert = json.loads(raw)
            except json.JSONDecodeError:
                bad_lines += 1
                continue

            rule = alert.get("rule") or {}
            agent = alert.get("agent") or {}
            decoder = alert.get("decoder") or {}
            predecoder = alert.get("predecoder") or {}
            data = alert.get("data") or {}
            if not isinstance(data, dict):
                data = {}
            mitre = rule.get("mitre") or {}

            groups = as_list(rule.get("groups"))
            tactics = as_list(mitre.get("tactic"))
            group_set = lower_set(groups)
            tactic_set = lower_set(tactics)
            level = safe_int(rule.get("level"))
            decoder_name = normalize_text(decoder.get("name"))
            program_name = normalize_text(predecoder.get("program_name"), default="")
            cls = event_class(group_set, tactic_set, decoder_name.lower(), program_name.lower())
            attack = is_attack_event(group_set, tactic_set, level)
            operational = is_operational_event(group_set, decoder_name.lower())

            rows.append(
                {
                    "line_number": line_number,
                    "timestamp": normalize_text(alert.get("timestamp"), default=""),
                    "rule_id": normalize_text(rule.get("id")),
                    "rule_description": normalize_text(rule.get("description")),
                    "rule_level": level,
                    "rule_firedtimes": safe_int(rule.get("firedtimes"), default=1),
                    "groups": groups,
                    "mitre_tactics": tactics,
                    "agent_id": normalize_text(agent.get("id")),
                    "agent_name": normalize_text(agent.get("name")),
                    "agent_ip": normalize_text(agent.get("ip"), default=""),
                    "src_ip": normalize_text(data.get("srcip"), default=""),
                    "src_port": normalize_text(data.get("srcport"), default=""),
                    "src_user": normalize_text(data.get("srcuser"), default=""),
                    "dst_user": normalize_text(data.get("dstuser"), default=""),
                    "decoder_name": decoder_name,
                    "program_name": program_name,
                    "location": normalize_text(alert.get("location")),
                    "event_class": cls,
                    "event_attack": bool(attack),
                    "event_operational": bool(operational),
                    "has_mitre": bool(tactics),
                    "has_src_ip": bool(normalize_text(data.get("srcip"), default="")),
                    "has_src_port": bool(normalize_text(data.get("srcport"), default="")),
                }
            )

    df = pd.DataFrame(rows)
    if df.empty:
        raise SystemExit(f"No valid JSON alerts found in {input_file}. Bad lines: {bad_lines}")
    df["event_ts"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df[df["event_ts"].notna()].copy()
    if df.empty:
        raise SystemExit("No alerts had parseable timestamps")
    df.sort_values(["event_ts", "line_number"], inplace=True)
    return df.reset_index(drop=True)


def class_counts_to_target(counts: Dict[str, float]) -> str:
    if not counts:
        return "OtherAlert"
    return sorted(counts.items(), key=lambda item: (item[1], item[0]), reverse=True)[0][0]


def build_category_map(values: Sequence[str]) -> Dict[str, int]:
    mapping = {"Unknown": 0}
    for value in sorted({normalize_text(v) for v in values}):
        if value not in mapping:
            mapping[value] = len(mapping)
    return mapping


def aggregate_alerts(events: pd.DataFrame, window_size: str) -> tuple[pd.DataFrame, Dict[str, Dict[str, int]]]:
    work = events.copy()
    work["window_start"] = work["event_ts"].dt.floor(window_size)

    seen_src_ips: set[str] = set()
    seen_rule_ids: set[str] = set()
    rows: List[Dict[str, Any]] = []

    grouped = work.groupby(["window_start", "agent_id"], sort=True, dropna=False)
    for (window_start, agent_id), group in grouped:
        alert_count = int(len(group))
        levels = pd.to_numeric(group["rule_level"], errors="coerce").fillna(0.0)
        firedtimes = pd.to_numeric(group["rule_firedtimes"], errors="coerce").fillna(1.0)
        attack_count = int(group["event_attack"].sum())
        operational_count = int(group["event_operational"].sum())
        attack_weight = float(levels[group["event_attack"].to_numpy()].sum()) if attack_count else 0.0
        operational_weight = float(levels[group["event_operational"].to_numpy()].sum()) if operational_count else 0.0
        binary_target = "ATTACK" if attack_count > 0 and (attack_weight >= operational_weight or attack_count / alert_count >= 0.30 or levels.max() >= 8) else "BENIGN"

        class_weights: Dict[str, float] = {}
        for cls, level in zip(group["event_class"].astype(str), levels):
            class_weights[cls] = class_weights.get(cls, 0.0) + float(max(level, 1.0))

        src_ips = {value for value in group["src_ip"].astype(str) if value}
        rule_ids = {value for value in group["rule_id"].astype(str) if value}
        has_new_src_ip = bool(src_ips - seen_src_ips)
        has_new_rule_id = bool(rule_ids - seen_rule_ids)
        seen_src_ips.update(src_ips)
        seen_rule_ids.update(rule_ids)

        tactics = [tactic.lower() for tactics_list in group["mitre_tactics"] for tactic in tactics_list]
        groups = [name.lower() for groups_list in group["groups"] for name in groups_list]
        group_counter = pd.Series(groups, dtype=object).value_counts() if groups else pd.Series(dtype=int)
        tactic_counter = pd.Series(tactics, dtype=object).value_counts() if tactics else pd.Series(dtype=int)

        row: Dict[str, Any] = {
            "window_start": window_start,
            "agent_id": normalize_text(agent_id),
            "agent_name": top_value(group["agent_name"]),
            "agent_ip": top_value(group["agent_ip"], default=""),
            "top_rule_id": top_value(group["rule_id"]),
            "top_rule_description": top_value(group["rule_description"]),
            "top_decoder": top_value(group["decoder_name"]),
            "top_program": top_value(group["program_name"], default=""),
            "top_location": top_value(group["location"]),
            "binary_target": binary_target,
            "multiclass_target": class_counts_to_target(class_weights),
            "alert_count": alert_count,
            "unique_rule_count": int(group["rule_id"].nunique()),
            "unique_src_ip_count": int(group.loc[group["src_ip"] != "", "src_ip"].nunique()),
            "unique_src_user_count": int(group.loc[group["src_user"] != "", "src_user"].nunique()),
            "unique_dst_user_count": int(group.loc[group["dst_user"] != "", "dst_user"].nunique()),
            "unique_decoder_count": int(group["decoder_name"].nunique()),
            "unique_program_count": int(group.loc[group["program_name"] != "", "program_name"].nunique()),
            "unique_location_count": int(group["location"].nunique()),
            "rule_level_mean": float(levels.mean()),
            "rule_level_max": float(levels.max()),
            "rule_level_sum": float(levels.sum()),
            "rule_level_std": float(levels.std(ddof=0)),
            "rule_firedtimes_mean": float(firedtimes.mean()),
            "rule_firedtimes_max": float(firedtimes.max()),
            "rule_firedtimes_sum": float(firedtimes.sum()),
            "level_ge_7_count": int((levels >= 7).sum()),
            "level_ge_10_count": int((levels >= 10).sum()),
            "mitre_tagged_count": int(group["has_mitre"].sum()),
            "mitre_tagged_ratio": float(group["has_mitre"].mean()),
            "credential_tactic_count": int(tactic_counter.get("credential access", 0)),
            "lateral_tactic_count": int(tactic_counter.get("lateral movement", 0)),
            "recon_tactic_count": int(tactic_counter.get("reconnaissance", 0)),
            "auth_group_count": int(sum(group_counter.get(name, 0) for name in ["authentication_failed", "authentication_failures"])),
            "sshd_group_count": int(group_counter.get("sshd", 0)),
            "pam_group_count": int(group_counter.get("pam", 0)),
            "invalid_login_group_count": int(group_counter.get("invalid_login", 0)),
            "systemd_group_count": int(group_counter.get("systemd", 0)),
            "syscheck_group_count": int(group_counter.get("syscheck", 0) + group_counter.get("syscheck_registry", 0)),
            "web_group_count": int(group_counter.get("web", 0) + group_counter.get("accesslog", 0) + group_counter.get("web_scan", 0)),
            "docker_group_count": int(group_counter.get("docker", 0) + group_counter.get("docker-error", 0)),
            "windows_group_count": int(group_counter.get("windows", 0) + group_counter.get("windows_security", 0)),
            "dpkg_group_count": int(group_counter.get("dpkg", 0)),
            "src_ip_present_count": int(group["has_src_ip"].sum()),
            "src_port_present_count": int(group["has_src_port"].sum()),
            "has_new_src_ip": float(has_new_src_ip),
            "has_new_rule_id": float(has_new_rule_id),
            "event_hour": float(window_start.hour),
            "event_minute": float(window_start.minute),
            "day_of_week": float(window_start.dayofweek),
        }
        rows.append(row)

    df = pd.DataFrame(rows).sort_values(["window_start", "agent_id"]).reset_index(drop=True)
    maps = {
        "agent_id": build_category_map(df["agent_id"].astype(str).tolist()),
        "decoder": build_category_map(df["top_decoder"].astype(str).tolist()),
        "program": build_category_map(df["top_program"].astype(str).tolist()),
        "location": build_category_map(df["top_location"].astype(str).tolist()),
    }
    df["agent_id_code"] = df["agent_id"].map(maps["agent_id"]).fillna(0).astype(np.float64)
    df["decoder_code"] = df["top_decoder"].map(maps["decoder"]).fillna(0).astype(np.float64)
    df["program_code"] = df["top_program"].map(maps["program"]).fillna(0).astype(np.float64)
    df["location_code"] = df["top_location"].map(maps["location"]).fillna(0).astype(np.float64)

    for column in FEATURE_COLUMNS:
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0.0).astype(np.float32)
    return df, maps


def collapse_rare_multiclass(df: pd.DataFrame, min_windows: int) -> Dict[str, int]:
    df["multiclass_target_raw"] = df["multiclass_target"].astype(str)
    if min_windows <= 1:
        return {}
    counts = count_labels(df["multiclass_target"])
    rare = {label: count for label, count in counts.items() if count < min_windows and label != "OtherAlert"}
    if rare:
        df.loc[df["multiclass_target"].isin(rare.keys()), "multiclass_target"] = "OtherAlert"
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
    groups = sorted(df["agent_id"].astype(str).unique().tolist())
    if len(groups) < 3:
        raise SystemExit("Need at least three agents for groupkfold split")
    n = min(n_folds, len(groups))
    mapped = fold % n
    test_group = groups[mapped]
    val_group = groups[(mapped + 1) % n]
    train_groups = set(groups) - {test_group, val_group}
    return {
        "train": df.index[df["agent_id"].isin(train_groups)].to_numpy(dtype=int),
        "val": df.index[df["agent_id"] == val_group].to_numpy(dtype=int),
        "test": df.index[df["agent_id"] == test_group].to_numpy(dtype=int),
    }


def count_labels(values: Sequence[object]) -> Dict[str, int]:
    counts = pd.Series(list(map(str, values)), dtype=object).value_counts(dropna=False)
    return {str(key): int(value) for key, value in counts.items()}


def update_stats(stats: Stats, counts: Dict[str, int], binary_view: bool) -> None:
    assert stats.label_counts is not None
    stats.rows += int(sum(counts.values()))
    for key, value in counts.items():
        stats.label_counts[key] = stats.label_counts.get(key, 0) + int(value)
    if binary_view:
        stats.benign += int(counts.get("BENIGN", 0))
        stats.attack += int(counts.get("ATTACK", 0))
    else:
        service = int(counts.get("ServiceFailure", 0) + counts.get("SystemAlert", 0))
        stats.benign += service
        stats.attack += int(sum(counts.values()) - service)


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
        raise SystemExit("Anomaly train split has no BENIGN windows")

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
            "agents": sorted(split_df["agent_id"].astype(str).unique().tolist()),
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
            "group_key": "agent_id",
            "target_policy": "Weak labels derived from Wazuh rule groups, MITRE tactics, severity, and operational alert groups.",
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
    parser.add_argument("--feature_profile", default="full", choices=FEATURE_PROFILES)
    args = parser.parse_args()

    ensure_pyarrow()
    split_modes = normalize_modes(args.split_mode)
    if args.train_ratio <= 0 or args.val_ratio <= 0 or args.train_ratio + args.val_ratio >= 1:
        raise SystemExit("train_ratio and val_ratio must be positive and sum to less than 1")

    input_file = resolve_from_root(args.in_file)
    if not input_file.exists():
        raise SystemExit(f"Input file does not exist: {input_file}")

    print("== prepare_dataset (LAB-ALERTS) ==")
    print(f"Input       : {input_file}")
    print(f"Dataset     : {args.dataset}")
    print(f"Split modes : {split_modes}")
    print(f"Window size : {args.window_size}")
    print(f"Features    : {args.feature_profile}")

    events = parse_jsonl(input_file)
    windows, maps = aggregate_alerts(events, args.window_size)
    rare_classes = collapse_rare_multiclass(windows, args.min_multiclass_windows)
    print(f"Events      : {len(events):,}")
    print(f"Windows     : {len(windows):,}")
    print(f"Binary      : {count_labels(windows['binary_target'])}")
    print(f"Multiclass  : {count_labels(windows['multiclass_target'])}")
    if rare_classes:
        print(f"Collapsed rare multiclass labels into OtherAlert: {rare_classes}")

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