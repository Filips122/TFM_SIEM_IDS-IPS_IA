#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Turn the raw ARGOS-LAB alert stream into window-level training datasets.

Input : src/models/ARGOS_LAB/argos-alerts_30d.jsonl  (1.46M alerts, ~1.5 GB)
Unit  : one row per (1 min window x agent_id), matching the manifest's own
        aggregation so results stay comparable with the shipped statistics.

The file is streamed once and folded into per-window accumulators, so peak
memory stays proportional to the number of windows (~88k), not alerts.

Columns that are dropped, and why
---------------------------------
  alert_id        unique per row, pure identifier
  is_simulated    constant 0 across all 1,462,265 rows (zero variance)
  dst_port        empty in 100% of rows
  agent_name/ip   1:1 redundant with agent_id (4 agents); kept as metadata
  full_log        free text, ~70% of the file size, redundant with rule_id
  rule_description 9,228 distinct values driven by embedded CVE ids while
                  rule_id has only 48; kept as metadata, not as a feature
  weak_label_reason  literally names the rule that produced the label

High-cardinality columns (src_ip 4.8k, src_user 13.2k, src_port 38.2k,
geo_city 723) are never one-hot encoded. They are folded into counts,
distinct counts, Shannon entropy, top-value share and novelty rates.
"""

from __future__ import annotations

import argparse
import json
import math
import shutil
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

import numpy as np
import pandas as pd

from feature_spec import (
    FEATURE_COLUMNS,
    FEATURE_GROUPS,
    META_COLUMNS,
    SYSTEM_USERS,
    activity_class,
    is_posture_alert,
)

try:
    import pyarrow  # noqa: F401
except Exception:
    pyarrow = None


DEFAULT_IN_FILE = Path("src/models/ARGOS_LAB/argos-alerts_30d.jsonl")
DEFAULT_OUT_DIR = Path("src/models/ARGOS_LAB/datasets")
DATASET_NAME = "ARGOS-LAB"
SPLITS = ("train", "val", "test")
EPS = 1e-9

# Groups counted individually because they carry the rule taxonomy.
TRACKED_GROUPS = {
    "authentication_failed": "grp_auth_failed_ratio",
    "authentication_failures": "grp_auth_failed_ratio",
    "invalid_login": "grp_invalid_login_ratio",
    "sshd": "grp_sshd_ratio",
    "pam": "grp_pam_ratio",
    "trivy": "grp_trivy_ratio",
    "agent_flooding": "grp_agent_flooding_ratio",
    "syscheck": "grp_syscheck_ratio",
    "syscheck_file": "grp_syscheck_ratio",
    "sca": "grp_sca_ratio",
    "ossec": "grp_ossec_ratio",
    "dpkg": "grp_dpkg_ratio",
    "syslog": "grp_syslog_ratio",
}
GROUP_FEATURES = sorted(set(TRACKED_GROUPS.values()))


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
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
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def clean_str(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"", "nan", "none", "null"} else text


def parse_ts(value: object) -> float:
    text = clean_str(value)
    if not text:
        return float("nan")
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return float("nan")


def shannon(counts: Dict[str, int]) -> tuple[float, float, float]:
    """Return (entropy, normalized entropy, top-value share)."""
    total = sum(counts.values())
    if total <= 0:
        return 0.0, 0.0, 0.0
    entropy = 0.0
    top = 0
    for value in counts.values():
        p = value / total
        entropy -= p * math.log(p + EPS)
        if value > top:
            top = value
    k = len(counts)
    norm = entropy / math.log(k) if k > 1 else 0.0
    return entropy, norm, top / total


def std_from_moments(total: float, sq_total: float, n: int) -> float:
    if n <= 0:
        return 0.0
    mean = total / n
    var = sq_total / n - mean * mean
    return math.sqrt(var) if var > 0 else 0.0


def safe_div(a: float, b: float) -> float:
    return float(a) / float(b) if b else 0.0


# --------------------------------------------------------------------------
# streaming aggregation
# --------------------------------------------------------------------------
class WindowAcc:
    """Accumulates every statistic for one (window_start, agent_id) cell."""

    __slots__ = (
        "n", "ts", "levels_sum", "levels_sq", "levels_max", "levels_min",
        "lvl7", "lvl10", "lvl12", "fired_sum", "fired_max",
        "src_ip", "src_user", "src_port", "dst_user", "country", "city",
        "rule_id", "decoder", "program", "location", "groups", "tactics",
        "activity", "taxonomy", "rule_desc",
        "lat_sum", "lat_sq", "lon_sum", "lon_sq", "geo_n",
        "src_ip_present", "src_port_present", "dst_user_present", "mitre_present",
        "root_hits", "system_hits", "user_hits",
        "attack", "benign", "unknown", "posture",
        "agent_name",
    )

    def __init__(self) -> None:
        self.n = 0
        self.ts: List[float] = []
        self.levels_sum = 0.0
        self.levels_sq = 0.0
        self.levels_max = 0.0
        self.levels_min = float("inf")
        self.lvl7 = 0
        self.lvl10 = 0
        self.lvl12 = 0
        self.fired_sum = 0.0
        self.fired_max = 0.0
        self.src_ip: Dict[str, int] = {}
        self.src_user: Dict[str, int] = {}
        self.src_port: Dict[str, int] = {}
        self.dst_user: Dict[str, int] = {}
        self.country: Dict[str, int] = {}
        self.city: set[str] = set()
        self.rule_id: Dict[str, int] = {}
        self.decoder: Dict[str, int] = {}
        self.program: Dict[str, int] = {}
        self.location: Dict[str, int] = {}
        self.groups: Dict[str, int] = {}
        self.tactics: Dict[str, int] = {}
        self.activity: Dict[str, int] = {}
        self.taxonomy: Dict[str, int] = {}
        self.rule_desc: Dict[str, int] = {}
        self.lat_sum = 0.0
        self.lat_sq = 0.0
        self.lon_sum = 0.0
        self.lon_sq = 0.0
        self.geo_n = 0
        self.src_ip_present = 0
        self.src_port_present = 0
        self.dst_user_present = 0
        self.mitre_present = 0
        self.root_hits = 0
        self.system_hits = 0
        self.user_hits = 0
        self.attack = 0
        self.benign = 0
        self.unknown = 0
        self.posture = 0
        self.agent_name = ""


def bump(mapping: Dict[str, int], key: str) -> None:
    if key:
        mapping[key] = mapping.get(key, 0) + 1


def top_key(mapping: Dict[str, int], default: str = "Unknown") -> str:
    if not mapping:
        return default
    return max(mapping.items(), key=lambda item: (item[1], item[0]))[0]


def stream_windows(input_file: Path, exclude_posture: bool, progress_every: int) -> tuple[Dict[tuple, WindowAcc], Dict[str, int]]:
    """One pass over the JSONL, folding alerts into per-window accumulators."""
    windows: Dict[tuple, WindowAcc] = {}
    counters = {"rows": 0, "bad_json": 0, "no_timestamp": 0, "skipped_posture": 0, "kept": 0}

    with input_file.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            counters["rows"] += 1
            if progress_every and counters["rows"] % progress_every == 0:
                print(f"  ... {counters['rows']:,} alerts read, {len(windows):,} windows", flush=True)
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                counters["bad_json"] += 1
                continue

            groups = {str(g).strip().lower() for g in (alert.get("rule_groups") or []) if str(g).strip()}
            decoder = clean_str(alert.get("decoder_name")) or "Unknown"
            posture = is_posture_alert(groups, decoder)
            if exclude_posture and posture:
                counters["skipped_posture"] += 1
                continue

            epoch = parse_ts(alert.get("timestamp"))
            if math.isnan(epoch):
                counters["no_timestamp"] += 1
                continue

            window_start = clean_str(alert.get("window_start"))
            if not window_start:
                continue
            agent_id = clean_str(alert.get("agent_id")) or "Unknown"
            key = (window_start, agent_id)
            acc = windows.get(key)
            if acc is None:
                acc = windows[key] = WindowAcc()

            counters["kept"] += 1
            acc.n += 1
            acc.ts.append(epoch)
            if not acc.agent_name:
                acc.agent_name = clean_str(alert.get("agent_name"))

            level = float(alert.get("rule_level") or 0)
            acc.levels_sum += level
            acc.levels_sq += level * level
            acc.levels_max = max(acc.levels_max, level)
            acc.levels_min = min(acc.levels_min, level)
            acc.lvl7 += level >= 7
            acc.lvl10 += level >= 10
            acc.lvl12 += level >= 12

            fired = float(alert.get("rule_firedtimes") or 0)
            acc.fired_sum += fired
            acc.fired_max = max(acc.fired_max, fired)

            src_ip = clean_str(alert.get("src_ip"))
            src_user = clean_str(alert.get("src_user"))
            src_port = clean_str(alert.get("src_port"))
            dst_user = clean_str(alert.get("dst_user"))
            bump(acc.src_ip, src_ip)
            bump(acc.src_user, src_user)
            bump(acc.src_port, src_port)
            bump(acc.dst_user, dst_user)
            acc.src_ip_present += bool(src_ip)
            acc.src_port_present += bool(src_port)
            acc.dst_user_present += bool(dst_user)

            # Attacker credential targeting: srcuser and dstuser both carry the
            # attempted account depending on which decoder fired, so merge them.
            account = (src_user or dst_user).lower()
            if account:
                acc.user_hits += 1
                if account == "root":
                    acc.root_hits += 1
                if account in SYSTEM_USERS:
                    acc.system_hits += 1

            bump(acc.country, clean_str(alert.get("geo_country")))
            city = clean_str(alert.get("geo_city"))
            if city:
                acc.city.add(city)
            lat, lon = alert.get("geo_lat"), alert.get("geo_lon")
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                acc.lat_sum += float(lat)
                acc.lat_sq += float(lat) ** 2
                acc.lon_sum += float(lon)
                acc.lon_sq += float(lon) ** 2
                acc.geo_n += 1

            rule_id = clean_str(alert.get("rule_id")) or "Unknown"
            bump(acc.rule_id, rule_id)
            bump(acc.rule_desc, clean_str(alert.get("rule_description")))
            bump(acc.decoder, decoder)
            bump(acc.program, clean_str(alert.get("program_name")))
            bump(acc.location, clean_str(alert.get("location")))
            for group in groups:
                bump(acc.groups, group)
            tactics = [str(t).strip().lower() for t in (alert.get("mitre_tactics") or []) if str(t).strip()]
            for tactic in tactics:
                bump(acc.tactics, tactic)
            acc.mitre_present += bool(tactics)

            bump(acc.activity, activity_class(groups, rule_id))
            bump(acc.taxonomy, clean_str(alert.get("taxonomy_label")) or "OtherAlert")

            label = clean_str(alert.get("weak_label")).upper()
            if label == "ATTACK":
                acc.attack += 1
            elif label == "BENIGN":
                acc.benign += 1
            else:
                acc.unknown += 1
            acc.posture += posture

    if not windows:
        raise SystemExit(f"No usable alerts found in {input_file}")
    return windows, counters


# --------------------------------------------------------------------------
# window feature construction
# --------------------------------------------------------------------------
def build_window_frame(windows: Dict[tuple, WindowAcc], attack_ratio: float, roll: int) -> tuple[pd.DataFrame, Dict[str, Dict[str, int]]]:
    """Second pass: order windows in time and derive causal/novelty features."""
    ordered = sorted(windows.items(), key=lambda item: (item[0][0], item[0][1]))

    seen_ip_freq: Dict[str, int] = {}
    seen_users: set[str] = set()
    agent_hist: Dict[str, deque] = {}
    agent_prev_ts: Dict[str, float] = {}
    agent_index: Dict[str, int] = {}

    rows: List[Dict[str, Any]] = []
    for (window_start, agent_id), acc in ordered:
        n = acc.n
        window_dt = datetime.fromisoformat(window_start.replace("Z", "+00:00")).astimezone(timezone.utc)

        times = sorted(acc.ts)
        span = times[-1] - times[0] if len(times) > 1 else 0.0
        if len(times) > 1:
            gaps = np.diff(np.asarray(times, dtype=np.float64))
            mean_ia = float(gaps.mean())
            std_ia = float(gaps.std())
            min_ia = float(gaps.min())
        else:
            mean_ia = std_ia = min_ia = 0.0

        ip_entropy, ip_entropy_norm, ip_top = shannon(acc.src_ip)
        user_entropy, user_entropy_norm, user_top = shannon(acc.src_user)
        _, port_entropy_norm, _ = shannon(acc.src_port)
        _, country_entropy_norm, country_top = shannon(acc.country)
        _, rule_entropy_norm, rule_top = shannon(acc.rule_id)

        # --- novelty, computed against everything seen strictly earlier -----
        ips = set(acc.src_ip)
        users = set(acc.src_user)
        new_ips = ips - set(seen_ip_freq)
        new_users = users - seen_users
        prior_freqs = [seen_ip_freq.get(ip, 0) for ip in ips]
        mean_seen = float(np.mean(prior_freqs)) if prior_freqs else 0.0
        max_seen = float(np.max(prior_freqs)) if prior_freqs else 0.0
        for ip, count in acc.src_ip.items():
            seen_ip_freq[ip] = seen_ip_freq.get(ip, 0) + count
        seen_users |= users

        # --- per-agent causal baseline --------------------------------------
        hist = agent_hist.setdefault(agent_id, deque(maxlen=roll))
        counts_hist = [h[0] for h in hist]
        ip_hist = [h[1] for h in hist]
        lag1 = float(counts_hist[-1]) if counts_hist else 0.0
        lag2 = float(counts_hist[-2]) if len(counts_hist) > 1 else 0.0
        roll_mean = float(np.mean(counts_hist)) if counts_hist else 0.0
        roll_std = float(np.std(counts_hist)) if counts_hist else 0.0
        count_z = safe_div(n - roll_mean, roll_std) if roll_std > 0 else 0.0
        ip_roll_mean = float(np.mean(ip_hist)) if ip_hist else 0.0
        ip_roll_std = float(np.std(ip_hist)) if ip_hist else 0.0
        uniq_ip = len(acc.src_ip)
        ip_z = safe_div(uniq_ip - ip_roll_mean, ip_roll_std) if ip_roll_std > 0 else 0.0
        prev_ts = agent_prev_ts.get(agent_id)
        gap = float(times[0] - prev_ts) if prev_ts is not None else 0.0
        agent_prev_ts[agent_id] = times[-1]
        idx = agent_index.get(agent_id, 0)
        agent_index[agent_id] = idx + 1
        hist.append((n, uniq_ip))

        labelled = acc.attack + acc.benign
        binary_target = "UNKNOWN"
        if labelled > 0:
            binary_target = "ATTACK" if (acc.attack / labelled) >= attack_ratio else "BENIGN"

        lat_mean = safe_div(acc.lat_sum, acc.geo_n)
        lon_mean = safe_div(acc.lon_sum, acc.geo_n)
        lat_std = std_from_moments(acc.lat_sum, acc.lat_sq, acc.geo_n)
        lon_std = std_from_moments(acc.lon_sum, acc.lon_sq, acc.geo_n)

        row: Dict[str, Any] = {
            # ---------------- metadata ----------------
            "window_start": window_dt,
            "agent_id": agent_id,
            "agent_name": acc.agent_name or "Unknown",
            "top_rule_id": top_key(acc.rule_id),
            "top_rule_description": top_key(acc.rule_desc, default=""),
            "top_decoder": top_key(acc.decoder),
            "top_program": top_key(acc.program, default=""),
            "top_location": top_key(acc.location),
            "top_country": top_key(acc.country, default=""),
            "posture_ratio": safe_div(acc.posture, n),
            "attack_alert_count": acc.attack,
            "benign_alert_count": acc.benign,
            "unknown_alert_count": acc.unknown,
            "binary_target": binary_target,
            "activity_target": top_key(acc.activity, default="Other"),
            "taxonomy_target": top_key(acc.taxonomy, default="OtherAlert"),
            # ---------------- behavioral ----------------
            "alert_count": n,
            "log_alert_count": math.log1p(n),
            "span_seconds": span,
            "alerts_per_second": safe_div(n, max(span, 1.0)),
            "mean_interarrival": mean_ia,
            "std_interarrival": std_ia,
            "min_interarrival": min_ia,
            "burstiness_index": safe_div(std_ia, mean_ia + EPS),
            "unique_src_ip": uniq_ip,
            "unique_src_user": len(acc.src_user),
            "unique_dst_user": len(acc.dst_user),
            "unique_src_port": len(acc.src_port),
            "src_ip_entropy": ip_entropy,
            "src_ip_entropy_norm": ip_entropy_norm,
            "top_src_ip_share": ip_top,
            "src_user_entropy": user_entropy,
            "src_user_entropy_norm": user_entropy_norm,
            "top_src_user_share": user_top,
            "src_port_entropy_norm": port_entropy_norm,
            "alerts_per_src_ip": safe_div(n, uniq_ip),
            "users_per_src_ip": safe_div(len(acc.src_user), uniq_ip),
            "ports_per_src_ip": safe_div(len(acc.src_port), uniq_ip),
            "alerts_per_src_user": safe_div(n, len(acc.src_user)),
            "src_ip_present_ratio": safe_div(acc.src_ip_present, n),
            "src_port_present_ratio": safe_div(acc.src_port_present, n),
            "dst_user_present_ratio": safe_div(acc.dst_user_present, n),
            "unique_country": len(acc.country),
            "unique_city": len(acc.city),
            "country_entropy_norm": country_entropy_norm,
            "top_country_share": country_top,
            "geo_missing_ratio": safe_div(n - acc.geo_n, n),
            "geo_lat_mean": lat_mean,
            "geo_lon_mean": lon_mean,
            "geo_lat_std": lat_std,
            "geo_lon_std": lon_std,
            "geo_spread": math.sqrt(lat_std * lat_std + lon_std * lon_std),
            "new_src_ip_count": len(new_ips),
            "new_src_ip_ratio": safe_div(len(new_ips), uniq_ip),
            "repeat_src_ip_ratio": safe_div(uniq_ip - len(new_ips), uniq_ip),
            "new_src_user_count": len(new_users),
            "new_src_user_ratio": safe_div(len(new_users), len(acc.src_user)),
            "mean_src_ip_seen_before": mean_seen,
            "max_src_ip_seen_before": max_seen,
            "root_user_ratio": safe_div(acc.root_hits, acc.user_hits),
            "system_user_ratio": safe_div(acc.system_hits, acc.user_hits),
            "agent_gap_seconds": gap,
            "agent_count_lag1": lag1,
            "agent_count_lag2": lag2,
            "agent_count_roll_mean": roll_mean,
            "agent_count_roll_std": roll_std,
            "agent_count_z": count_z,
            "agent_uniqip_roll_mean": ip_roll_mean,
            "agent_uniqip_z": ip_z,
            "agent_window_index": float(idx),
            # ---------------- context ----------------
            "event_hour": float(window_dt.hour),
            "hour_sin": math.sin(2 * math.pi * window_dt.hour / 24.0),
            "hour_cos": math.cos(2 * math.pi * window_dt.hour / 24.0),
            "day_of_week": float(window_dt.weekday()),
            "is_weekend": float(window_dt.weekday() >= 5),
            "is_night": float(window_dt.hour < 6 or window_dt.hour >= 22),
            # ---------------- signature ----------------
            "rule_level_mean": safe_div(acc.levels_sum, n),
            "rule_level_max": acc.levels_max,
            "rule_level_min": 0.0 if acc.levels_min == float("inf") else acc.levels_min,
            "rule_level_std": std_from_moments(acc.levels_sum, acc.levels_sq, n),
            "rule_level_sum": acc.levels_sum,
            "rule_level_range": acc.levels_max - (0.0 if acc.levels_min == float("inf") else acc.levels_min),
            "level_ge_7_count": acc.lvl7,
            "level_ge_10_count": acc.lvl10,
            "level_ge_12_count": acc.lvl12,
            "level_ge_7_ratio": safe_div(acc.lvl7, n),
            "unique_rule_count": len(acc.rule_id),
            "rule_entropy_norm": rule_entropy_norm,
            "top_rule_share": rule_top,
            "rule_firedtimes_mean": safe_div(acc.fired_sum, n),
            "rule_firedtimes_max": acc.fired_max,
            "rule_firedtimes_sum": acc.fired_sum,
            "mitre_tagged_ratio": safe_div(acc.mitre_present, n),
            "credential_tactic_ratio": safe_div(acc.tactics.get("credential access", 0), n),
            "lateral_tactic_ratio": safe_div(acc.tactics.get("lateral movement", 0), n),
            "impact_tactic_count": float(acc.tactics.get("impact", 0)),
            "evasion_tactic_count": float(acc.tactics.get("defense evasion", 0)),
            "unique_decoder_count": len(acc.decoder),
            "unique_location_count": len(acc.location),
        }
        for feature in GROUP_FEATURES:
            row[feature] = 0.0
        for group, count in acc.groups.items():
            feature = TRACKED_GROUPS.get(group)
            if feature:
                row[feature] += safe_div(count, n)
        rows.append(row)

    df = pd.DataFrame(rows)
    maps = {
        "agent_id": build_category_map(df["agent_id"]),
        "decoder": build_category_map(df["top_decoder"]),
        "program": build_category_map(df["top_program"]),
        "location": build_category_map(df["top_location"]),
    }
    df["agent_id_code"] = df["agent_id"].map(maps["agent_id"]).fillna(0.0)
    df["decoder_code"] = df["top_decoder"].map(maps["decoder"]).fillna(0.0)
    df["program_code"] = df["top_program"].map(maps["program"]).fillna(0.0)
    df["location_code"] = df["top_location"].map(maps["location"]).fillna(0.0)

    missing = [column for column in FEATURE_COLUMNS if column not in df.columns]
    if missing:
        raise SystemExit(f"Feature spec declares columns the builder never produced: {missing}")
    for column in FEATURE_COLUMNS:
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0.0).replace([np.inf, -np.inf], 0.0).astype(np.float32)

    df.sort_values(["window_start", "agent_id"], inplace=True)
    return df.reset_index(drop=True), maps


def build_category_map(series: pd.Series) -> Dict[str, int]:
    mapping = {"Unknown": 0}
    for value in sorted({str(v) for v in series.tolist()}):
        if value not in mapping:
            mapping[value] = len(mapping)
    return mapping


# --------------------------------------------------------------------------
# splitting
# --------------------------------------------------------------------------
def date_split(df: pd.DataFrame, train_ratio: float, val_ratio: float) -> Dict[str, np.ndarray]:
    times = np.array(sorted(df["window_start"].drop_duplicates().tolist()))
    if len(times) < 3:
        raise SystemExit("Need at least three distinct windows for a date split")
    train_end = max(1, int(round(len(times) * train_ratio)))
    val_end = min(max(train_end + 1, int(round(len(times) * (train_ratio + val_ratio)))), len(times) - 1)
    bounds = {"train": set(times[:train_end]), "val": set(times[train_end:val_end]), "test": set(times[val_end:])}
    return {name: df.index[df["window_start"].isin(values)].to_numpy(dtype=int) for name, values in bounds.items()}


def stratified_random_split(df: pd.DataFrame, seed: int, train_ratio: float, val_ratio: float) -> Dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    out: Dict[str, List[int]] = {split: [] for split in SPLITS}
    for _, group in df.groupby("binary_target", sort=True):
        idx = group.index.to_numpy(copy=True)
        rng.shuffle(idx)
        n = len(idx)
        n_train = max(1, int(round(n * train_ratio))) if n >= 3 else n
        n_val = max(1, int(round(n * val_ratio))) if n - n_train >= 2 else max(0, n - n_train)
        out["train"].extend(idx[:n_train].tolist())
        out["val"].extend(idx[n_train : n_train + n_val].tolist())
        out["test"].extend(idx[n_train + n_val :].tolist())
    return {split: np.array(sorted(values), dtype=int) for split, values in out.items()}


def groupkfold_split(df: pd.DataFrame, fold: int, n_folds: int) -> Dict[str, np.ndarray]:
    """Leave-one-agent-out. With 4 agents this is the strongest generalization
    test available, and it is deliberately brutal: agent 003 is the scanner."""
    agents = sorted(df["agent_id"].astype(str).unique().tolist())
    if len(agents) < 3:
        raise SystemExit("Need at least three agents for a groupkfold split")
    n = min(n_folds, len(agents))
    mapped = fold % n
    test_agent = agents[mapped]
    val_agent = agents[(mapped + 1) % n]
    train_agents = set(agents) - {test_agent, val_agent}
    return {
        "train": df.index[df["agent_id"].isin(train_agents)].to_numpy(dtype=int),
        "val": df.index[df["agent_id"] == val_agent].to_numpy(dtype=int),
        "test": df.index[df["agent_id"] == test_agent].to_numpy(dtype=int),
    }


def build_split_indices(df: pd.DataFrame, args: argparse.Namespace, mode: str, fold: int | None) -> Dict[str, np.ndarray]:
    if mode == "date":
        return date_split(df, args.train_ratio, args.val_ratio)
    if mode == "random":
        return stratified_random_split(df, args.seed, args.train_ratio, args.val_ratio)
    if mode == "groupkfold":
        return groupkfold_split(df, int(fold or 0), args.n_folds)
    raise ValueError(f"Unsupported split mode: {mode}")


# --------------------------------------------------------------------------
# materialization
# --------------------------------------------------------------------------
def count_labels(values: Iterable[object]) -> Dict[str, int]:
    counts = pd.Series([str(v) for v in values], dtype=object).value_counts()
    return {str(k): int(v) for k, v in counts.items()}


def frame_for_target(df: pd.DataFrame, target_column: str) -> pd.DataFrame:
    out = df.loc[:, FEATURE_COLUMNS + META_COLUMNS].copy()
    out["target"] = df[target_column].astype(str).to_numpy(copy=True)
    return out


def write_parquet(base: Path, pipeline: str, split: str, df: pd.DataFrame) -> None:
    if df.empty:
        return
    folder = base / pipeline / split
    folder.mkdir(parents=True, exist_ok=True)
    df.to_parquet(folder / "part-00000.parquet", index=False)


def write_label_map(path: Path, labels: Sequence[str], binary: bool) -> None:
    ordered = sorted({str(v) for v in labels})
    if binary and {"BENIGN", "ATTACK"}.issubset(set(ordered)):
        ordered = ["BENIGN", "ATTACK"]
    write_json(path, {label: index for index, label in enumerate(ordered)})


def collapse_rare(df: pd.DataFrame, column: str, min_windows: int, fallback: str) -> Dict[str, int]:
    if min_windows <= 1:
        return {}
    counts = count_labels(df[column])
    rare = {label: count for label, count in counts.items() if count < min_windows and label != fallback}
    if rare:
        df.loc[df[column].isin(rare.keys()), column] = fallback
    return rare


def materialize(base: Path, df: pd.DataFrame, split_indices: Dict[str, np.ndarray], args: argparse.Namespace) -> Dict[str, Any]:
    """Write every pipeline. UNKNOWN windows are excluded from the supervised
    pipelines (they are netstat/dpkg churn the labeller could not classify) but
    kept in the anomaly evaluation sets, where no label is needed for fitting."""
    stats: Dict[str, Any] = {}

    for split, indices in split_indices.items():
        part = df.loc[indices]
        if part.empty:
            raise SystemExit(f"Split '{split}' is empty")
        labelled = part[part["binary_target"] != "UNKNOWN"]

        binary_df = frame_for_target(labelled, "binary_target")
        write_parquet(base, "binary", split, binary_df)

        multi_df = frame_for_target(part, "activity_target")
        write_parquet(base, "multiclass", split, multi_df)

        tax_df = frame_for_target(part, "taxonomy_target")
        write_parquet(base, "taxonomy", split, tax_df)

        stats[split] = {
            "windows": int(len(part)),
            "labelled_windows": int(len(labelled)),
            "binary": count_labels(labelled["binary_target"]),
            "activity": count_labels(part["activity_target"]),
            "taxonomy": count_labels(part["taxonomy_target"]),
            "window_start_min": str(part["window_start"].min()),
            "window_start_max": str(part["window_start"].max()),
            "agents": sorted(part["agent_id"].unique().tolist()),
        }

    # --- anomaly pipeline --------------------------------------------------
    # Three fitting policies, because the classic "train on BENIGN only" setup
    # is degenerate here: 97.8% of BENIGN rows are vulnerability-scanner output,
    # so a detector fitted on them merely learns "not Trivy".
    train_part = df.loc[split_indices["train"]]
    quiet_cut = float(train_part["alert_count"].quantile(args.quiet_quantile))
    policies = {
        "train_benign": train_part[train_part["binary_target"] == "BENIGN"],
        "train_quiet": train_part[train_part["alert_count"] <= quiet_cut],
        "train_all": train_part,
    }
    for name, part in policies.items():
        write_parquet(base, "anomaly", name, frame_for_target(part, "binary_target"))

    for split, folder in (("val", "val_mixed"), ("test", "test_mixed")):
        part = df.loc[split_indices[split]]
        part = part[part["binary_target"] != "UNKNOWN"]
        write_parquet(base, "anomaly", folder, frame_for_target(part, "binary_target"))

    stats["anomaly"] = {
        "quiet_quantile": args.quiet_quantile,
        "quiet_alert_count_cut": quiet_cut,
        "fit_rows": {name: int(len(part)) for name, part in policies.items()},
    }
    if stats["anomaly"]["fit_rows"]["train_quiet"] == 0:
        raise SystemExit("Anomaly 'quiet' fitting set is empty")

    labelled_all = df[df["binary_target"] != "UNKNOWN"]
    write_label_map(base / "binary" / "label_map.json", labelled_all["binary_target"].unique(), binary=True)
    write_label_map(base / "multiclass" / "label_map.json", df["activity_target"].unique(), binary=False)
    write_label_map(base / "taxonomy" / "label_map.json", df["taxonomy_target"].unique(), binary=False)
    return stats


def prepare_mode(df: pd.DataFrame, maps: Dict[str, Dict[str, int]], args: argparse.Namespace, mode: str, counters: Dict[str, int], rare: Dict[str, Any], fold: int | None = None) -> None:
    base = resolve_from_root(args.out_dir) / mode / args.dataset
    if mode == "groupkfold":
        base = base / f"fold_{fold}"
    clear_dir(base)
    split_indices = build_split_indices(df, args, mode, fold)
    stats = materialize(base, df, split_indices, args)

    write_json(base / "feature_columns.json", FEATURE_COLUMNS)
    write_json(base / "feature_groups.json", FEATURE_GROUPS)
    write_json(base / "category_maps.json", maps)
    write_json(base / "split_policy.json", {"split_mode": mode, "fold": fold, "splits": stats})
    write_json(
        base / "prepare_dataset_summary.json",
        {
            "dataset": args.dataset,
            "source": str(resolve_from_root(args.in_file)),
            "exclude_posture": bool(args.exclude_posture),
            "windows": int(len(df)),
            "feature_count": len(FEATURE_COLUMNS),
            "feature_group_sizes": {name: len(cols) for name, cols in FEATURE_GROUPS.items()},
            "window_attack_ratio_threshold": args.attack_ratio,
            "rolling_baseline_windows": args.roll,
            "ingest_counters": counters,
            "collapsed_rare_classes": rare,
            "binary_counts": count_labels(df[df["binary_target"] != "UNKNOWN"]["binary_target"]),
            "unknown_windows": int((df["binary_target"] == "UNKNOWN").sum()),
            "activity_counts": count_labels(df["activity_target"]),
            "taxonomy_counts": count_labels(df["taxonomy_target"]),
            "label_policy": (
                "A window is ATTACK when attack_alerts / (attack_alerts + benign_alerts) "
                f">= {args.attack_ratio}; UNKNOWN when the window holds no labelled alert. "
                "Alert-level labels are the export's own weak_label field."
            ),
        },
    )
    print(f"Prepared {mode}{'' if fold is None else f' fold_{fold}'} -> {base}")


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
    parser = argparse.ArgumentParser(description="Build ARGOS-LAB window datasets from the raw alert stream")
    parser.add_argument("--in_file", default=str(DEFAULT_IN_FILE))
    parser.add_argument("--out_dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--dataset", default=DATASET_NAME)
    parser.add_argument("--split_mode", nargs="+", default=["date"], help="date, random, groupkfold, all, or comma-separated")
    parser.add_argument("--train_ratio", type=float, default=0.70)
    parser.add_argument("--val_ratio", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n_folds", type=int, default=4, help="leave-one-agent-out; the capture has 4 agents")
    parser.add_argument("--fold", type=int, default=0)
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--attack_ratio", type=float, default=0.5, help="attack share needed to label a window ATTACK")
    parser.add_argument("--roll", type=int, default=15, help="windows in the per-agent rolling baseline")
    parser.add_argument("--quiet_quantile", type=float, default=0.60, help="alert_count quantile defining 'routine' windows for anomaly fitting")
    parser.add_argument("--min_class_windows", type=int, default=30, help="collapse multiclass labels rarer than this")
    parser.add_argument(
        "--exclude_posture",
        action="store_true",
        help="drop Trivy/SCA/syscheck posture findings before windowing. The manifest asks for metrics "
             "with and without these rows, since 97.8%% of BENIGN alerts are scanner output.",
    )
    parser.add_argument("--progress_every", type=int, default=200_000)
    args = parser.parse_args()

    ensure_pyarrow()
    if args.train_ratio <= 0 or args.val_ratio <= 0 or args.train_ratio + args.val_ratio >= 1:
        raise SystemExit("train_ratio and val_ratio must be positive and sum to less than 1")

    input_file = resolve_from_root(args.in_file)
    if not input_file.exists():
        raise SystemExit(f"Input file does not exist: {input_file}")
    modes = normalize_modes(args.split_mode)

    print("== prepare_dataset (ARGOS-LAB) ==")
    print(f"Input           : {input_file}")
    print(f"Dataset         : {args.dataset}")
    print(f"Split modes     : {modes}")
    print(f"Exclude posture : {bool(args.exclude_posture)}")
    print(f"Features        : {len(FEATURE_COLUMNS)} "
          f"({', '.join(f'{k}={len(v)}' for k, v in FEATURE_GROUPS.items())})")
    print("Streaming alerts ...", flush=True)

    windows, counters = stream_windows(input_file, bool(args.exclude_posture), int(args.progress_every))
    print(f"Alerts read     : {counters['rows']:,} (kept {counters['kept']:,}, "
          f"posture skipped {counters['skipped_posture']:,}, bad json {counters['bad_json']:,})")
    print(f"Windows         : {len(windows):,}")
    print("Deriving window features ...", flush=True)

    df, maps = build_window_frame(windows, args.attack_ratio, args.roll)
    rare = {
        "activity": collapse_rare(df, "activity_target", args.min_class_windows, "Other"),
        "taxonomy": collapse_rare(df, "taxonomy_target", args.min_class_windows, "OtherAlert"),
    }
    print(f"Binary          : {count_labels(df[df['binary_target'] != 'UNKNOWN']['binary_target'])} "
          f"(+{int((df['binary_target'] == 'UNKNOWN').sum()):,} UNKNOWN held out)")
    print(f"Activity        : {count_labels(df['activity_target'])}")
    if any(rare.values()):
        print(f"Collapsed rare  : {rare}")

    for mode in modes:
        if mode == "groupkfold":
            folds = range(args.n_folds) if args.all_folds else [args.fold]
            root = resolve_from_root(args.out_dir) / mode / args.dataset
            root.mkdir(parents=True, exist_ok=True)
            write_json(root / "feature_columns.json", FEATURE_COLUMNS)
            write_json(root / "feature_groups.json", FEATURE_GROUPS)
            for fold in folds:
                prepare_mode(df, maps, args, mode, counters, rare, fold=int(fold))
        else:
            prepare_mode(df, maps, args, mode, counters, rare)


if __name__ == "__main__":
    main()
