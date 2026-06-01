#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import math
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

import numpy as np
import pandas as pd

import prepare_dataset_identity as base


DATASET_NAME = "CSR-LANL"
DEFAULT_IN_DIR = Path("out/CSR-LANL")
DEFAULT_OUT_DIR = Path("src/models/CSR-LANL/datasets_redteam_identity_v3")

V3_CONTEXT_MINUTES = (15, 60)
V3_ROLLING_WINDOWS = (15, 60)
V3_ROLLING_METRICS = (
    "total_event_count",
    "auth_event_count",
    "auth_fail_count",
    "auth_failure_ratio",
    "auth_unique_dst_computer_count",
    "flow_event_count",
    "flow_byte_sum",
    "flow_unique_dst_computer_count",
    "flow_unique_dst_port_count",
    "identity_unique_pair_count",
    "identity_novelty_signal_count",
)
V3_BASE_FEATURE_COLUMNS = (
    "v3_hour_of_day_sin",
    "v3_hour_of_day_cos",
    "v3_minute_of_day_sin",
    "v3_minute_of_day_cos",
    "v3_is_off_hours",
    "v3_is_weekend_proxy",
    "v3_entity_seen_window_count",
    "v3_entity_window_gap_seconds",
    "v3_total_event_log1p",
    "v3_destination_breadth",
    "v3_auth_lateral_pressure",
    "v3_auth_failure_pressure",
    "v3_flow_fanout_pressure",
    "v3_flow_volume_pressure",
    "v3_identity_novelty_ratio",
    "v3_identity_novelty_flag_count",
    "v3_pre_model_risk_score",
)
V3_LABEL_COLUMNS = (
    "label_exact",
    "label_context_15m",
    "label_context_60m",
    "label_entity_day",
    "label_entity_attack_period",
    "v3_target_policy",
)
TARGET_POLICY_TO_COLUMN = {
    "exact": "label_exact",
    "context_15m": "label_context_15m",
    "context_60m": "label_context_60m",
    "entity_day": "label_entity_day",
}


def v3_feature_columns() -> List[str]:
    columns = list(V3_BASE_FEATURE_COLUMNS)
    for metric in V3_ROLLING_METRICS:
        columns.append(f"v3_entity_{metric}_prior_mean")
        columns.append(f"v3_entity_{metric}_prior_zscore")
        for window in V3_ROLLING_WINDOWS:
            columns.append(f"v3_entity_{metric}_roll{window}_mean")
            columns.append(f"v3_entity_{metric}_roll{window}_ratio")
    return columns


V3_FEATURE_COLUMNS = v3_feature_columns()
FEATURE_COLUMNS = list(dict.fromkeys([*base.FEATURE_COLUMNS, *V3_FEATURE_COLUMNS]))
META_COLUMNS = list(dict.fromkeys([*base.META_COLUMNS, *V3_LABEL_COLUMNS]))


def activate_v3_schema() -> None:
    base.FEATURE_COLUMNS = FEATURE_COLUMNS
    base.META_COLUMNS = META_COLUMNS


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def bool_series(values: pd.Series) -> pd.Series:
    if pd.api.types.is_bool_dtype(values):
        return values.fillna(False).astype(bool)
    return values.astype(str).str.strip().str.lower().isin({"1", "true", "t", "yes", "y"})


def ensure_numeric_columns(df: pd.DataFrame, columns: Iterable[str]) -> None:
    for column in columns:
        if column not in df.columns:
            df[column] = 0.0
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0.0).astype(np.float32)


def rolling_mean_by_entity(ordered: pd.DataFrame, metric: str, window: int) -> pd.Series:
    shifted = ordered.groupby("entity", sort=False, observed=True)[metric].shift(1)
    rolled = shifted.groupby(ordered["entity"], sort=False, observed=True).rolling(window, min_periods=1).mean()
    rolled.index = rolled.index.droplevel(0)
    return rolled.reindex(ordered.index).fillna(0.0).astype(np.float32)


def prior_mean_zscore_by_entity(ordered: pd.DataFrame, metric: str, seen_count: pd.Series) -> tuple[pd.Series, pd.Series]:
    current = ordered[metric].astype(np.float64)
    grouped = ordered.groupby("entity", sort=False, observed=True)[metric]
    prior_sum = grouped.cumsum().astype(np.float64) - current
    prior_sq_sum = (ordered[metric].astype(np.float64) ** 2).groupby(ordered["entity"], sort=False, observed=True).cumsum() - (current**2)
    count = seen_count.astype(np.float64)
    prior_mean = np.divide(prior_sum, count, out=np.zeros(len(ordered), dtype=np.float64), where=count > 0)
    prior_var = np.divide(prior_sq_sum, count, out=np.zeros(len(ordered), dtype=np.float64), where=count > 1) - prior_mean**2
    prior_std = np.sqrt(np.maximum(prior_var, 0.0))
    zscore = np.divide(current - prior_mean, prior_std, out=np.zeros(len(ordered), dtype=np.float64), where=prior_std > 1e-6)
    return pd.Series(prior_mean, index=ordered.index).astype(np.float32), pd.Series(zscore, index=ordered.index).astype(np.float32)


def membership_mask(df: pd.DataFrame, lookup: set[tuple[int, str]]) -> np.ndarray:
    return np.fromiter(
        ((int(window), str(entity)) in lookup for window, entity in zip(df["window_start"], df["entity"])),
        dtype=bool,
        count=len(df),
    )


def add_context_labels(df: pd.DataFrame, window_seconds: int) -> Dict[str, Any]:
    df["label_exact"] = bool_series(df["redteam_exact"])
    df["day_index"] = pd.to_numeric(df["day_index"], errors="coerce").fillna(0).astype(np.int64)
    df["window_start"] = pd.to_numeric(df["window_start"], errors="coerce").fillna(0).astype(np.int64)
    df["entity"] = df["entity"].astype(str)

    exact_rows = df.loc[df["label_exact"], ["window_start", "entity", "day_index"]].copy()
    exact_pairs = {(int(row.window_start), str(row.entity)) for row in exact_rows.itertuples(index=False)}
    for minutes in V3_CONTEXT_MINUTES:
        radius_windows = int(math.ceil((int(minutes) * 60.0) / float(window_seconds)))
        context_pairs: set[tuple[int, str]] = set()
        for window_start, entity in exact_pairs:
            for offset in range(-radius_windows, radius_windows + 1):
                context_pairs.add((int(window_start + offset * window_seconds), str(entity)))
        df[f"label_context_{minutes}m"] = membership_mask(df, context_pairs)

    entity_days = {(str(row.entity), int(row.day_index)) for row in exact_rows.itertuples(index=False)}
    df["label_entity_day"] = np.fromiter(
        ((str(entity), int(day)) in entity_days for entity, day in zip(df["entity"], df["day_index"])),
        dtype=bool,
        count=len(df),
    )

    if exact_rows.empty:
        df["label_entity_attack_period"] = False
    else:
        periods = exact_rows.groupby("entity", sort=False)["window_start"].agg(["min", "max"])
        start = df["entity"].map(periods["min"])
        end = df["entity"].map(periods["max"])
        df["label_entity_attack_period"] = start.notna() & (df["window_start"] >= start.fillna(0).astype(np.int64)) & (df["window_start"] <= end.fillna(0).astype(np.int64))

    return {
        "exact_windows": int(df["label_exact"].sum()),
        "context_15m_windows": int(df["label_context_15m"].sum()),
        "context_60m_windows": int(df["label_context_60m"].sum()),
        "entity_day_windows": int(df["label_entity_day"].sum()),
        "entity_attack_period_windows": int(df["label_entity_attack_period"].sum()),
        "redteam_entities": int(exact_rows["entity"].nunique()) if not exact_rows.empty else 0,
        "redteam_entity_days": int(len(entity_days)),
    }


def add_v3_features(df: pd.DataFrame) -> None:
    required = set(V3_ROLLING_METRICS) | {
        "auth_event_count",
        "auth_fail_count",
        "auth_failure_ratio",
        "auth_unique_dst_computer_count",
        "flow_event_count",
        "flow_byte_sum",
        "flow_unique_dst_computer_count",
        "flow_unique_dst_port_count",
        "dns_unique_dst_computer_count",
        "identity_unique_pair_count",
        "identity_novelty_signal_count",
        "has_new_src_user",
        "has_new_dst_computer",
        "has_new_process",
    }
    ensure_numeric_columns(df, required)
    ordered = df.loc[:, ["window_start", "entity", *sorted(required)]].copy()
    ordered["_v3_order"] = np.arange(len(ordered), dtype=np.int64)
    ordered["entity"] = ordered["entity"].astype(str).astype("category")
    ordered["window_start"] = pd.to_numeric(ordered["window_start"], errors="coerce").fillna(0).astype(np.int64)
    ordered = ordered.sort_values(["entity", "window_start", "_v3_order"], kind="mergesort")

    features = pd.DataFrame(index=ordered.index)
    seconds = ordered["window_start"].to_numpy(dtype=np.float64, copy=False)
    minute_of_day = np.floor((np.mod(seconds, 86_400.0)) / 60.0)
    hour_of_day = np.floor(minute_of_day / 60.0)
    hour_angle = 2.0 * math.pi * hour_of_day / 24.0
    minute_angle = 2.0 * math.pi * minute_of_day / 1440.0
    features["v3_hour_of_day_sin"] = np.sin(hour_angle).astype(np.float32)
    features["v3_hour_of_day_cos"] = np.cos(hour_angle).astype(np.float32)
    features["v3_minute_of_day_sin"] = np.sin(minute_angle).astype(np.float32)
    features["v3_minute_of_day_cos"] = np.cos(minute_angle).astype(np.float32)
    features["v3_is_off_hours"] = ((hour_of_day < 7) | (hour_of_day >= 19)).astype(np.float32)
    features["v3_is_weekend_proxy"] = ((np.floor(seconds / 86_400.0).astype(np.int64) % 7) >= 5).astype(np.float32)

    grouped = ordered.groupby("entity", sort=False, observed=True)
    seen_count = grouped.cumcount().astype(np.float32)
    features["v3_entity_seen_window_count"] = seen_count
    features["v3_entity_window_gap_seconds"] = grouped["window_start"].diff().fillna(0).clip(lower=0).astype(np.float32)
    features["v3_total_event_log1p"] = np.log1p(ordered["total_event_count"].astype(np.float32)).astype(np.float32)
    features["v3_destination_breadth"] = (
        ordered["auth_unique_dst_computer_count"] + ordered["flow_unique_dst_computer_count"] + ordered["dns_unique_dst_computer_count"]
    ).astype(np.float32)
    features["v3_auth_lateral_pressure"] = (
        np.log1p(ordered["auth_event_count"].astype(np.float32)) * np.log1p(ordered["auth_unique_dst_computer_count"].astype(np.float32))
    ).astype(np.float32)
    features["v3_auth_failure_pressure"] = (
        ordered["auth_fail_count"].astype(np.float32)
        * (1.0 + ordered["auth_failure_ratio"].astype(np.float32))
        * np.log1p(ordered["auth_event_count"].astype(np.float32))
    ).astype(np.float32)
    features["v3_flow_fanout_pressure"] = (
        np.log1p(ordered["flow_event_count"].astype(np.float32))
        * np.log1p(ordered["flow_unique_dst_computer_count"].astype(np.float32) + ordered["flow_unique_dst_port_count"].astype(np.float32))
    ).astype(np.float32)
    features["v3_flow_volume_pressure"] = np.log1p(ordered["flow_byte_sum"].astype(np.float32)).astype(np.float32)
    identity_denominator = ordered["identity_unique_pair_count"].astype(np.float32) + 1.0
    features["v3_identity_novelty_ratio"] = (ordered["identity_novelty_signal_count"].astype(np.float32) / identity_denominator).astype(np.float32)
    features["v3_identity_novelty_flag_count"] = (
        ordered["identity_novelty_signal_count"].astype(np.float32)
        + ordered["has_new_src_user"].astype(np.float32)
        + ordered["has_new_dst_computer"].astype(np.float32)
        + ordered["has_new_process"].astype(np.float32)
    ).astype(np.float32)

    risk = (
        features["v3_auth_failure_pressure"]
        + features["v3_auth_lateral_pressure"]
        + features["v3_flow_fanout_pressure"]
        + features["v3_identity_novelty_flag_count"] * 2.0
        + features["v3_identity_novelty_ratio"] * 5.0
        + features["v3_is_off_hours"] * 0.5
    )
    features["v3_pre_model_risk_score"] = pd.to_numeric(risk, errors="coerce").fillna(0.0).astype(np.float32)

    for metric in V3_ROLLING_METRICS:
        current = ordered[metric].astype(np.float32)
        prior_mean, prior_zscore = prior_mean_zscore_by_entity(ordered, metric, seen_count)
        features[f"v3_entity_{metric}_prior_mean"] = prior_mean
        features[f"v3_entity_{metric}_prior_zscore"] = prior_zscore
        for window in V3_ROLLING_WINDOWS:
            mean_values = rolling_mean_by_entity(ordered, metric, window)
            ratio_values = (current / (mean_values + 1.0)).astype(np.float32)
            ratio_values[seen_count <= 0] = 0.0
            features[f"v3_entity_{metric}_roll{window}_mean"] = mean_values
            features[f"v3_entity_{metric}_roll{window}_ratio"] = ratio_values

    features.replace([np.inf, -np.inf], 0.0, inplace=True)
    features.fillna(0.0, inplace=True)
    features["_v3_order"] = ordered["_v3_order"].to_numpy(dtype=np.int64, copy=True)
    features = features.sort_values("_v3_order", kind="mergesort").reset_index(drop=True)
    for column in V3_FEATURE_COLUMNS:
        df[column] = pd.to_numeric(features[column], errors="coerce").fillna(0.0).astype(np.float32)


def apply_target_policy(df: pd.DataFrame, target_policy: str) -> Dict[str, Any]:
    if target_policy not in TARGET_POLICY_TO_COLUMN:
        raise SystemExit(f"Unsupported target_policy={target_policy!r}")
    exact = bool_series(df["label_exact"])
    context_15m = bool_series(df["label_context_15m"])
    context_60m = bool_series(df["label_context_60m"])
    entity_day = bool_series(df["label_entity_day"])
    attack = bool_series(df[TARGET_POLICY_TO_COLUMN[target_policy]])

    labels = np.full(len(df), "BENIGN", dtype=object)
    if target_policy == "entity_day":
        labels[entity_day.to_numpy(dtype=bool)] = "RedTeamEntityDay"
    if target_policy in {"context_60m", "entity_day"}:
        labels[context_60m.to_numpy(dtype=bool)] = "RedTeamContext60m"
    if target_policy in {"context_15m", "context_60m", "entity_day"}:
        labels[context_15m.to_numpy(dtype=bool)] = "RedTeamContext15m"
    labels[exact.to_numpy(dtype=bool)] = "RedTeamExact"

    df["binary_target"] = np.where(attack.to_numpy(dtype=bool), "ATTACK", "BENIGN")
    df["multiclass_target_raw"] = labels
    df["multiclass_target"] = labels
    df["redteam_near"] = context_60m.astype(bool)
    df["v3_target_policy"] = target_policy
    return {
        "target_policy": target_policy,
        "target_column": TARGET_POLICY_TO_COLUMN[target_policy],
        "target_attack_windows": int(attack.sum()),
        "exact_attack_windows": int(exact.sum()),
        "context_15m_windows": int(context_15m.sum()),
        "context_60m_windows": int(context_60m.sum()),
        "entity_day_windows": int(entity_day.sum()),
    }


def add_sample_indices(selected: set[int], indices: Sequence[int]) -> None:
    selected.update(int(index) for index in indices)


def sample_group_indices(group: pd.DataFrame, sample_size: int, rng: np.random.Generator) -> np.ndarray:
    if sample_size <= 0 or group.empty:
        return np.array([], dtype=np.int64)
    indices = group.index.to_numpy(dtype=np.int64, copy=True)
    if len(indices) <= sample_size:
        return indices
    return rng.choice(indices, size=int(sample_size), replace=False)


def apply_v3_sampling(df: pd.DataFrame, args: argparse.Namespace) -> tuple[pd.DataFrame, Dict[str, Any]]:
    max_windows = None if args.max_windows is None or int(args.max_windows) <= 0 else int(args.max_windows)
    if args.no_v3_sampling and max_windows is None:
        return df.reset_index(drop=True), {"enabled": False, "reason": "no_v3_sampling"}

    rng = np.random.default_rng(int(args.seed))
    exact = bool_series(df["label_exact"])
    context_60m = bool_series(df["label_context_60m"])
    target_attack = df["binary_target"].astype(str).str.upper() != "BENIGN"
    must_keep = exact | target_attack
    if args.keep_context_60m:
        must_keep |= context_60m
    if args.keep_entity_day_context:
        must_keep |= bool_series(df["label_entity_day"])

    selected: set[int] = set(df.index[must_keep].astype(int).tolist())
    benign_pool = df.loc[~must_keep].copy()
    if not args.no_v3_sampling and not benign_pool.empty:
        if args.hard_benign_windows > 0 and "v3_pre_model_risk_score" in benign_pool.columns:
            hard = benign_pool.nlargest(int(args.hard_benign_windows), "v3_pre_model_risk_score")
            add_sample_indices(selected, hard.index.to_numpy(dtype=np.int64))
        if args.benign_per_day > 0 and "day_index" in benign_pool.columns:
            for _, group in benign_pool.groupby("day_index", sort=True):
                add_sample_indices(selected, sample_group_indices(group, int(args.benign_per_day), rng))
        if args.benign_per_hour > 0:
            hour_bucket = (pd.to_numeric(benign_pool["window_start"], errors="coerce").fillna(0).astype(np.int64) // 3600).astype(np.int64)
            for _, group in benign_pool.groupby([benign_pool["day_index"], hour_bucket], sort=True):
                add_sample_indices(selected, sample_group_indices(group, int(args.benign_per_hour), rng))

    if max_windows is not None:
        must_indices = set(df.index[must_keep].astype(int).tolist())
        if len(selected) > max_windows and len(must_indices) < max_windows:
            optional = np.array(sorted(selected - must_indices), dtype=np.int64)
            slots = int(max_windows - len(must_indices))
            optional_keep = rng.choice(optional, size=slots, replace=False) if len(optional) > slots else optional
            selected = set(must_indices) | set(int(index) for index in optional_keep)
        elif len(selected) < max_windows:
            remaining = np.array(sorted(set(df.index.astype(int).tolist()) - selected), dtype=np.int64)
            slots = min(int(max_windows - len(selected)), len(remaining))
            if slots > 0:
                add_sample_indices(selected, rng.choice(remaining, size=slots, replace=False))

    sampled = df.loc[sorted(selected)].sort_values(["window_start", "entity"], kind="mergesort").reset_index(drop=True)
    return sampled, {
        "enabled": not args.no_v3_sampling,
        "input_windows": int(len(df)),
        "output_windows": int(len(sampled)),
        "max_windows": max_windows,
        "must_keep_windows": int(must_keep.sum()),
        "hard_benign_windows": int(args.hard_benign_windows),
        "benign_per_day": int(args.benign_per_day),
        "benign_per_hour": int(args.benign_per_hour),
        "keep_context_60m": bool(args.keep_context_60m),
        "keep_entity_day_context": bool(args.keep_entity_day_context),
        "target_counts_after_sampling": base.count_labels(sampled["binary_target"]),
    }


def patch_metadata_v3(
    base_dir: Path,
    args: argparse.Namespace,
    label_policy: Dict[str, Any],
    target_policy: Dict[str, Any],
    sampling_policy: Dict[str, Any],
) -> None:
    v3_payload = {
        "profile_version": 3,
        "profile_name": "redteam_identity_v3",
        "v3_label_policy": label_policy,
        "v3_target_policy": target_policy,
        "v3_sampling_policy": sampling_policy,
        "v3_feature_profile": {
            "feature_count": len(V3_FEATURE_COLUMNS),
            "rolling_metrics": list(V3_ROLLING_METRICS),
            "rolling_windows": list(V3_ROLLING_WINDOWS),
            "base_features": list(V3_BASE_FEATURE_COLUMNS),
            "policy": "Causal entity-history, context-label, and SOC triage features layered on top of identity sketches.",
        },
    }
    for name in ["dataset_profile.json", "prepare_dataset_summary.json"]:
        path = base_dir / name
        payload = read_json(path) if path.exists() else {}
        payload.update(v3_payload)
        if name == "dataset_profile.json":
            payload["created_at_utc"] = payload.get("created_at_utc") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            fingerprint_source = {
                "config": payload.get("config", {}),
                "feature_columns": FEATURE_COLUMNS,
                "v3_label_policy": label_policy,
                "v3_target_policy": target_policy,
                "v3_sampling_policy": sampling_policy,
            }
            payload["config_fingerprint"] = hashlib.sha256(
                json.dumps(fingerprint_source, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()
        base.write_json(path, payload)


def prepare_mode_v3(
    df: pd.DataFrame,
    maps: Dict[str, Dict[str, int]],
    args: argparse.Namespace,
    split_mode: str,
    rare_classes: Dict[str, int],
    source_counts: Dict[str, int],
    redteam_policy: Dict[str, Any],
    label_policy: Dict[str, Any],
    target_policy: Dict[str, Any],
    sampling_policy: Dict[str, Any],
    fold: int | None = None,
) -> None:
    out_base = base.resolve_from_root(args.out_dir) / split_mode / args.dataset
    if split_mode in base.GROUP_FOLD_SPLIT_MODES:
        out_base = out_base / f"fold_{fold}"
    base.clear_dir(out_base)
    split_indices = base.build_split_indices(df, args, split_mode, fold=fold)
    base.materialize(out_base, df, split_indices)
    base.write_dataset_metadata(out_base, df, maps, args, split_mode, split_indices, rare_classes, source_counts, redteam_policy, fold=fold)
    patch_metadata_v3(out_base, args, label_policy, target_policy, sampling_policy)
    print(f"Prepared V3 {split_mode}{'' if fold is None else f' fold_{fold}'}: {out_base}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare CSR-LANL identity V3 datasets with context labels and entity-centric features.")
    parser.add_argument("--in_dir", default=str(DEFAULT_IN_DIR))
    parser.add_argument("--out_dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--dataset", default=DATASET_NAME)
    parser.add_argument("--split_mode", nargs="+", default=["date"], help="date, random, groupkfold, redteam_stratified_groupkfold, all, or comma-separated values")
    parser.add_argument("--source_set", default="auth_flow", choices=sorted(base.SOURCE_SETS))
    parser.add_argument("--window_seconds", type=int, default=60)
    parser.add_argument("--train_ratio", type=float, default=0.70)
    parser.add_argument("--val_ratio", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n_folds", type=int, default=5)
    parser.add_argument("--fold", type=int, default=0)
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--chunk_size", type=int, default=100_000)
    parser.add_argument("--max_rows_per_source", type=int, default=None)
    parser.add_argument("--time_min", type=int, default=None)
    parser.add_argument("--time_max", type=int, default=None)
    parser.add_argument("--time_window_hours", type=float, default=None)
    parser.add_argument("--redteam_window_hours", type=float, default=1.0)
    parser.add_argument("--redteam_window_limit", type=int, default=250)
    parser.add_argument("--redteam_exclusion_windows", type=int, default=1)
    parser.add_argument("--min_redteam_matches", type=int, default=15)
    parser.add_argument("--min_multiclass_windows", type=int, default=5)
    parser.add_argument("--target_policy", default="exact", choices=sorted(TARGET_POLICY_TO_COLUMN))
    parser.add_argument("--max_windows", type=int, default=2_000_000, help="Final V3 window cap after preserving positives and hard benign windows; use 0 for no cap.")
    parser.add_argument("--hard_benign_windows", type=int, default=150_000)
    parser.add_argument("--benign_per_day", type=int, default=20_000)
    parser.add_argument("--benign_per_hour", type=int, default=1_500)
    parser.add_argument("--keep_context_60m", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--keep_entity_day_context", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--no_v3_sampling", action="store_true")
    parser.add_argument("--no_progress", action="store_true")
    parser.add_argument("--progress_every_chunks", type=int, default=4)
    parser.add_argument("--progress_every_rows", type=int, default=1_000_000)
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
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
    if args.min_redteam_matches < 0:
        raise SystemExit("min_redteam_matches must be zero or positive")
    for name in ["hard_benign_windows", "benign_per_day", "benign_per_hour"]:
        if int(getattr(args, name)) < 0:
            raise SystemExit(f"{name} must be zero or positive")
    input_dir = base.resolve_from_root(args.in_dir)
    if not input_dir.exists() or not input_dir.is_dir():
        raise SystemExit(f"Input directory does not exist: {input_dir}")


def main() -> None:
    args = parse_args()
    base.ensure_pyarrow()
    activate_v3_schema()
    split_modes = base.normalize_modes(args.split_mode)
    validate_args(args)

    input_dir = base.resolve_from_root(args.in_dir)
    print("== prepare_dataset_identity_v3 (CSR-LANL) ==", flush=True)
    print(f"Input       : {input_dir}", flush=True)
    print(f"Output      : {base.resolve_from_root(args.out_dir)}", flush=True)
    print(f"Split modes : {split_modes}", flush=True)
    print(f"Source set  : {args.source_set}", flush=True)
    print(f"Target      : {args.target_policy}", flush=True)
    print(f"V3 features : {len(V3_FEATURE_COLUMNS):,} new, {len(FEATURE_COLUMNS):,} total", flush=True)

    windows, maps, source_counts, redteam_policy = base.build_windows(args)
    print(f"Base windows: {len(windows):,}", flush=True)

    label_policy = add_context_labels(windows, args.window_seconds)
    add_v3_features(windows)
    target_policy = apply_target_policy(windows, args.target_policy)
    sampling_input_rows = int(len(windows))
    windows, sampling_policy = apply_v3_sampling(windows, args)
    sampling_policy["input_windows"] = sampling_input_rows
    rare_classes = base.collapse_rare_multiclass(windows, args.min_multiclass_windows)

    matched_after_sampling = int(bool_series(windows["label_exact"]).sum())
    redteam_policy["matched_redteam_entity_windows_after_v3_sampling"] = matched_after_sampling
    redteam_policy["v3_label_policy"] = label_policy
    redteam_policy["v3_target_policy"] = target_policy
    redteam_policy["v3_sampling_policy"] = sampling_policy

    print(f"V3 windows  : {len(windows):,} (from {sampling_input_rows:,})", flush=True)
    print(f"Binary      : {base.count_labels(windows['binary_target'])}", flush=True)
    print(f"Labels      : {label_policy}", flush=True)
    print(f"Sampling    : {sampling_policy}", flush=True)
    if matched_after_sampling < int(args.min_redteam_matches):
        raise SystemExit(
            "Matched red-team exact windows below required minimum after V3 sampling: "
            f"{matched_after_sampling} < {args.min_redteam_matches}. Increase the redteam window, row cap, or source set."
        )
    if rare_classes:
        print(f"Collapsed rare multiclass labels into RedTeamOther: {rare_classes}", flush=True)

    for split_mode in split_modes:
        if split_mode in base.GROUP_FOLD_SPLIT_MODES:
            folds = range(args.n_folds) if args.all_folds else [args.fold]
            mode_root = base.resolve_from_root(args.out_dir) / split_mode / args.dataset
            mode_root.mkdir(parents=True, exist_ok=True)
            base.write_json(mode_root / "feature_columns.json", FEATURE_COLUMNS)
            for fold in folds:
                prepare_mode_v3(
                    windows,
                    maps,
                    args,
                    split_mode,
                    rare_classes,
                    source_counts,
                    redteam_policy,
                    label_policy,
                    target_policy,
                    sampling_policy,
                    fold=int(fold),
                )
        else:
            prepare_mode_v3(
                windows,
                maps,
                args,
                split_mode,
                rare_classes,
                source_counts,
                redteam_policy,
                label_policy,
                target_policy,
                sampling_policy,
            )


if __name__ == "__main__":
    main()