#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

import joblib
import numpy as np
import pandas as pd

from data_loader import LoadedFrameSplit, load_feature_columns, load_split_frame, resolve_from_root


DEFAULT_BUDGETS = [10, 25, 50, 100, 250, 500]
DEFAULT_DAILY_BUDGETS = [5, 10, 25, 50]
OUTPUT_COLUMNS = [
    "window_start",
    "window_end",
    "day_index",
    "entity",
    "score",
    "target",
    "is_attack",
    "redteam_exact",
    "redteam_near",
    "redteam_roles",
    "source_families",
]


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    if isinstance(value, tuple):
        return [json_ready(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        number = float(value)
        return number if np.isfinite(number) else None
    if isinstance(value, float):
        return value if np.isfinite(value) else None
    if isinstance(value, (np.bool_,)):
        return bool(value)
    return value


def save_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_ready(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_ints(values: Sequence[int] | None, defaults: Sequence[int]) -> List[int]:
    source = defaults if values is None or len(values) == 0 else values
    cleaned = sorted({int(value) for value in source if int(value) > 0})
    if not cleaned:
        raise SystemExit("At least one positive budget is required")
    return cleaned


def resolve_artifact_dir(path: str | Path, fold: int | None) -> Path:
    artifact_dir = resolve_from_root(path)
    if (artifact_dir / "model.joblib").exists():
        return artifact_dir
    if fold is not None:
        fold_dir = artifact_dir / f"fold_{fold}"
        if (fold_dir / "model.joblib").exists():
            return fold_dir
    raise SystemExit(f"No model.joblib found in artifact directory: {artifact_dir}")


def label_order(artifact_dir: Path, pipeline: str) -> List[str]:
    path = artifact_dir / "label_map.json"
    if not path.exists():
        return ["BENIGN", "ATTACK"] if pipeline in {"binary", "anomaly"} else []
    mapping = read_json(path)
    ordered = [None] * (max(int(index) for index in mapping.values()) + 1)
    for label, index in mapping.items():
        ordered[int(index)] = str(label)
    return [label if label is not None else f"class_{index}" for index, label in enumerate(ordered)]


def positive_column(class_names: Sequence[str]) -> int:
    upper_names = [str(name).upper() for name in class_names]
    if "ATTACK" in upper_names:
        return upper_names.index("ATTACK")
    return 1 if len(class_names) > 1 else 0


def attack_columns(class_names: Sequence[str]) -> List[int]:
    indices = [index for index, label in enumerate(class_names) if str(label).upper() != "BENIGN"]
    return indices or [positive_column(class_names)]


def predict_proba_batches(model: Any, features: np.ndarray, batch_size: int) -> np.ndarray:
    batches = []
    for start in range(0, len(features), batch_size):
        stop = min(start + batch_size, len(features))
        batches.append(model.predict_proba(features[start:stop]))
    return np.concatenate(batches, axis=0) if batches else np.empty((0, 0), dtype=np.float64)


def score_samples_batches(model: Any, features: np.ndarray, batch_size: int) -> np.ndarray:
    batches = []
    for start in range(0, len(features), batch_size):
        stop = min(start + batch_size, len(features))
        batches.append(-model.score_samples(features[start:stop]))
    return np.concatenate(batches, axis=0) if batches else np.empty((0,), dtype=np.float64)


def model_scores(model: Any, split: LoadedFrameSplit, pipeline: str, class_names: Sequence[str], batch_size: int) -> np.ndarray:
    if pipeline == "anomaly":
        return score_samples_batches(model, split.X.astype(np.float32), batch_size)
    probabilities = predict_proba_batches(model, split.X.astype(np.float32), batch_size)
    if pipeline == "binary":
        return probabilities[:, positive_column(class_names)]
    if pipeline == "multiclass":
        return probabilities[:, attack_columns(class_names)].sum(axis=1)
    raise SystemExit(f"Unsupported pipeline: {pipeline}")


def bool_series(series: pd.Series) -> pd.Series:
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False).astype(bool)
    text = series.astype(str).str.strip().str.lower()
    return text.isin({"1", "true", "t", "yes", "y"})


def scored_frame(split: LoadedFrameSplit, scores: np.ndarray) -> pd.DataFrame:
    frame = split.meta.copy()
    frame["score"] = np.asarray(scores, dtype=np.float64)
    frame["target"] = split.y.astype(str)
    if "window_start" in frame.columns:
        frame["window_start"] = pd.to_numeric(frame["window_start"], errors="coerce").fillna(0).astype(np.int64)
        frame["day_index"] = (frame["window_start"] // 86400).astype(np.int64)
    else:
        frame["window_start"] = np.arange(len(frame), dtype=np.int64)
        frame["day_index"] = 0
    if "window_end" not in frame.columns:
        frame["window_end"] = frame["window_start"]
    if "entity" not in frame.columns:
        frame["entity"] = "Unknown"
    for column in ["redteam_exact", "redteam_near"]:
        if column not in frame.columns:
            frame[column] = False
    for column in ["redteam_roles", "source_families"]:
        if column not in frame.columns:
            frame[column] = ""
    redteam_exact = bool_series(frame["redteam_exact"])
    target_attack = frame["target"].astype(str).str.upper() != "BENIGN"
    frame["is_attack"] = (redteam_exact | target_attack).astype(bool)
    frame["redteam_exact"] = redteam_exact.astype(bool)
    frame["redteam_near"] = bool_series(frame["redteam_near"]).astype(bool)
    return frame


def safe_ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if float(denominator) > 0 else 0.0


def global_topk_metrics(frame: pd.DataFrame, budgets: Sequence[int]) -> Dict[str, Any]:
    scores = frame["score"].to_numpy(dtype=np.float64)
    attack_mask = frame["is_attack"].to_numpy(dtype=bool)
    order = np.argsort(-scores, kind="mergesort")
    ordered_attacks = attack_mask[order]
    attack_ranks = np.flatnonzero(ordered_attacks) + 1
    total_rows = int(len(frame))
    total_attacks = int(attack_mask.sum())
    metrics: Dict[str, Any] = {
        "rows": total_rows,
        "attack_windows": total_attacks,
        "attack_rate": safe_ratio(total_attacks, total_rows),
        "first_attack_rank": int(attack_ranks[0]) if len(attack_ranks) else None,
        "median_attack_rank": float(np.median(attack_ranks)) if len(attack_ranks) else None,
        "mean_attack_rank": float(np.mean(attack_ranks)) if len(attack_ranks) else None,
    }
    for budget in budgets:
        selected = order[: min(int(budget), total_rows)]
        alerts = int(len(selected))
        hits = int(attack_mask[selected].sum()) if alerts else 0
        precision = safe_ratio(hits, alerts)
        recall = safe_ratio(hits, total_attacks)
        metrics[f"alerts_at_{budget}"] = alerts
        metrics[f"attack_windows_found_at_{budget}"] = hits
        metrics[f"precision_at_{budget}"] = precision
        metrics[f"recall_at_{budget}"] = recall
        metrics[f"f1_at_{budget}"] = safe_ratio(2.0 * precision * recall, precision + recall)
    return metrics


def daily_topk_metrics(frame: pd.DataFrame, budgets: Sequence[int]) -> Dict[str, Any]:
    if frame.empty:
        return {}
    sorted_frame = frame.sort_values(["day_index", "score"], ascending=[True, False], kind="mergesort")
    total_days = int(frame["day_index"].nunique())
    total_attacks = int(frame["is_attack"].sum())
    attack_days = set(frame.loc[frame["is_attack"], "day_index"].astype(int).tolist())
    metrics: Dict[str, Any] = {"days": total_days, "attack_days": int(len(attack_days))}
    grouped = sorted_frame.groupby("day_index", sort=False, group_keys=False)
    for budget in budgets:
        selected = grouped.head(int(budget))
        alerts = int(len(selected))
        hits = int(selected["is_attack"].sum())
        selected_attack_days = set(selected.loc[selected["is_attack"], "day_index"].astype(int).tolist())
        precision = safe_ratio(hits, alerts)
        recall = safe_ratio(hits, total_attacks)
        metrics[f"alerts_at_daily_{budget}"] = alerts
        metrics[f"alerts_per_day_at_{budget}"] = safe_ratio(alerts, total_days)
        metrics[f"attack_windows_found_at_daily_{budget}"] = hits
        metrics[f"precision_at_daily_{budget}"] = precision
        metrics[f"recall_at_daily_{budget}"] = recall
        metrics[f"attack_days_found_at_daily_{budget}"] = int(len(selected_attack_days))
        metrics[f"attack_day_recall_at_daily_{budget}"] = safe_ratio(len(selected_attack_days), len(attack_days))
    return metrics


def threshold_metrics(frame: pd.DataFrame, threshold: float) -> Dict[str, Any]:
    selected = frame["score"].to_numpy(dtype=np.float64) >= float(threshold)
    attack_mask = frame["is_attack"].to_numpy(dtype=bool)
    total_rows = int(len(frame))
    total_attacks = int(attack_mask.sum())
    alerts = int(selected.sum())
    hits = int((selected & attack_mask).sum())
    precision = safe_ratio(hits, alerts)
    recall = safe_ratio(hits, total_attacks)
    redteam_entities = set(frame.loc[frame["is_attack"], "entity"].astype(str).tolist())
    selected_entities = set(frame.loc[selected, "entity"].astype(str).tolist())
    redteam_entities_found = len(redteam_entities & selected_entities)
    attack_days = set(frame.loc[frame["is_attack"], "day_index"].astype(int).tolist())
    selected_attack_days = set(frame.loc[selected & attack_mask, "day_index"].astype(int).tolist())
    days = int(frame["day_index"].nunique()) if "day_index" in frame.columns else 1
    return {
        "threshold": float(threshold),
        "rows": total_rows,
        "attack_windows": total_attacks,
        "alerts": alerts,
        "alerts_per_day": safe_ratio(alerts, days),
        "attack_windows_found": hits,
        "precision": precision,
        "recall": recall,
        "f1": safe_ratio(2.0 * precision * recall, precision + recall),
        "redteam_entities_found": int(redteam_entities_found),
        "redteam_entity_recall": safe_ratio(redteam_entities_found, len(redteam_entities)),
        "attack_days_found": int(len(selected_attack_days)),
        "attack_day_recall": safe_ratio(len(selected_attack_days), len(attack_days)),
    }


def best_fbeta_threshold(frame: pd.DataFrame, beta: float) -> float:
    if frame.empty:
        return float("inf")
    scores = frame["score"].to_numpy(dtype=np.float64)
    attack_mask = frame["is_attack"].to_numpy(dtype=bool)
    total_attacks = int(attack_mask.sum())
    if total_attacks <= 0:
        return float(np.max(scores)) if len(scores) else float("inf")
    order = np.argsort(-scores, kind="mergesort")
    ordered_scores = scores[order]
    ordered_attacks = attack_mask[order]
    true_positives = np.cumsum(ordered_attacks, dtype=np.float64)
    alerts = np.arange(1, len(ordered_scores) + 1, dtype=np.float64)
    precision = true_positives / alerts
    recall = true_positives / float(total_attacks)
    beta2 = float(beta) ** 2
    fbeta = (1.0 + beta2) * precision * recall / ((beta2 * precision) + recall + 1e-12)
    best_index = int(np.nanargmax(fbeta)) if len(fbeta) else 0
    return float(ordered_scores[best_index])


def threshold_for_top_n(frame: pd.DataFrame, n_alerts: int) -> float:
    return threshold_for_scores(frame["score"].to_numpy(dtype=np.float64), n_alerts)


def threshold_for_scores(scores: np.ndarray, n_items: int) -> float:
    if len(scores) == 0:
        return float("inf")
    n = max(1, min(int(n_items), len(scores)))
    partitioned = np.partition(scores, len(scores) - n)
    return float(partitioned[len(scores) - n])


def calibrated_policy_metrics(val_frame: pd.DataFrame, test_frame: pd.DataFrame, daily_budgets: Sequence[int], beta: float) -> Dict[str, Any]:
    policies: Dict[str, Any] = {}
    fbeta_threshold = best_fbeta_threshold(val_frame, beta=beta)
    policies[f"max_f{beta:g}_on_val"] = {
        "selection": "best_fbeta_threshold_on_val",
        "beta": float(beta),
        "threshold": fbeta_threshold,
        "val": threshold_metrics(val_frame, fbeta_threshold),
        "test": threshold_metrics(test_frame, fbeta_threshold),
    }
    val_days = max(1, int(val_frame["day_index"].nunique())) if "day_index" in val_frame.columns else 1
    for budget in daily_budgets:
        threshold = threshold_for_top_n(val_frame, int(budget) * val_days)
        policies[f"budget_daily_{budget}_on_val"] = {
            "selection": "global_threshold_for_validation_daily_budget",
            "daily_budget": int(budget),
            "threshold": threshold,
            "val": threshold_metrics(val_frame, threshold),
            "test": threshold_metrics(test_frame, threshold),
        }
    return policies


def entity_score_frame(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame()
    sorted_by_entity = frame.sort_values(["entity", "score"], ascending=[True, False], kind="mergesort")
    base = frame.groupby("entity", dropna=False).agg(
        risk_score=("score", "max"),
        max_score=("score", "max"),
        mean_score=("score", "mean"),
        n_windows=("score", "size"),
        redteam_window_count=("is_attack", "sum"),
        first_window_start=("window_start", "min"),
        last_window_start=("window_start", "max"),
        first_day_index=("day_index", "min"),
        last_day_index=("day_index", "max"),
    )
    top5_scores = sorted_by_entity.groupby("entity", dropna=False)["score"].apply(lambda values: float(values.head(5).mean()))
    base["mean_top5_score"] = top5_scores
    redteam_day_counts = frame.loc[frame["is_attack"]].groupby("entity", dropna=False)["day_index"].nunique()
    base["redteam_day_count"] = redteam_day_counts.reindex(base.index, fill_value=0).astype(int)
    base["has_redteam"] = base["redteam_window_count"] > 0
    ranked = base.reset_index().sort_values(["risk_score", "mean_top5_score"], ascending=[False, False], kind="mergesort")
    ranked.insert(0, "entity_rank", np.arange(1, len(ranked) + 1, dtype=np.int64))
    return ranked


def entity_metrics(frame: pd.DataFrame, budgets: Sequence[int]) -> tuple[Dict[str, Any], pd.DataFrame]:
    ranked = entity_score_frame(frame)
    if ranked.empty:
        return {}, ranked
    total_entities = int(len(ranked))
    total_redteam_entities = int(ranked["has_redteam"].sum())
    redteam_ranks = ranked.loc[ranked["has_redteam"], "entity_rank"].to_numpy(dtype=np.int64)
    metrics: Dict[str, Any] = {
        "entities": total_entities,
        "redteam_entities": total_redteam_entities,
        "first_redteam_entity_rank": int(redteam_ranks[0]) if len(redteam_ranks) else None,
        "median_redteam_entity_rank": float(np.median(redteam_ranks)) if len(redteam_ranks) else None,
        "mean_redteam_entity_rank": float(np.mean(redteam_ranks)) if len(redteam_ranks) else None,
    }
    for budget in budgets:
        selected = ranked.head(int(budget))
        hits = int(selected["has_redteam"].sum())
        metrics[f"redteam_entity_recall_at_{budget}"] = safe_ratio(hits, total_redteam_entities)
        metrics[f"entity_precision_at_{budget}"] = safe_ratio(hits, len(selected))
        metrics[f"redteam_entities_found_at_{budget}"] = hits
    return metrics, ranked


def entity_day_score_frame(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame()
    grouped = frame.groupby(["day_index", "entity"], dropna=False).agg(
        risk_score=("score", "max"),
        mean_score=("score", "mean"),
        n_windows=("score", "size"),
        redteam_window_count=("is_attack", "sum"),
        first_window_start=("window_start", "min"),
        last_window_start=("window_start", "max"),
    )
    grouped["has_redteam"] = grouped["redteam_window_count"] > 0
    ranked = grouped.reset_index().sort_values(["day_index", "risk_score"], ascending=[True, False], kind="mergesort")
    ranked["entity_day_rank"] = ranked.groupby("day_index", sort=False).cumcount() + 1
    return ranked


def daily_entity_topk_metrics(frame: pd.DataFrame, daily_budgets: Sequence[int]) -> Dict[str, Any]:
    ranked = entity_day_score_frame(frame)
    if ranked.empty:
        return {}
    total_days = int(frame["day_index"].nunique())
    total_attack_windows = int(frame["is_attack"].sum())
    redteam_entities = set(frame.loc[frame["is_attack"], "entity"].astype(str).tolist())
    attack_days = set(frame.loc[frame["is_attack"], "day_index"].astype(int).tolist())
    redteam_entity_days = int(ranked["has_redteam"].sum())
    metrics: Dict[str, Any] = {
        "entity_days": int(len(ranked)),
        "redteam_entity_days": redteam_entity_days,
    }
    for budget in daily_budgets:
        selected = ranked[ranked["entity_day_rank"] <= int(budget)]
        selected_redteam = selected[selected["has_redteam"]]
        entity_day_hits = int(selected_redteam["has_redteam"].sum())
        attack_window_hits = int(selected["redteam_window_count"].sum())
        selected_redteam_entities = set(selected_redteam["entity"].astype(str).tolist())
        selected_attack_days = set(selected_redteam["day_index"].astype(int).tolist())
        precision = safe_ratio(entity_day_hits, len(selected))
        recall = safe_ratio(entity_day_hits, redteam_entity_days)
        metrics[f"entity_days_at_daily_{budget}"] = int(len(selected))
        metrics[f"redteam_entity_days_found_at_daily_{budget}"] = entity_day_hits
        metrics[f"entity_day_precision_at_daily_{budget}"] = precision
        metrics[f"entity_day_recall_at_daily_{budget}"] = recall
        metrics[f"entity_day_f1_at_daily_{budget}"] = safe_ratio(2.0 * precision * recall, precision + recall)
        metrics[f"attack_windows_found_in_entity_days_at_daily_{budget}"] = attack_window_hits
        metrics[f"window_recall_in_entity_days_at_daily_{budget}"] = safe_ratio(attack_window_hits, total_attack_windows)
        metrics[f"redteam_entities_found_in_entity_days_at_daily_{budget}"] = int(len(selected_redteam_entities))
        metrics[f"redteam_entity_recall_in_entity_days_at_daily_{budget}"] = safe_ratio(len(selected_redteam_entities), len(redteam_entities))
        metrics[f"attack_days_found_in_entity_days_at_daily_{budget}"] = int(len(selected_attack_days))
        metrics[f"attack_day_recall_in_entity_days_at_daily_{budget}"] = safe_ratio(len(selected_attack_days), len(attack_days))
    return metrics


def selected_entity_metrics(frame: pd.DataFrame, ranked_entities: pd.DataFrame, selected_entities: set[str]) -> Dict[str, Any]:
    entity_series = frame["entity"].astype(str)
    selected_mask = entity_series.isin(selected_entities)
    selected_frame = frame[selected_mask]
    redteam_entities = set(frame.loc[frame["is_attack"], "entity"].astype(str).tolist())
    redteam_entities_found = len(redteam_entities & selected_entities)
    selected_count = int(len(selected_entities))
    total_entities = int(len(ranked_entities))
    total_attack_windows = int(frame["is_attack"].sum())
    attack_windows_found = int(selected_frame["is_attack"].sum())
    attack_days = set(frame.loc[frame["is_attack"], "day_index"].astype(int).tolist())
    selected_attack_days = set(selected_frame.loc[selected_frame["is_attack"], "day_index"].astype(int).tolist())
    days = int(frame["day_index"].nunique()) if "day_index" in frame.columns else 1
    entity_precision = safe_ratio(redteam_entities_found, selected_count)
    entity_recall = safe_ratio(redteam_entities_found, len(redteam_entities))
    return {
        "entities": total_entities,
        "redteam_entities": int(len(redteam_entities)),
        "selected_entities": selected_count,
        "selected_entities_per_day": safe_ratio(selected_count, days),
        "redteam_entities_found": int(redteam_entities_found),
        "entity_precision": entity_precision,
        "entity_recall": entity_recall,
        "entity_f1": safe_ratio(2.0 * entity_precision * entity_recall, entity_precision + entity_recall),
        "windows_in_selected_entities": int(len(selected_frame)),
        "attack_windows_found": attack_windows_found,
        "window_recall": safe_ratio(attack_windows_found, total_attack_windows),
        "attack_days_found": int(len(selected_attack_days)),
        "attack_day_recall": safe_ratio(len(selected_attack_days), len(attack_days)),
    }


def entity_threshold_metrics(frame: pd.DataFrame, ranked_entities: pd.DataFrame, threshold: float) -> Dict[str, Any]:
    selected = ranked_entities.loc[ranked_entities["risk_score"].to_numpy(dtype=np.float64) >= float(threshold), "entity"].astype(str)
    metrics = selected_entity_metrics(frame, ranked_entities, set(selected.tolist()))
    metrics["threshold"] = float(threshold)
    return metrics


def best_entity_fbeta_threshold(ranked_entities: pd.DataFrame, beta: float) -> float:
    if ranked_entities.empty:
        return float("inf")
    scores = ranked_entities["risk_score"].to_numpy(dtype=np.float64)
    attack_mask = ranked_entities["has_redteam"].to_numpy(dtype=bool)
    total_attacks = int(attack_mask.sum())
    if total_attacks <= 0:
        return float(np.max(scores)) if len(scores) else float("inf")
    order = np.argsort(-scores, kind="mergesort")
    ordered_scores = scores[order]
    ordered_attacks = attack_mask[order]
    true_positives = np.cumsum(ordered_attacks, dtype=np.float64)
    alerts = np.arange(1, len(ordered_scores) + 1, dtype=np.float64)
    precision = true_positives / alerts
    recall = true_positives / float(total_attacks)
    beta2 = float(beta) ** 2
    fbeta = (1.0 + beta2) * precision * recall / ((beta2 * precision) + recall + 1e-12)
    best_index = int(np.nanargmax(fbeta)) if len(fbeta) else 0
    return float(ordered_scores[best_index])


def selected_entity_day_metrics(frame: pd.DataFrame, ranked_entity_days: pd.DataFrame, selected_mask: pd.Series) -> Dict[str, Any]:
    selected = ranked_entity_days[selected_mask]
    selected_redteam = selected[selected["has_redteam"]]
    total_days = int(frame["day_index"].nunique()) if "day_index" in frame.columns else 1
    total_attack_windows = int(frame["is_attack"].sum())
    redteam_entities = set(frame.loc[frame["is_attack"], "entity"].astype(str).tolist())
    attack_days = set(frame.loc[frame["is_attack"], "day_index"].astype(int).tolist())
    redteam_entity_days = int(ranked_entity_days["has_redteam"].sum())
    entity_day_hits = int(selected_redteam["has_redteam"].sum())
    attack_window_hits = int(selected["redteam_window_count"].sum())
    selected_redteam_entities = set(selected_redteam["entity"].astype(str).tolist())
    selected_attack_days = set(selected_redteam["day_index"].astype(int).tolist())
    precision = safe_ratio(entity_day_hits, len(selected))
    recall = safe_ratio(entity_day_hits, redteam_entity_days)
    return {
        "entity_days": int(len(ranked_entity_days)),
        "redteam_entity_days": redteam_entity_days,
        "selected_entity_days": int(len(selected)),
        "selected_entity_days_per_day": safe_ratio(len(selected), total_days),
        "redteam_entity_days_found": entity_day_hits,
        "entity_day_precision": precision,
        "entity_day_recall": recall,
        "entity_day_f1": safe_ratio(2.0 * precision * recall, precision + recall),
        "redteam_entities_found": int(len(selected_redteam_entities)),
        "entity_recall": safe_ratio(len(selected_redteam_entities), len(redteam_entities)),
        "attack_windows_found": attack_window_hits,
        "window_recall": safe_ratio(attack_window_hits, total_attack_windows),
        "attack_days_found": int(len(selected_attack_days)),
        "attack_day_recall": safe_ratio(len(selected_attack_days), len(attack_days)),
    }


def entity_day_threshold_metrics(frame: pd.DataFrame, ranked_entity_days: pd.DataFrame, threshold: float) -> Dict[str, Any]:
    selected_mask = ranked_entity_days["risk_score"].to_numpy(dtype=np.float64) >= float(threshold)
    metrics = selected_entity_day_metrics(frame, ranked_entity_days, pd.Series(selected_mask, index=ranked_entity_days.index))
    metrics["threshold"] = float(threshold)
    return metrics


def calibrated_entity_policy_metrics(
    val_frame: pd.DataFrame,
    test_frame: pd.DataFrame,
    budgets: Sequence[int],
    daily_budgets: Sequence[int],
    beta: float,
) -> Dict[str, Any]:
    policies: Dict[str, Any] = {}
    val_entities = entity_score_frame(val_frame)
    test_entities = entity_score_frame(test_frame)
    entity_threshold = best_entity_fbeta_threshold(val_entities, beta=beta)
    policies[f"entity_max_f{beta:g}_on_val"] = {
        "selection": "best_entity_fbeta_threshold_on_val",
        "beta": float(beta),
        "threshold": entity_threshold,
        "val": entity_threshold_metrics(val_frame, val_entities, entity_threshold),
        "test": entity_threshold_metrics(test_frame, test_entities, entity_threshold),
    }
    for budget in budgets:
        threshold = threshold_for_scores(val_entities["risk_score"].to_numpy(dtype=np.float64), int(budget))
        policies[f"entity_budget_{budget}_on_val"] = {
            "selection": "global_entity_threshold_for_validation_budget",
            "entity_budget": int(budget),
            "threshold": threshold,
            "val": entity_threshold_metrics(val_frame, val_entities, threshold),
            "test": entity_threshold_metrics(test_frame, test_entities, threshold),
        }

    val_entity_days = entity_day_score_frame(val_frame)
    test_entity_days = entity_day_score_frame(test_frame)
    val_days = max(1, int(val_frame["day_index"].nunique())) if "day_index" in val_frame.columns else 1
    for budget in daily_budgets:
        threshold = threshold_for_scores(val_entity_days["risk_score"].to_numpy(dtype=np.float64), int(budget) * val_days)
        policies[f"entity_budget_daily_{budget}_on_val"] = {
            "selection": "entity_day_threshold_for_validation_daily_budget",
            "daily_entity_budget": int(budget),
            "threshold": threshold,
            "val": entity_day_threshold_metrics(val_frame, val_entity_days, threshold),
            "test": entity_day_threshold_metrics(test_frame, test_entity_days, threshold),
        }
    return policies


def score_distribution(frame: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for label, group in frame.groupby("target", dropna=False):
        values = group["score"].to_numpy(dtype=np.float64)
        rows.append(
            {
                "target": label,
                "rows": int(len(group)),
                "score_min": float(np.min(values)) if len(values) else np.nan,
                "score_mean": float(np.mean(values)) if len(values) else np.nan,
                "score_median": float(np.median(values)) if len(values) else np.nan,
                "score_p90": float(np.quantile(values, 0.90)) if len(values) else np.nan,
                "score_p99": float(np.quantile(values, 0.99)) if len(values) else np.nan,
                "score_max": float(np.max(values)) if len(values) else np.nan,
            }
        )
    return pd.DataFrame(rows)


def output_columns(frame: pd.DataFrame) -> List[str]:
    return [column for column in OUTPUT_COLUMNS if column in frame.columns]


def write_alerts(frame: pd.DataFrame, out_path: Path, limit: int) -> None:
    ordered = frame.sort_values("score", ascending=False, kind="mergesort").head(limit).copy()
    ordered.insert(0, "rank", np.arange(1, len(ordered) + 1, dtype=np.int64))
    ordered[["rank"] + output_columns(ordered)].to_csv(out_path, index=False)


def evaluate_split(
    model: Any,
    split_name: str,
    datasets_base: str,
    dataset: str,
    split_mode: str,
    fold: int | None,
    pipeline: str,
    class_names: Sequence[str],
    feature_columns: Sequence[str],
    budgets: Sequence[int],
    daily_budgets: Sequence[int],
    artifact_dir: Path,
    batch_size: int,
    sample_frac: float | None,
) -> tuple[Dict[str, Any], pd.DataFrame]:
    split = load_split_frame(
        datasets_base=datasets_base,
        split_mode=split_mode,
        dataset=dataset,
        pipeline=pipeline,
        split=split_name,
        fold=fold,
        sample_frac=sample_frac,
        feature_cols=feature_columns,
    )
    scores = model_scores(model, split, pipeline, class_names, batch_size=batch_size)
    frame = scored_frame(split, scores)
    metrics = global_topk_metrics(frame, budgets)
    metrics.update(daily_topk_metrics(frame, daily_budgets))
    entity_report, ranked_entities = entity_metrics(frame, budgets)
    metrics.update(entity_report)
    metrics.update(daily_entity_topk_metrics(frame, daily_budgets))

    max_budget = max(max(budgets), max(daily_budgets) * max(1, int(frame["day_index"].nunique())))
    write_alerts(frame, artifact_dir / f"alerts_{split_name}.csv", min(max_budget, len(frame)))
    if split_name == "test":
        ranked_entities.to_csv(artifact_dir / "top_entities_test.csv", index=False)
        entity_day_score_frame(frame).to_csv(artifact_dir / "top_entity_days_test.csv", index=False)
        score_distribution(frame).to_csv(artifact_dir / "score_distribution_test.csv", index=False)
        top_days = frame.groupby("day_index", dropna=False).agg(
            rows=("score", "size"),
            max_score=("score", "max"),
            mean_score=("score", "mean"),
            attack_windows=("is_attack", "sum"),
        )
        top_days.reset_index().sort_values("max_score", ascending=False).to_csv(artifact_dir / "top_days_test.csv", index=False)
    return metrics, frame


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Operational top-k evaluation for CSR-LANL artifacts.")
    parser.add_argument("--artifact_dir", required=True)
    parser.add_argument("--datasets_base", default="src/models/CSR-LANL/datasets_redteam")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold", "redteam_stratified_groupkfold"])
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--pipeline", required=True, choices=["binary", "multiclass", "anomaly"])
    parser.add_argument("--model_kind", default="hgb", choices=["hgb", "isoforest"])
    parser.add_argument("--budgets", nargs="*", type=int, default=None)
    parser.add_argument("--daily_budgets", nargs="*", type=int, default=None)
    parser.add_argument("--batch_size", type=int, default=200_000)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--fbeta_beta", type=float, default=2.0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    budgets = normalize_ints(args.budgets, DEFAULT_BUDGETS)
    daily_budgets = normalize_ints(args.daily_budgets, DEFAULT_DAILY_BUDGETS)
    artifact_dir = resolve_artifact_dir(args.artifact_dir, args.fold)
    model = joblib.load(artifact_dir / "model.joblib")
    class_names = label_order(artifact_dir, args.pipeline)
    feature_columns = load_feature_columns(args.datasets_base, args.split_mode, args.dataset, args.fold)

    payload: Dict[str, Any] = {
        "dataset": args.dataset,
        "split_mode": args.split_mode,
        "fold": args.fold,
        "pipeline": args.pipeline,
        "model_kind": args.model_kind,
        "artifact_dir": str(artifact_dir),
        "datasets_base": str(resolve_from_root(args.datasets_base)),
        "budgets": budgets,
        "daily_budgets": daily_budgets,
        "sample_frac": args.sample_frac,
        "class_names": list(class_names),
    }
    split_frames: Dict[str, pd.DataFrame] = {}
    for split_name in ["val", "test"]:
        metrics, frame = evaluate_split(
            model=model,
            split_name=split_name,
            datasets_base=args.datasets_base,
            dataset=args.dataset,
            split_mode=args.split_mode,
            fold=args.fold,
            pipeline=args.pipeline,
            class_names=class_names,
            feature_columns=feature_columns,
            budgets=budgets,
            daily_budgets=daily_budgets,
            artifact_dir=artifact_dir,
            batch_size=args.batch_size,
            sample_frac=args.sample_frac,
        )
        payload[split_name] = metrics
        split_frames[split_name] = frame

    payload["policies"] = calibrated_policy_metrics(split_frames["val"], split_frames["test"], daily_budgets, beta=args.fbeta_beta)
    payload["entity_policies"] = calibrated_entity_policy_metrics(
        split_frames["val"], split_frames["test"], budgets, daily_budgets, beta=args.fbeta_beta
    )

    save_json(artifact_dir / "operational_metrics.json", payload)
    print("Saved:", artifact_dir / "operational_metrics.json")


if __name__ == "__main__":
    main()