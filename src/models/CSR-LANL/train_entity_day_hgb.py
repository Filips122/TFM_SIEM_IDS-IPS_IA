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
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.utils.class_weight import compute_sample_weight

from data_loader import GROUP_FOLD_SPLIT_MODES, list_parquets, load_feature_columns, split_folder
from reporting import plot_corr_matrix, save_metrics_and_plots, save_staged_classification_history
from train_utils import artifacts_root, fit_label_encoder, now_run_id, save_dataset_profile_ref, save_json, save_label_encoder


SPLIT_MODE_CHOICES = ["date", "random", "groupkfold", "redteam_stratified_groupkfold"]
DEFAULT_BUDGETS = [10, 25, 50, 100, 250, 500]
DEFAULT_DAILY_BUDGETS = [5, 10, 25, 50]
META_COLUMNS = [
    "entity",
    "day_index",
    "target",
    "window_count",
    "attack_window_count",
    "redteam_near_window_count",
    "first_window_start",
    "last_window_start",
    "first_window_end",
    "last_window_end",
]


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


def save_json_ready(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_ready(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_ints(values: Sequence[int] | None, defaults: Sequence[int]) -> List[int]:
    source = defaults if values is None or len(values) == 0 else values
    cleaned = sorted({int(value) for value in source if int(value) > 0})
    if not cleaned:
        raise SystemExit("At least one positive budget is required")
    return cleaned


def safe_ratio(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if float(denominator) > 0 else 0.0


def threshold_for_scores(scores: np.ndarray, n_items: int) -> float:
    if len(scores) == 0:
        return float("inf")
    n = max(1, min(int(n_items), len(scores)))
    partitioned = np.partition(scores, len(scores) - n)
    return float(partitioned[len(scores) - n])


def positive_column(class_names: Sequence[str]) -> int:
    upper_names = [str(name).upper() for name in class_names]
    if "ATTACK" in upper_names:
        return upper_names.index("ATTACK")
    return 1 if len(class_names) > 1 else 0


def read_entity_day_split(
    datasets_base: str | Path,
    split_mode: str,
    dataset: str,
    split: str,
    fold: int | None,
    feature_columns: Sequence[str],
    sample_frac: float | None,
    seed: int,
) -> pd.DataFrame:
    folder = split_folder(datasets_base, split_mode, dataset, "binary", split, fold)
    paths = list_parquets(folder)
    if not paths:
        raise FileNotFoundError(f"No entity-day parquet files in: {folder}")
    columns = list(dict.fromkeys(META_COLUMNS + list(feature_columns)))
    frame = pd.concat([pd.read_parquet(path, columns=columns) for path in paths], ignore_index=True)
    if sample_frac is not None:
        if not (0.0 < sample_frac <= 1.0):
            raise ValueError("sample_frac must be in (0, 1]")
        frame = frame.sample(frac=sample_frac, random_state=seed).reset_index(drop=True)
    return frame


def to_xy(frame: pd.DataFrame, feature_columns: Sequence[str]) -> tuple[np.ndarray, np.ndarray]:
    missing = [column for column in feature_columns if column not in frame.columns]
    if missing:
        raise ValueError(f"Missing entity-day features: {missing[:10]}")
    X = frame.loc[:, list(feature_columns)].to_numpy(dtype=np.float32, copy=True)
    np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    y = frame["target"].astype(str).to_numpy(copy=True)
    return X, y


def predict_proba_batches(model: Any, features: np.ndarray, batch_size: int) -> np.ndarray:
    batches = []
    for start in range(0, len(features), batch_size):
        stop = min(start + batch_size, len(features))
        batches.append(model.predict_proba(features[start:stop]))
    return np.concatenate(batches, axis=0) if batches else np.empty((0, 0), dtype=np.float64)


def scored_entity_day_frame(frame: pd.DataFrame, scores: np.ndarray) -> pd.DataFrame:
    columns = [column for column in META_COLUMNS if column in frame.columns]
    out = frame.loc[:, columns].copy()
    out["entity"] = out.get("entity", "Unknown").fillna("Unknown").astype(str)
    out["day_index"] = pd.to_numeric(out.get("day_index", 0), errors="coerce").fillna(0).astype(np.int64)
    out["target"] = out["target"].astype(str)
    out["score"] = np.asarray(scores, dtype=np.float64)
    out["window_count"] = pd.to_numeric(out.get("window_count", 0), errors="coerce").fillna(0).astype(np.int64)
    out["attack_window_count"] = pd.to_numeric(out.get("attack_window_count", 0), errors="coerce").fillna(0).astype(np.int64)
    out["redteam_near_window_count"] = pd.to_numeric(out.get("redteam_near_window_count", 0), errors="coerce").fillna(0).astype(np.int64)
    out["is_attack"] = ((out["target"].str.upper() != "BENIGN") | (out["attack_window_count"] > 0)).astype(bool)
    return out


def entity_day_selection_metrics(frame: pd.DataFrame, selected: pd.DataFrame) -> Dict[str, Any]:
    selected_redteam = selected[selected["is_attack"]]
    attack_entity_days = int(frame["is_attack"].sum())
    attack_windows = int(frame["attack_window_count"].sum())
    redteam_entities = set(frame.loc[frame["is_attack"], "entity"].astype(str).tolist())
    attack_days = set(frame.loc[frame["is_attack"], "day_index"].astype(int).tolist())
    selected_redteam_entities = set(selected_redteam["entity"].astype(str).tolist())
    selected_attack_days = set(selected_redteam["day_index"].astype(int).tolist())
    selected_entity_days = int(len(selected))
    entity_day_hits = int(selected_redteam["is_attack"].sum())
    attack_window_hits = int(selected["attack_window_count"].sum())
    precision = safe_ratio(entity_day_hits, selected_entity_days)
    recall = safe_ratio(entity_day_hits, attack_entity_days)
    total_days = int(frame["day_index"].nunique()) if not frame.empty else 0
    return {
        "entity_days": int(len(frame)),
        "redteam_entity_days": attack_entity_days,
        "selected_entity_days": selected_entity_days,
        "selected_entity_days_per_day": safe_ratio(selected_entity_days, total_days),
        "redteam_entity_days_found": entity_day_hits,
        "entity_day_precision": precision,
        "entity_day_recall": recall,
        "entity_day_f1": safe_ratio(2.0 * precision * recall, precision + recall),
        "attack_windows": attack_windows,
        "attack_windows_found": attack_window_hits,
        "window_recall": safe_ratio(attack_window_hits, attack_windows),
        "redteam_entities": int(len(redteam_entities)),
        "redteam_entities_found": int(len(selected_redteam_entities)),
        "entity_recall": safe_ratio(len(selected_redteam_entities), len(redteam_entities)),
        "attack_days": int(len(attack_days)),
        "attack_days_found": int(len(selected_attack_days)),
        "attack_day_recall": safe_ratio(len(selected_attack_days), len(attack_days)),
    }


def global_topk_metrics(frame: pd.DataFrame, budgets: Sequence[int]) -> Dict[str, Any]:
    ordered = frame.sort_values("score", ascending=False, kind="mergesort").reset_index(drop=True)
    ordered["global_rank"] = np.arange(1, len(ordered) + 1, dtype=np.int64)
    attack_ranks = ordered.loc[ordered["is_attack"], "global_rank"].to_numpy(dtype=np.int64)
    metrics: Dict[str, Any] = {
        "entity_days": int(len(frame)),
        "redteam_entity_days": int(frame["is_attack"].sum()),
        "attack_windows": int(frame["attack_window_count"].sum()),
        "days": int(frame["day_index"].nunique()) if not frame.empty else 0,
        "attack_days": int(frame.loc[frame["is_attack"], "day_index"].nunique()) if not frame.empty else 0,
        "redteam_entities": int(frame.loc[frame["is_attack"], "entity"].nunique()) if not frame.empty else 0,
        "first_redteam_entity_day_rank": int(attack_ranks[0]) if len(attack_ranks) else None,
        "median_redteam_entity_day_rank": float(np.median(attack_ranks)) if len(attack_ranks) else None,
        "mean_redteam_entity_day_rank": float(np.mean(attack_ranks)) if len(attack_ranks) else None,
    }
    for budget in budgets:
        selected = ordered.head(int(budget))
        selected_metrics = entity_day_selection_metrics(frame, selected)
        for key, value in selected_metrics.items():
            if key in {"entity_days", "redteam_entity_days", "attack_windows", "redteam_entities", "attack_days"}:
                continue
            metrics[f"{key}_at_{budget}"] = value
    return metrics


def daily_topk_metrics(frame: pd.DataFrame, daily_budgets: Sequence[int]) -> Dict[str, Any]:
    ordered = frame.sort_values(["day_index", "score"], ascending=[True, False], kind="mergesort").copy()
    ordered["daily_rank"] = ordered.groupby("day_index", sort=False).cumcount() + 1
    metrics: Dict[str, Any] = {}
    for budget in daily_budgets:
        selected = ordered[ordered["daily_rank"] <= int(budget)]
        selected_metrics = entity_day_selection_metrics(frame, selected)
        for key, value in selected_metrics.items():
            if key in {"entity_days", "redteam_entity_days", "attack_windows", "redteam_entities", "attack_days"}:
                continue
            metrics[f"{key}_at_daily_{budget}"] = value
    return metrics


def threshold_metrics(frame: pd.DataFrame, threshold: float) -> Dict[str, Any]:
    selected = frame[frame["score"].to_numpy(dtype=np.float64) >= float(threshold)]
    metrics = entity_day_selection_metrics(frame, selected)
    metrics["threshold"] = float(threshold)
    return metrics


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


def calibrated_policy_metrics(val_frame: pd.DataFrame, test_frame: pd.DataFrame, daily_budgets: Sequence[int], beta: float) -> Dict[str, Any]:
    policies: Dict[str, Any] = {}
    fbeta_threshold = best_fbeta_threshold(val_frame, beta=beta)
    policies[f"entity_day_max_f{beta:g}_on_val"] = {
        "selection": "best_entity_day_fbeta_threshold_on_val",
        "beta": float(beta),
        "threshold": fbeta_threshold,
        "val": threshold_metrics(val_frame, fbeta_threshold),
        "test": threshold_metrics(test_frame, fbeta_threshold),
    }
    val_days = max(1, int(val_frame["day_index"].nunique())) if not val_frame.empty else 1
    for budget in daily_budgets:
        threshold = threshold_for_scores(val_frame["score"].to_numpy(dtype=np.float64), int(budget) * val_days)
        policies[f"entity_day_budget_daily_{budget}_on_val"] = {
            "selection": "entity_day_threshold_for_validation_daily_budget",
            "daily_entity_budget": int(budget),
            "threshold": threshold,
            "val": threshold_metrics(val_frame, threshold),
            "test": threshold_metrics(test_frame, threshold),
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


def write_top_entity_days(frame: pd.DataFrame, out_path: Path, limit: int) -> None:
    ordered = frame.sort_values("score", ascending=False, kind="mergesort").head(int(limit)).copy()
    ordered.insert(0, "global_rank", np.arange(1, len(ordered) + 1, dtype=np.int64))
    columns = [
        "global_rank",
        "day_index",
        "entity",
        "score",
        "target",
        "is_attack",
        "attack_window_count",
        "redteam_near_window_count",
        "window_count",
        "first_window_start",
        "last_window_start",
    ]
    ordered[[column for column in columns if column in ordered.columns]].to_csv(out_path, index=False)


def evaluate_frames(
    model: Any,
    frames: Dict[str, pd.DataFrame],
    feature_columns: Sequence[str],
    class_names: Sequence[str],
    budgets: Sequence[int],
    daily_budgets: Sequence[int],
    beta: float,
    batch_size: int,
    artifact_dir: Path,
) -> Dict[str, Any]:
    scored: Dict[str, pd.DataFrame] = {}
    positive_index = positive_column(class_names)
    for split_name, frame in frames.items():
        X, _ = to_xy(frame, feature_columns)
        probabilities = predict_proba_batches(model, X, batch_size=batch_size)
        scores = probabilities[:, positive_index]
        scored[split_name] = scored_entity_day_frame(frame, scores)
    metrics = {
        "val": {**global_topk_metrics(scored["val"], budgets), **daily_topk_metrics(scored["val"], daily_budgets)},
        "test": {**global_topk_metrics(scored["test"], budgets), **daily_topk_metrics(scored["test"], daily_budgets)},
        "policies": calibrated_policy_metrics(scored["val"], scored["test"], daily_budgets, beta=beta),
    }
    write_top_entity_days(scored["val"], artifact_dir / "top_entity_days_val.csv", limit=5000)
    write_top_entity_days(scored["test"], artifact_dir / "top_entity_days_test.csv", limit=5000)
    score_distribution(scored["test"]).to_csv(artifact_dir / "score_distribution_test.csv", index=False)
    save_json_ready(artifact_dir / "operational_metrics.json", metrics)
    return metrics


def run_one(
    datasets_base: str,
    split_mode: str,
    fold: int | None,
    sample_frac: float | None,
    epochs: int,
    out_dir: Path,
    dataset: str,
    class_weight: str,
    budgets: Sequence[int],
    daily_budgets: Sequence[int],
    beta: float,
    batch_size: int,
) -> Dict[str, Any]:
    feature_columns = load_feature_columns(datasets_base, split_mode, dataset, fold)
    train_df = read_entity_day_split(datasets_base, split_mode, dataset, "train", fold, feature_columns, sample_frac, seed=42)
    val_df = read_entity_day_split(datasets_base, split_mode, dataset, "val", fold, feature_columns, sample_frac, seed=43)
    test_df = read_entity_day_split(datasets_base, split_mode, dataset, "test", fold, feature_columns, sample_frac, seed=44)
    X_train, y_train_text = to_xy(train_df, feature_columns)
    X_val, y_val_text = to_xy(val_df, feature_columns)
    X_test, y_test_text = to_xy(test_df, feature_columns)
    encoder = fit_label_encoder(y_train_text)
    if len(encoder.classes_) < 2:
        raise SystemExit(f"Entity-day trainer requires at least two classes in train split, got {list(encoder.classes_)}")
    y_train = encoder.transform(y_train_text.astype(str))
    y_val = encoder.transform(y_val_text.astype(str))
    y_test = encoder.transform(y_test_text.astype(str))
    model = HistGradientBoostingClassifier(max_iter=epochs, learning_rate=0.08, max_depth=3, early_stopping=True, validation_fraction=0.15, random_state=42)
    sample_weight = compute_sample_weight(class_weight="balanced", y=y_train) if class_weight == "balanced" else None
    model.fit(X_train, y_train, sample_weight=sample_weight)
    save_staged_classification_history(out_dir, model, X_train, y_train, X_val, y_val, encoder.classes_)
    p_train = model.predict_proba(X_train)
    p_val = model.predict_proba(X_val)
    p_test = model.predict_proba(X_test)
    metrics_train = save_metrics_and_plots(out_dir, "train", y_train, p_train, encoder.classes_)
    metrics_val = save_metrics_and_plots(out_dir, "val", y_val, p_val, encoder.classes_)
    metrics_test = save_metrics_and_plots(out_dir, "test", y_test, p_test, encoder.classes_)
    plot_corr_matrix(X_train, out_dir / "plots" / "corr_matrix.png")
    joblib.dump(model, out_dir / "model.joblib")
    save_label_encoder(out_dir, encoder)
    (out_dir / "feature_columns.json").write_text(json.dumps(list(feature_columns), ensure_ascii=False, indent=2), encoding="utf-8")
    operational = evaluate_frames(
        model=model,
        frames={"train": train_df, "val": val_df, "test": test_df},
        feature_columns=feature_columns,
        class_names=encoder.classes_,
        budgets=budgets,
        daily_budgets=daily_budgets,
        beta=beta,
        batch_size=batch_size,
        artifact_dir=out_dir,
    )
    return {
        "best_iter": int(getattr(model, "n_iter_", model.max_iter)),
        "train": metrics_train,
        "val": metrics_val,
        "test": metrics_test,
        "operational": operational,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--datasets_base", default="src/models/CSR-LANL/datasets_redteam_temporal_rarity_entity_day")
    parser.add_argument("--split_mode", default="date", choices=SPLIT_MODE_CHOICES)
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--n_folds", type=int, default=5)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--epochs", type=int, default=215)
    parser.add_argument("--class_weight", default="balanced", choices=["none", "balanced"])
    parser.add_argument("--budgets", type=int, nargs="*", default=None)
    parser.add_argument("--daily_budgets", type=int, nargs="*", default=None)
    parser.add_argument("--beta", type=float, default=2.0)
    parser.add_argument("--batch_size", type=int, default=200000)
    args = parser.parse_args()
    budgets = normalize_ints(args.budgets, DEFAULT_BUDGETS)
    daily_budgets = normalize_ints(args.daily_budgets, DEFAULT_DAILY_BUDGETS)
    run_id = now_run_id()
    root = artifacts_root(
        "offline_CSR_LANL_entity_day_hgb",
        args.split_mode,
        run_id,
        run_config={
            "sample_frac": args.sample_frac,
            "epochs": args.epochs,
            "datasets_base": args.datasets_base,
            "class_weight": args.class_weight,
            "budgets": budgets,
            "daily_budgets": daily_budgets,
            "beta": args.beta,
        },
    )
    if args.split_mode not in GROUP_FOLD_SPLIT_MODES:
        save_dataset_profile_ref(root, args.datasets_base, args.split_mode, args.dataset)
        out = run_one(args.datasets_base, args.split_mode, None, args.sample_frac, args.epochs, root, args.dataset, args.class_weight, budgets, daily_budgets, args.beta, args.batch_size)
        save_json(root / "results.json", {"best_iter": out["best_iter"], "test": out["test"]})
        print("Saved:", root)
        return
    folds = range(args.n_folds) if args.all_folds else [0 if args.fold is None else args.fold]
    summary: Dict[str, Any] = {}
    for fold in folds:
        fold_dir = root / f"fold_{fold}"
        fold_dir.mkdir(parents=True, exist_ok=True)
        save_dataset_profile_ref(fold_dir, args.datasets_base, args.split_mode, args.dataset, int(fold))
        out = run_one(args.datasets_base, args.split_mode, int(fold), args.sample_frac, args.epochs, fold_dir, args.dataset, args.class_weight, budgets, daily_budgets, args.beta, args.batch_size)
        save_json(fold_dir / "results.json", {"best_iter": out["best_iter"], "test": out["test"]})
        summary[f"fold_{fold}"] = {"best_iter": out["best_iter"], "test": out["test"]}
    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()