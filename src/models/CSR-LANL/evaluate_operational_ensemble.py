#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

import joblib
import numpy as np
import pandas as pd

from data_loader import load_feature_columns, load_split_frame, resolve_from_root
from evaluate_operational import (
    DEFAULT_BUDGETS,
    DEFAULT_DAILY_BUDGETS,
    calibrated_policy_metrics,
    daily_topk_metrics,
    entity_metrics,
    global_topk_metrics,
    label_order,
    model_scores,
    normalize_ints,
    save_json,
    score_distribution,
    scored_frame,
    write_alerts,
)
from train_utils import artifacts_root, save_dataset_profile_ref


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Operational ensemble evaluation for CSR-LANL artifacts.")
    parser.add_argument("--artifact_dirs", nargs="+", required=True)
    parser.add_argument("--pipelines", nargs="+", required=True, choices=["binary", "multiclass", "anomaly"])
    parser.add_argument("--model_kinds", nargs="+", default=None)
    parser.add_argument("--weights", nargs="+", type=float, default=None)
    parser.add_argument("--out_dir", default=None)
    parser.add_argument("--ensemble_name", default="operational_ensemble_CSR_LANL")
    parser.add_argument("--datasets_base", default="src/models/CSR-LANL/datasets_redteam")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold", "redteam_stratified_groupkfold"])
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--budgets", nargs="*", type=int, default=None)
    parser.add_argument("--daily_budgets", nargs="*", type=int, default=None)
    parser.add_argument("--batch_size", type=int, default=200_000)
    parser.add_argument("--fbeta_beta", type=float, default=2.0)
    return parser.parse_args()


def validate_lengths(args: argparse.Namespace) -> None:
    n_sources = len(args.artifact_dirs)
    if len(args.pipelines) != n_sources:
        raise SystemExit("--pipelines must have the same length as --artifact_dirs")
    if args.model_kinds is not None and len(args.model_kinds) != n_sources:
        raise SystemExit("--model_kinds must have the same length as --artifact_dirs")
    if args.weights is not None and len(args.weights) != n_sources:
        raise SystemExit("--weights must have the same length as --artifact_dirs")


def percentile_from_validation(validation_scores: np.ndarray, scores: np.ndarray) -> np.ndarray:
    reference = np.asarray(validation_scores, dtype=np.float64)
    reference = reference[np.isfinite(reference)]
    if len(reference) == 0:
        return np.zeros_like(scores, dtype=np.float64)
    reference = np.sort(reference)
    values = np.asarray(scores, dtype=np.float64)
    ranks = np.searchsorted(reference, values, side="right")
    return ranks.astype(np.float64) / float(len(reference))


def source_payload(args: argparse.Namespace) -> List[Dict[str, Any]]:
    weights = args.weights if args.weights is not None else [1.0] * len(args.artifact_dirs)
    model_kinds = args.model_kinds if args.model_kinds is not None else ["auto"] * len(args.artifact_dirs)
    payload = []
    for artifact_dir, pipeline, model_kind, weight in zip(args.artifact_dirs, args.pipelines, model_kinds, weights):
        payload.append(
            {
                "artifact_dir": str(resolve_from_root(artifact_dir)),
                "pipeline": pipeline,
                "model_kind": model_kind,
                "weight": float(weight),
            }
        )
    return payload


def output_root(args: argparse.Namespace, sources: Sequence[Dict[str, Any]]) -> Path:
    if args.out_dir:
        root = resolve_from_root(args.out_dir)
        root.mkdir(parents=True, exist_ok=True)
        return root
    root = artifacts_root(
        args.ensemble_name,
        args.split_mode,
        time.strftime("%Y%m%d_%H%M%S"),
        run_config={
            "datasets_base": args.datasets_base,
            "sources": sources,
            "weights": [source["weight"] for source in sources],
        },
    )
    save_dataset_profile_ref(root, args.datasets_base, args.split_mode, args.dataset, args.fold)
    return root


def evaluate_frame(frame: pd.DataFrame, split_name: str, budgets: Sequence[int], daily_budgets: Sequence[int], root: Path) -> Dict[str, Any]:
    metrics = global_topk_metrics(frame, budgets)
    metrics.update(daily_topk_metrics(frame, daily_budgets))
    entity_report, ranked_entities = entity_metrics(frame, budgets)
    metrics.update(entity_report)
    max_budget = max(max(budgets), max(daily_budgets) * max(1, int(frame["day_index"].nunique())))
    write_alerts(frame, root / f"alerts_{split_name}.csv", min(max_budget, len(frame)))
    if split_name == "test":
        ranked_entities.to_csv(root / "top_entities_test.csv", index=False)
        score_distribution(frame).to_csv(root / "score_distribution_test.csv", index=False)
        top_days = frame.groupby("day_index", dropna=False).agg(
            rows=("score", "size"),
            max_score=("score", "max"),
            mean_score=("score", "mean"),
            attack_windows=("is_attack", "sum"),
        )
        top_days.reset_index().sort_values("max_score", ascending=False).to_csv(root / "top_days_test.csv", index=False)
    return metrics


def main() -> None:
    args = parse_args()
    validate_lengths(args)
    budgets = normalize_ints(args.budgets, DEFAULT_BUDGETS)
    daily_budgets = normalize_ints(args.daily_budgets, DEFAULT_DAILY_BUDGETS)
    sources = source_payload(args)
    root = output_root(args, sources)
    feature_columns = load_feature_columns(args.datasets_base, args.split_mode, args.dataset, args.fold)
    weights = np.asarray([source["weight"] for source in sources], dtype=np.float64)
    if np.sum(weights) <= 0:
        raise SystemExit("Sum of --weights must be positive")

    combined_scores: Dict[str, np.ndarray] = {}
    reference_frames: Dict[str, pd.DataFrame] = {}
    per_source_scores: Dict[str, Dict[str, np.ndarray]] = {}

    for source_index, source in enumerate(sources):
        artifact_dir = Path(source["artifact_dir"])
        model = joblib.load(artifact_dir / "model.joblib")
        class_names = label_order(artifact_dir, source["pipeline"])
        source_scores: Dict[str, np.ndarray] = {}
        for split_name in ["val", "test"]:
            split = load_split_frame(
                datasets_base=args.datasets_base,
                split_mode=args.split_mode,
                dataset=args.dataset,
                pipeline=source["pipeline"],
                split=split_name,
                fold=args.fold,
                feature_cols=feature_columns,
            )
            scores = model_scores(model, split, source["pipeline"], class_names, batch_size=args.batch_size)
            source_scores[split_name] = scores
            if split_name not in reference_frames:
                reference_frames[split_name] = scored_frame(split, np.zeros(len(scores), dtype=np.float64))
            elif len(reference_frames[split_name]) != len(scores):
                raise SystemExit(f"Source {source_index} produced a different number of rows for split {split_name}")
        per_source_scores[str(source_index)] = source_scores

    for split_name in ["val", "test"]:
        normalized_parts = []
        for source_index in range(len(sources)):
            source_scores = per_source_scores[str(source_index)]
            normalized = percentile_from_validation(source_scores["val"], source_scores[split_name])
            normalized_parts.append(normalized * weights[source_index])
        combined_scores[split_name] = np.sum(normalized_parts, axis=0) / float(np.sum(weights))

    val_frame = reference_frames["val"].copy()
    test_frame = reference_frames["test"].copy()
    val_frame["score"] = combined_scores["val"]
    test_frame["score"] = combined_scores["test"]

    payload: Dict[str, Any] = {
        "dataset": args.dataset,
        "split_mode": args.split_mode,
        "fold": args.fold,
        "pipeline": "ensemble",
        "model_kind": "score_percentile_ensemble",
        "artifact_dir": str(root),
        "datasets_base": str(resolve_from_root(args.datasets_base)),
        "budgets": budgets,
        "daily_budgets": daily_budgets,
        "sources": sources,
        "normalization": "validation_empirical_percentile",
        "val": evaluate_frame(val_frame, "val", budgets, daily_budgets, root),
        "test": evaluate_frame(test_frame, "test", budgets, daily_budgets, root),
    }
    payload["policies"] = calibrated_policy_metrics(val_frame, test_frame, daily_budgets, beta=args.fbeta_beta)
    save_json(root / "operational_metrics.json", payload)
    save_json(root / "results.json", {"test": {"best_f1": payload["test"].get("f1_at_100"), "pr_auc": None}})
    print("Saved:", root / "operational_metrics.json")


if __name__ == "__main__":
    main()