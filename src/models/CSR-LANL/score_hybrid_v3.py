#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, Sequence

import numpy as np
import pandas as pd

import evaluate_operational as op
import evaluate_operational_v3 as op_v3
from data_loader import LoadedFrameSplit, load_feature_columns, load_split_frame, resolve_from_root


DEFAULT_WEIGHTS = {
    "v3_pre_model_risk_score": 2.0,
    "v3_auth_failure_pressure": 1.6,
    "v3_auth_lateral_pressure": 1.4,
    "v3_flow_fanout_pressure": 1.2,
    "v3_identity_novelty_flag_count": 1.5,
    "v3_identity_novelty_ratio": 1.5,
    "v3_entity_auth_fail_count_prior_zscore": 1.2,
    "v3_entity_flow_unique_dst_computer_count_prior_zscore": 1.0,
    "v3_entity_identity_unique_pair_count_prior_zscore": 1.0,
    "v3_entity_identity_novelty_signal_count_prior_zscore": 1.3,
    "v3_is_off_hours": 0.3,
}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(op.json_ready(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def now_run_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.localtime())


def artifact_dir(out_dir: str | Path, split_mode: str, run_id: str, fold: int | None) -> Path:
    root = resolve_from_root(out_dir) / split_mode / run_id
    if fold is not None:
        root = root / f"fold_{fold}"
    root.mkdir(parents=True, exist_ok=True)
    return root


def load_weights(path: str | None) -> Dict[str, float]:
    if path is None:
        return dict(DEFAULT_WEIGHTS)
    payload = read_json(resolve_from_root(path))
    if not isinstance(payload, dict):
        raise SystemExit("weights JSON must be an object mapping feature names to numeric weights")
    return {str(key): float(value) for key, value in payload.items()}


def robust_scaler(frame: pd.DataFrame, features: Sequence[str]) -> Dict[str, Dict[str, float]]:
    params: Dict[str, Dict[str, float]] = {}
    for feature in features:
        if feature not in frame.columns:
            continue
        values = pd.to_numeric(frame[feature], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=np.float64)
        q25, median, q75 = np.quantile(values, [0.25, 0.50, 0.75]) if len(values) else (0.0, 0.0, 1.0)
        iqr = float(q75 - q25)
        if not np.isfinite(iqr) or iqr <= 1e-9:
            iqr = 1.0
        params[feature] = {"median": float(median), "iqr": iqr}
    return params


def hybrid_scores(frame: pd.DataFrame, weights: Dict[str, float], scaler: Dict[str, Dict[str, float]], clip_z: float) -> np.ndarray:
    scores = np.zeros(len(frame), dtype=np.float64)
    for feature, weight in weights.items():
        if feature not in frame.columns or feature not in scaler:
            continue
        values = pd.to_numeric(frame[feature], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=np.float64)
        median = float(scaler[feature]["median"])
        iqr = float(scaler[feature]["iqr"])
        z = (values - median) / iqr
        z = np.clip(z, 0.0, float(clip_z))
        scores += float(weight) * z
    return scores


def scored_frame_from_hybrid(split: LoadedFrameSplit, scores: np.ndarray, attack_label: str) -> pd.DataFrame:
    frame = op.scored_frame(split, scores)
    frame = op_v3.attach_v3_labels(frame, split)
    frame["is_attack"] = op_v3.choose_attack_mask(frame, attack_label).astype(bool).to_numpy(copy=True)
    return frame


def evaluate_frame(
    frame: pd.DataFrame,
    split_name: str,
    artifact_path: Path,
    attack_label: str,
    budgets: Sequence[int],
    daily_budgets: Sequence[int],
) -> Dict[str, Any]:
    metrics = op.global_topk_metrics(frame, budgets)
    metrics.update(op.daily_topk_metrics(frame, daily_budgets))
    entity_report, ranked_entities = op.entity_metrics(frame, budgets)
    metrics.update(entity_report)
    metrics.update(op.daily_entity_topk_metrics(frame, daily_budgets))

    max_budget = max(max(budgets), max(daily_budgets) * max(1, int(frame["day_index"].nunique())))
    op_v3.write_alerts_v3(frame, artifact_path, split_name, attack_label, min(max_budget, len(frame)))
    if split_name == "test":
        ranked_entities.to_csv(artifact_path / f"v3_{attack_label}_top_entities_test.csv", index=False)
        op.entity_day_score_frame(frame).to_csv(artifact_path / f"v3_{attack_label}_top_entity_days_test.csv", index=False)
        op.score_distribution(frame).to_csv(artifact_path / f"v3_{attack_label}_score_distribution_test.csv", index=False)
    return metrics


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interpretable hybrid risk score for CSR-LANL V3 datasets.")
    parser.add_argument("--datasets_base", default="src/models/CSR-LANL/datasets_redteam_identity_v3")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold", "redteam_stratified_groupkfold"])
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--pipeline", default="binary", choices=["binary", "multiclass", "anomaly"])
    parser.add_argument("--attack_label", default="exact", choices=["exact", "context_15m", "context_60m", "entity_day", "entity_attack_period", "target", "target_or_exact"])
    parser.add_argument("--weights_json", default=None)
    parser.add_argument("--clip_z", type=float, default=20.0)
    parser.add_argument("--out_dir", default="src/models/CSR-LANL/artifacts/hybrid_risk_CSR_LANL")
    parser.add_argument("--run_id", default=None)
    parser.add_argument("--budgets", nargs="*", type=int, default=None)
    parser.add_argument("--daily_budgets", nargs="*", type=int, default=None)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--fbeta_beta", type=float, default=2.0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    budgets = op.normalize_ints(args.budgets, op.DEFAULT_BUDGETS)
    daily_budgets = op.normalize_ints(args.daily_budgets, op.DEFAULT_DAILY_BUDGETS)
    run_id = args.run_id or now_run_id()
    fold = (0 if args.fold is None else args.fold) if args.split_mode in {"groupkfold", "redteam_stratified_groupkfold"} else None
    artifact_path = artifact_dir(args.out_dir, args.split_mode, run_id, fold)
    feature_columns = load_feature_columns(args.datasets_base, args.split_mode, args.dataset, fold)
    weights = load_weights(args.weights_json)
    selected_features = [feature for feature in weights if feature in feature_columns]
    if not selected_features:
        raise SystemExit("None of the hybrid score features exist in this dataset. Use a V3 dataset or provide --weights_json.")

    train = load_split_frame(
        datasets_base=args.datasets_base,
        split_mode=args.split_mode,
        dataset=args.dataset,
        pipeline=args.pipeline,
        split="train",
        fold=fold,
        sample_frac=args.sample_frac,
        feature_cols=feature_columns,
    )
    scaler = robust_scaler(train.frame, selected_features)

    payload: Dict[str, Any] = {
        "dataset": args.dataset,
        "split_mode": args.split_mode,
        "fold": fold,
        "pipeline": args.pipeline,
        "attack_label": args.attack_label,
        "artifact_dir": str(artifact_path),
        "datasets_base": str(resolve_from_root(args.datasets_base)),
        "budgets": budgets,
        "daily_budgets": daily_budgets,
        "sample_frac": args.sample_frac,
        "weights": {feature: weights[feature] for feature in selected_features},
        "robust_scaler": scaler,
        "clip_z": float(args.clip_z),
    }
    split_frames: Dict[str, pd.DataFrame] = {}
    for split_name in ["val", "test"]:
        split = load_split_frame(
            datasets_base=args.datasets_base,
            split_mode=args.split_mode,
            dataset=args.dataset,
            pipeline=args.pipeline,
            split=split_name,
            fold=fold,
            sample_frac=args.sample_frac,
            feature_cols=feature_columns,
        )
        scores = hybrid_scores(split.frame, {feature: weights[feature] for feature in selected_features}, scaler, args.clip_z)
        frame = scored_frame_from_hybrid(split, scores, args.attack_label)
        payload[split_name] = evaluate_frame(frame, split_name, artifact_path, args.attack_label, budgets, daily_budgets)
        split_frames[split_name] = frame

    payload["policies"] = op.calibrated_policy_metrics(split_frames["val"], split_frames["test"], daily_budgets, beta=args.fbeta_beta)
    payload["entity_policies"] = op.calibrated_entity_policy_metrics(
        split_frames["val"], split_frames["test"], budgets, daily_budgets, beta=args.fbeta_beta
    )
    write_json(artifact_path / "operational_metrics.json", payload)
    write_json(artifact_path / "scoring_policy.json", {"weights": payload["weights"], "robust_scaler": scaler, "clip_z": float(args.clip_z)})
    print("Saved:", artifact_path)


if __name__ == "__main__":
    main()