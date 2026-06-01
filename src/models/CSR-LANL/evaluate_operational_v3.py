#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Sequence

import joblib
import numpy as np
import pandas as pd

import evaluate_operational as op
from data_loader import LoadedFrameSplit, load_feature_columns, load_split_frame, resolve_from_root


ATTACK_LABEL_COLUMNS = {
    "exact": "label_exact",
    "context_15m": "label_context_15m",
    "context_60m": "label_context_60m",
    "entity_day": "label_entity_day",
    "entity_attack_period": "label_entity_attack_period",
}
V3_LABEL_COLUMNS = [*ATTACK_LABEL_COLUMNS.values(), "v3_target_policy"]


def bool_series(values: pd.Series) -> pd.Series:
    if pd.api.types.is_bool_dtype(values):
        return values.fillna(False).astype(bool)
    return values.astype(str).str.strip().str.lower().isin({"1", "true", "t", "yes", "y"})


def attach_v3_labels(frame: pd.DataFrame, split: LoadedFrameSplit) -> pd.DataFrame:
    out = frame.copy()
    source = split.frame.reset_index(drop=True)
    for column in V3_LABEL_COLUMNS:
        if column in source.columns:
            if column == "v3_target_policy":
                out[column] = source[column].astype(str).to_numpy(copy=True)
            else:
                out[column] = bool_series(source[column]).to_numpy(dtype=bool, copy=True)
    if "label_exact" not in out.columns and "redteam_exact" in out.columns:
        out["label_exact"] = bool_series(out["redteam_exact"]).to_numpy(dtype=bool, copy=True)
    if "label_context_60m" not in out.columns and "redteam_near" in out.columns:
        out["label_context_60m"] = bool_series(out["redteam_near"]).to_numpy(dtype=bool, copy=True)
    return out


def choose_attack_mask(frame: pd.DataFrame, attack_label: str) -> pd.Series:
    if attack_label == "target":
        return frame["target"].astype(str).str.upper() != "BENIGN"
    if attack_label == "target_or_exact":
        target_attack = frame["target"].astype(str).str.upper() != "BENIGN"
        exact = bool_series(frame.get("label_exact", pd.Series(False, index=frame.index)))
        return target_attack | exact
    if attack_label not in ATTACK_LABEL_COLUMNS:
        raise SystemExit(f"Unsupported attack_label={attack_label!r}")
    column = ATTACK_LABEL_COLUMNS[attack_label]
    if column not in frame.columns:
        raise SystemExit(f"Dataset does not contain V3 attack label column: {column}")
    return bool_series(frame[column])


def scored_frame_v3(split: LoadedFrameSplit, scores: np.ndarray, attack_label: str) -> pd.DataFrame:
    frame = op.scored_frame(split, scores)
    frame = attach_v3_labels(frame, split)
    attack_mask = choose_attack_mask(frame, attack_label)
    frame["is_attack"] = attack_mask.astype(bool).to_numpy(copy=True)
    return frame


def write_alerts_v3(frame: pd.DataFrame, artifact_dir: Path, split_name: str, attack_label: str, limit: int) -> None:
    ordered = frame.sort_values("score", ascending=False, kind="mergesort").head(limit).copy()
    ordered.insert(0, "rank", np.arange(1, len(ordered) + 1, dtype=np.int64))
    base_columns = [column for column in op.OUTPUT_COLUMNS if column in ordered.columns]
    label_columns = [column for column in V3_LABEL_COLUMNS if column in ordered.columns]
    ordered[["rank", *base_columns, *label_columns]].to_csv(artifact_dir / f"v3_{attack_label}_alerts_{split_name}.csv", index=False)


def evaluate_split_v3(
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
    attack_label: str,
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
    scores = op.model_scores(model, split, pipeline, class_names, batch_size=batch_size)
    frame = scored_frame_v3(split, scores, attack_label=attack_label)
    metrics = op.global_topk_metrics(frame, budgets)
    metrics.update(op.daily_topk_metrics(frame, daily_budgets))
    entity_report, ranked_entities = op.entity_metrics(frame, budgets)
    metrics.update(entity_report)
    metrics.update(op.daily_entity_topk_metrics(frame, daily_budgets))

    max_budget = max(max(budgets), max(daily_budgets) * max(1, int(frame["day_index"].nunique())))
    write_alerts_v3(frame, artifact_dir, split_name, attack_label, min(max_budget, len(frame)))
    if split_name == "test":
        ranked_entities.to_csv(artifact_dir / f"v3_{attack_label}_top_entities_test.csv", index=False)
        op.entity_day_score_frame(frame).to_csv(artifact_dir / f"v3_{attack_label}_top_entity_days_test.csv", index=False)
        op.score_distribution(frame).to_csv(artifact_dir / f"v3_{attack_label}_score_distribution_test.csv", index=False)
        top_days = frame.groupby("day_index", dropna=False).agg(
            rows=("score", "size"),
            max_score=("score", "max"),
            mean_score=("score", "mean"),
            attack_windows=("is_attack", "sum"),
        )
        top_days.reset_index().sort_values("max_score", ascending=False).to_csv(artifact_dir / f"v3_{attack_label}_top_days_test.csv", index=False)
    return metrics, frame


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="V3 operational evaluation for CSR-LANL context and entity-day labels.")
    parser.add_argument("--artifact_dir", required=True)
    parser.add_argument("--datasets_base", default="src/models/CSR-LANL/datasets_redteam_identity_v3")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold", "redteam_stratified_groupkfold"])
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--pipeline", required=True, choices=["binary", "multiclass", "anomaly"])
    parser.add_argument("--model_kind", default="hgb", choices=["hgb", "isoforest"])
    parser.add_argument("--attack_label", default="exact", choices=["exact", "context_15m", "context_60m", "entity_day", "entity_attack_period", "target", "target_or_exact"])
    parser.add_argument("--budgets", nargs="*", type=int, default=None)
    parser.add_argument("--daily_budgets", nargs="*", type=int, default=None)
    parser.add_argument("--batch_size", type=int, default=200_000)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--fbeta_beta", type=float, default=2.0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    budgets = op.normalize_ints(args.budgets, op.DEFAULT_BUDGETS)
    daily_budgets = op.normalize_ints(args.daily_budgets, op.DEFAULT_DAILY_BUDGETS)
    artifact_dir = op.resolve_artifact_dir(args.artifact_dir, args.fold)
    model = joblib.load(artifact_dir / "model.joblib")
    class_names = op.label_order(artifact_dir, args.pipeline)
    feature_columns = load_feature_columns(args.datasets_base, args.split_mode, args.dataset, args.fold)

    payload: Dict[str, Any] = {
        "dataset": args.dataset,
        "split_mode": args.split_mode,
        "fold": args.fold,
        "pipeline": args.pipeline,
        "model_kind": args.model_kind,
        "attack_label": args.attack_label,
        "artifact_dir": str(artifact_dir),
        "datasets_base": str(resolve_from_root(args.datasets_base)),
        "budgets": budgets,
        "daily_budgets": daily_budgets,
        "sample_frac": args.sample_frac,
        "class_names": list(class_names),
    }
    split_frames: Dict[str, pd.DataFrame] = {}
    for split_name in ["val", "test"]:
        metrics, frame = evaluate_split_v3(
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
            attack_label=args.attack_label,
        )
        payload[split_name] = metrics
        split_frames[split_name] = frame

    payload["policies"] = op.calibrated_policy_metrics(split_frames["val"], split_frames["test"], daily_budgets, beta=args.fbeta_beta)
    payload["entity_policies"] = op.calibrated_entity_policy_metrics(
        split_frames["val"], split_frames["test"], budgets, daily_budgets, beta=args.fbeta_beta
    )

    output_path = artifact_dir / f"operational_metrics_v3_{args.attack_label}.json"
    op.save_json(output_path, payload)
    print("Saved:", output_path)


if __name__ == "__main__":
    main()