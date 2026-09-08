#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Collect every ARGOS-LAB run into one comparison table.

Walks src/models/ARGOS_LAB/artifacts, reads each run's results.json /
summary.json, and prints a ranked table plus a CSV. Runs are grouped by model,
split mode and feature regime, because on this dataset the feature regime
changes the score far more than the model does.

Usage:
    python compare_models.py
    python compare_models.py --metric mcc --split_mode groupkfold
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"

CLASSIFIER_METRICS = ["balanced_accuracy", "macro_f1", "mcc", "roc_auc", "pr_auc_minority", "accuracy"]
ANOMALY_METRICS = ["roc_auc", "pr_auc", "pr_auc_lift", "precision_at_1pct", "precision_at_5pct"]


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def flatten_test_block(block: Any) -> Dict[str, Any]:
    """Pull the reported metrics out of a run's `test` entry.

    Classifier runs store a flat dict; anomaly runs store
    {"attack": {...}, "rare": {...}} and the rare-class view is the meaningful
    one, since ATTACK is ~98% of windows.
    """
    if not isinstance(block, dict):
        return {}
    if "rare" in block or "attack" in block:
        rare = block.get("rare", {})
        out = {f"rare_{key}": rare.get(key) for key in ANOMALY_METRICS}
        out["rare_positive_label"] = rare.get("positive_label")
        out["roc_auc"] = block.get("attack", {}).get("roc_auc")
        return out
    return {key: block.get(key) for key in CLASSIFIER_METRICS if key in block}


def collect() -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    if not ARTIFACTS.exists():
        return pd.DataFrame()

    for results_path in sorted(ARTIFACTS.rglob("results.json")):
        payload = read_json(results_path)
        if not payload or "test" not in payload:
            continue
        # artifacts/<model>/<split_mode>/<regime>/<run_id>[/fold_n]/results.json
        relative = results_path.relative_to(ARTIFACTS).parts
        if len(relative) < 4:
            continue
        model, split_mode, regime, run_id = relative[0], relative[1], relative[2], relative[3]
        fold = next((part for part in relative if part.startswith("fold_")), None)
        args = payload.get("args", {}) or {}

        row: Dict[str, Any] = {
            "model": model,
            "split_mode": split_mode,
            "dataset": args.get("dataset", regime.split("__")[0]),
            "feature_set": args.get("feature_set", regime.split("__")[1] if "__" in regime else ""),
            "pipeline": args.get("pipeline", "anomaly" if "anomaly" in model else ""),
            "train_policy": args.get("train_policy"),
            "fold": fold,
            "run_id": run_id,
            "path": str(results_path.parent.relative_to(ARTIFACTS)),
        }
        row.update(flatten_test_block(payload["test"]))
        rows.append(row)

    # groupkfold runs also write an aggregate summary.json
    for summary_path in sorted(ARTIFACTS.rglob("summary.json")):
        payload = read_json(summary_path)
        if not payload or "folds" not in payload:
            continue
        relative = summary_path.relative_to(ARTIFACTS).parts
        if len(relative) < 4:
            continue
        args = payload.get("args", {}) or {}
        folds = [flatten_test_block(value.get("test")) for value in payload["folds"].values()
                 if isinstance(value, dict) and not value.get("skipped")]
        folds = [f for f in folds if f]
        if not folds:
            continue
        frame = pd.DataFrame(folds)
        row = {
            "model": relative[0],
            "split_mode": relative[1],
            "dataset": args.get("dataset", ""),
            "feature_set": args.get("feature_set", ""),
            "pipeline": args.get("pipeline", "anomaly" if "anomaly" in relative[0] else ""),
            "train_policy": args.get("train_policy"),
            "fold": f"MEAN of {len(folds)}",
            "run_id": relative[3],
            "path": str(summary_path.parent.relative_to(ARTIFACTS)),
        }
        for column in frame.columns:
            values = pd.to_numeric(frame[column], errors="coerce")
            if values.notna().any():
                row[column] = float(values.mean())
        rows.append(row)

    return pd.DataFrame(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare ARGOS-LAB runs")
    parser.add_argument("--metric", default="macro_f1", help="column to sort by")
    parser.add_argument("--split_mode", default=None)
    parser.add_argument("--dataset", default=None)
    parser.add_argument("--feature_set", default=None)
    parser.add_argument("--model", default=None, help="substring filter on model name")
    parser.add_argument("--folds", action="store_true", help="show individual folds as well as their mean")
    parser.add_argument("--out_csv", default="src/models/ARGOS_LAB/artifacts/comparison.csv")
    args = parser.parse_args()

    df = collect()
    if df.empty:
        raise SystemExit("No runs found under src/models/ARGOS_LAB/artifacts. Train a model first.")

    if args.split_mode:
        df = df[df["split_mode"] == args.split_mode]
    if args.dataset:
        df = df[df["dataset"] == args.dataset]
    if args.feature_set:
        df = df[df["feature_set"] == args.feature_set]
    if args.model:
        df = df[df["model"].str.contains(args.model, case=False, na=False)]
    if not args.folds:
        df = df[df["fold"].isna() | df["fold"].astype(str).str.startswith("MEAN")]
    if df.empty:
        raise SystemExit("No runs match those filters.")

    sort_key = args.metric if args.metric in df.columns else ("rare_pr_auc_lift" if "rare_pr_auc_lift" in df.columns else None)
    if sort_key:
        df = df.sort_values(sort_key, ascending=False, na_position="last")

    display_cols = [c for c in ["model", "pipeline", "dataset", "feature_set", "split_mode", "train_policy", "fold"] if c in df.columns]
    metric_cols = [c for c in CLASSIFIER_METRICS + [f"rare_{m}" for m in ANOMALY_METRICS] if c in df.columns and df[c].notna().any()]

    out = df[display_cols + metric_cols].copy()
    for column in metric_cols:
        out[column] = pd.to_numeric(out[column], errors="coerce").round(4)

    with pd.option_context("display.max_columns", None, "display.width", 250, "display.max_colwidth", 28):
        print(out.to_string(index=False))

    csv_path = Path(__file__).resolve().parents[3] / args.out_csv
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(csv_path, index=False)
    print(f"\n{len(df)} runs -> {csv_path}")
    print("\nNote: on ARGOS-LAB, ATTACK is ~98% of windows. Read `pr_auc_minority` (classifiers) "
          "and `rare_pr_auc_lift` (anomaly) rather than accuracy or ATTACK-side PR-AUC.")


if __name__ == "__main__":
    main()
