#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compare_artifacts import aggregate_group_columns, augment_row_metadata, key_to_dict, selected_run_dirs


NUMERIC_METRICS = [
    "test_accuracy",
    "test_macro_f1",
    "test_macro_recall",
    "test_logloss",
    "test_roc_auc",
    "test_ece",
    "test_pr_auc",
    "test_best_f1",
    "test_best_threshold",
]

SUPERVISED_RANK_METRICS = ["test_macro_f1", "test_macro_recall", "test_pr_auc", "test_roc_auc", "test_accuracy", "test_best_f1"]
ANOMALY_RANK_METRICS = ["test_pr_auc", "test_best_f1", "test_roc_auc", "test_macro_f1", "test_accuracy"]


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_test_metrics(payload: Dict[str, Any]) -> Dict[str, Any]:
    test = payload.get("test", payload)
    return {
        "test_accuracy": test.get("accuracy"),
        "test_macro_f1": test.get("macro_f1"),
        "test_macro_recall": test.get("macro_recall"),
        "test_logloss": test.get("logloss"),
        "test_roc_auc": test.get("roc_auc"),
        "test_ece": test.get("ece"),
        "test_pr_auc": test.get("pr_auc"),
        "test_best_f1": test.get("best_f1"),
        "test_best_threshold": test.get("best_threshold"),
    }


def row_base(model: str, split_mode: str, run_id: str, fold: str | None) -> Dict[str, Any]:
    return {"model": model, "split_mode": split_mode, "run_id": run_id, "fold": fold, "status": "ok", "reason": None}


def is_anomaly_model(model: str) -> bool:
    name = str(model).lower()
    return "anomaly" in name or "isoforest" in name


def rank_metrics_for_model(model: str, aggregate: bool = False) -> List[str]:
    metrics = ANOMALY_RANK_METRICS if is_anomaly_model(model) else SUPERVISED_RANK_METRICS
    return [f"{metric}_mean" for metric in metrics] if aggregate else list(metrics)


def metric_warning(row: pd.Series) -> str | None:
    warnings: List[str] = []
    model = str(row.get("model", ""))
    accuracy = row.get("test_accuracy")
    macro_f1 = row.get("test_macro_f1")
    pr_auc = row.get("test_pr_auc")
    if pd.notna(accuracy) and pd.notna(macro_f1) and float(accuracy) >= 0.95 and float(macro_f1) <= 0.55:
        warnings.append("majority_class_collapse")
    if is_anomaly_model(model) and pd.notna(pr_auc) and float(pr_auc) < 0.05:
        warnings.append("weak_anomaly_pr_auc")
    if (not is_anomaly_model(model)) and pd.isna(macro_f1):
        warnings.append("missing_macro_f1")
    return ";".join(warnings) if warnings else None


def collect_run_rows(model_dir: Path, mode_dir: Path, run_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    fold_dirs = sorted([path for path in run_dir.glob("fold_*") if path.is_dir()])
    if fold_dirs:
        for fold_dir in fold_dirs:
            row = row_base(model_dir.name, mode_dir.name, run_dir.name, fold_dir.name)
            augment_row_metadata(row, run_dir, fold_dir)
            result_path = fold_dir / "results.json"
            if result_path.exists():
                row.update(normalize_test_metrics(read_json(result_path)))
            else:
                row["status"] = "missing_metrics"
                row["reason"] = "fold_dir_without_results"
            rows.append(row)
        return rows
    row = row_base(model_dir.name, mode_dir.name, run_dir.name, None)
    augment_row_metadata(row, run_dir)
    result_path = run_dir / "results.json"
    if result_path.exists():
        row.update(normalize_test_metrics(read_json(result_path)))
    else:
        row["status"] = "missing_metrics"
        row["reason"] = "run_dir_without_results"
    rows.append(row)
    return rows


def primary_score(row: pd.Series) -> Tuple[float, str]:
    for metric in rank_metrics_for_model(str(row.get("model", ""))):
        if pd.notna(row.get(metric)):
            return float(row[metric]), metric
    return -1e9, "none"


def df_to_md(dataframe: pd.DataFrame) -> str:
    header = "| " + " | ".join(map(str, dataframe.columns)) + " |"
    sep = "| " + " | ".join("---" for _ in dataframe.columns) + " |"
    rows = []
    for _, row in dataframe.iterrows():
        values = []
        for value in row:
            if pd.isna(value):
                values.append("")
            elif isinstance(value, float):
                values.append(f"{value:.6f}")
            else:
                values.append(str(value))
        rows.append("| " + " | ".join(values) + " |")
    return "\n".join([header, sep] + rows)


def aggregate_rows(detailed: pd.DataFrame) -> pd.DataFrame:
    ok_df = detailed[detailed["status"] == "ok"].copy()
    if ok_df.empty:
        return pd.DataFrame()
    for column in NUMERIC_METRICS:
        if column in ok_df.columns:
            ok_df[column] = pd.to_numeric(ok_df[column], errors="coerce")
    rows: List[Dict[str, Any]] = []
    group_cols = aggregate_group_columns(ok_df, ["model", "split_mode"])
    for key, group in ok_df.groupby(group_cols, dropna=False):
        row: Dict[str, Any] = key_to_dict(group_cols, key)
        row.update({"n_rows": int(len(group)), "n_runs": int(group["run_id"].nunique())})
        for metric in NUMERIC_METRICS:
            if metric in group.columns:
                series = pd.to_numeric(group[metric], errors="coerce")
                row[f"{metric}_mean"] = float(series.mean()) if series.notna().any() else np.nan
        rows.append(row)
    agg = pd.DataFrame(rows)
    if agg.empty:
        return agg
    scores = []
    sources = []
    for _, row in agg.iterrows():
        chosen_score = -1e9
        chosen_source = "none"
        for metric in rank_metrics_for_model(str(row.get("model", "")), aggregate=True):
            if metric in agg.columns and pd.notna(row.get(metric)):
                chosen_score = float(row[metric])
                chosen_source = metric
                break
        scores.append(chosen_score)
        sources.append(chosen_source)
    agg["rank_score"] = scores
    agg["rank_metric"] = sources
    return agg.sort_values(["rank_score", "n_rows"], ascending=[False, False])


def collect_rows(artifacts_dir: Path, all_runs: bool = False) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for model_dir in sorted([path for path in artifacts_dir.iterdir() if path.is_dir() and path.name != "compare_models"]):
        for mode_dir in sorted([path for path in model_dir.iterdir() if path.is_dir()]):
            for run_dir in selected_run_dirs(mode_dir, all_runs):
                rows.extend(collect_run_rows(model_dir, mode_dir, run_dir))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts_dir", default="src/models/COWRIE_FULL/artifacts")
    parser.add_argument("--out_dir", default=None)
    parser.add_argument("--split_modes", nargs="*", default=None, help="Optional split modes to include")
    parser.add_argument("--all_runs", action="store_true", help="Include all historical runs instead of only the latest run per model/split")
    args = parser.parse_args()
    artifacts_dir = Path(args.artifacts_dir)
    if not artifacts_dir.exists():
        raise SystemExit(f"Does not exist: {artifacts_dir}")
    rows = collect_rows(artifacts_dir, all_runs=args.all_runs)
    if not rows:
        raise SystemExit("No metrics found in artifacts")
    detailed = pd.DataFrame(rows)
    if args.split_modes:
        requested_modes = {str(mode) for mode in args.split_modes}
        detailed = detailed[detailed["split_mode"].isin(requested_modes)].copy()
        if detailed.empty:
            raise SystemExit(f"No metrics found for requested split modes: {sorted(requested_modes)}")
    for column in NUMERIC_METRICS:
        if column in detailed.columns:
            detailed[column] = pd.to_numeric(detailed[column], errors="coerce")
    rank_data = detailed.apply(primary_score, axis=1, result_type="expand")
    detailed["rank_score"] = rank_data[0]
    detailed["rank_metric"] = rank_data[1]
    detailed["metric_warning"] = detailed.apply(metric_warning, axis=1)
    detailed = detailed.sort_values(["rank_score", "model", "split_mode"], ascending=[False, True, True])
    aggregated = aggregate_rows(detailed)
    out_dir = Path(args.out_dir) if args.out_dir else artifacts_dir / "compare_models" / pd.Timestamp.now().strftime("%Y%m%d_%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    detailed.to_csv(out_dir / "comparison.csv", index=False)
    (out_dir / "comparison.md").write_text(df_to_md(detailed), encoding="utf-8")
    if not aggregated.empty:
        aggregated.to_csv(out_dir / "comparison_aggregated.csv", index=False)
        (out_dir / "comparison_aggregated.md").write_text(df_to_md(aggregated), encoding="utf-8")
    print("\n=== COWRIE_FULL MODEL COMPARISON ===")
    print("Scope:", "all historical runs" if args.all_runs else "latest run per model/split")
    if args.split_modes:
        print("Split modes:", ", ".join(args.split_modes))
    print(df_to_md(detailed))
    if not aggregated.empty:
        print("\n=== COWRIE_FULL MODEL COMPARISON (aggregated) ===")
        print(df_to_md(aggregated))
    print("\nSaved:", out_dir)


if __name__ == "__main__":
    main()
