#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd


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


def collect_run_rows(model_dir: Path, mode_dir: Path, run_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    fold_dirs = sorted([path for path in run_dir.glob("fold_*") if path.is_dir()])
    if fold_dirs:
        for fold_dir in fold_dirs:
            row = row_base(model_dir.name, mode_dir.name, run_dir.name, fold_dir.name)
            result_path = fold_dir / "results.json"
            if result_path.exists():
                row.update(normalize_test_metrics(read_json(result_path)))
            else:
                row["status"] = "missing_metrics"
                row["reason"] = "fold_dir_without_results"
            rows.append(row)
        return rows
    row = row_base(model_dir.name, mode_dir.name, run_dir.name, None)
    result_path = run_dir / "results.json"
    if result_path.exists():
        row.update(normalize_test_metrics(read_json(result_path)))
    else:
        row["status"] = "missing_metrics"
        row["reason"] = "run_dir_without_results"
    rows.append(row)
    return rows


def primary_score(row: pd.Series) -> Tuple[float, str]:
    for metric in ["test_roc_auc", "test_pr_auc", "test_macro_f1", "test_accuracy", "test_best_f1"]:
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
    for (model, split_mode), group in ok_df.groupby(["model", "split_mode"], dropna=False):
        row: Dict[str, Any] = {"model": model, "split_mode": split_mode, "n_rows": int(len(group)), "n_runs": int(group["run_id"].nunique())}
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
        for metric in ["test_roc_auc_mean", "test_pr_auc_mean", "test_macro_f1_mean", "test_accuracy_mean", "test_best_f1_mean"]:
            if metric in agg.columns and pd.notna(row.get(metric)):
                chosen_score = float(row[metric])
                chosen_source = metric
                break
        scores.append(chosen_score)
        sources.append(chosen_source)
    agg["rank_score"] = scores
    agg["rank_metric"] = sources
    return agg.sort_values(["rank_score", "n_rows"], ascending=[False, False])


def collect_rows(artifacts_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for model_dir in sorted([path for path in artifacts_dir.iterdir() if path.is_dir() and path.name != "compare_models"]):
        for mode_dir in sorted([path for path in model_dir.iterdir() if path.is_dir()]):
            for run_dir in sorted([path for path in mode_dir.iterdir() if path.is_dir()]):
                rows.extend(collect_run_rows(model_dir, mode_dir, run_dir))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts_dir", default="src/models/COWRIE_FULL/artifacts")
    parser.add_argument("--out_dir", default=None)
    args = parser.parse_args()
    artifacts_dir = Path(args.artifacts_dir)
    if not artifacts_dir.exists():
        raise SystemExit(f"Does not exist: {artifacts_dir}")
    rows = collect_rows(artifacts_dir)
    if not rows:
        raise SystemExit("No metrics found in artifacts")
    detailed = pd.DataFrame(rows)
    for column in NUMERIC_METRICS:
        if column in detailed.columns:
            detailed[column] = pd.to_numeric(detailed[column], errors="coerce")
    rank_data = detailed.apply(primary_score, axis=1, result_type="expand")
    detailed["rank_score"] = rank_data[0]
    detailed["rank_metric"] = rank_data[1]
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
    print(df_to_md(detailed))
    if not aggregated.empty:
        print("\n=== COWRIE_FULL MODEL COMPARISON (aggregated) ===")
        print(df_to_md(aggregated))
    print("\nSaved:", out_dir)


if __name__ == "__main__":
    main()
