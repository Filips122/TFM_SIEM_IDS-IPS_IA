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

SUPERVISED_RANK_METRICS = ["test_macro_f1", "test_macro_recall", "test_pr_auc", "test_roc_auc", "test_accuracy", "test_best_f1"]
ANOMALY_RANK_METRICS = ["test_pr_auc", "test_best_f1", "test_roc_auc", "test_macro_f1", "test_accuracy"]


def read_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


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


SPLIT_MODE_NAMES = {"date", "random", "groupkfold"}


def build_row_base(model: str, dataset: str, split_mode: str, run_id: str, fold: str | None) -> Dict[str, Any]:
    return {
        "model": model,
        "dataset": dataset,
        "split_mode": split_mode,
        "run_id": run_id,
        "fold": fold,
        "status": "ok",
        "reason": None,
    }


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


def collect_run_rows(model_dir: Path, dataset: str, mode_dir: Path, run_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    model = model_dir.name
    split_mode = mode_dir.name
    run_id = run_dir.name

    fold_dirs = sorted([p for p in run_dir.glob("fold_*") if p.is_dir()])
    if fold_dirs:
        summary: Dict[str, Any] = {}
        summary_path = run_dir / "summary.json"
        if summary_path.exists():
            summary = read_json(summary_path)

        seen_folds = set()
        for fold_dir in fold_dirs:
            fold_name = fold_dir.name
            seen_folds.add(fold_name)
            row = build_row_base(model, dataset, split_mode, run_id, fold_name)

            mtest = fold_dir / "metrics_test.json"
            if mtest.exists():
                row.update(normalize_test_metrics(read_json(mtest)))
                rows.append(row)
                continue

            rj = fold_dir / "results.json"
            if rj.exists():
                row.update(normalize_test_metrics(read_json(rj)))
                rows.append(row)
                continue

            fold_data = summary.get(fold_name, {}) if isinstance(summary, dict) else {}
            if isinstance(fold_data, dict) and fold_data.get("skipped", False):
                row["status"] = "skipped"
                row["reason"] = fold_data.get("reason", "skipped")
            else:
                row["status"] = "missing_metrics"
                row["reason"] = "fold_dir_without_metrics"
            rows.append(row)

        if summary:
            for fold_name, fold_data in summary.items():
                if fold_name in seen_folds:
                    continue
                row = build_row_base(model, dataset, split_mode, run_id, fold_name)
                if isinstance(fold_data, dict) and fold_data.get("skipped", False):
                    row["status"] = "skipped"
                    row["reason"] = fold_data.get("reason", "skipped")
                else:
                    row["status"] = "missing_metrics"
                    row["reason"] = "summary_without_fold_dir"
                    if isinstance(fold_data, dict):
                        row.update(normalize_test_metrics(fold_data))
                rows.append(row)

        return rows

    row = build_row_base(model, dataset, split_mode, run_id, None)
    mtest = run_dir / "metrics_test.json"
    if mtest.exists():
        row.update(normalize_test_metrics(read_json(mtest)))
        rows.append(row)
        return rows

    rj = run_dir / "results.json"
    if rj.exists():
        row.update(normalize_test_metrics(read_json(rj)))
        rows.append(row)
        return rows

    row["status"] = "missing_metrics"
    row["reason"] = "run_dir_without_metrics"
    rows.append(row)
    return rows


def primary_score(row: pd.Series) -> Tuple[float, str]:
    for metric in rank_metrics_for_model(str(row.get("model", ""))):
        if pd.notna(row.get(metric)):
            return float(row[metric]), metric
    return -1e9, "none"


def df_to_md(dataframe: pd.DataFrame) -> str:
    cols = list(dataframe.columns)
    header = "| " + " | ".join(str(c) for c in cols) + " |"
    sep = "| " + " | ".join("---" for _ in cols) + " |"
    rows_md: List[str] = []
    for _, row in dataframe.iterrows():
        vals: List[str] = []
        for c in cols:
            v = row[c]
            if pd.isna(v):
                vals.append("")
            elif isinstance(v, float):
                vals.append(f"{v:.6f}")
            else:
                vals.append(str(v))
        rows_md.append("| " + " | ".join(vals) + " |")
    return "\n".join([header, sep] + rows_md)


def aggregate_rows(detailed: pd.DataFrame) -> pd.DataFrame:
    ok_df = detailed[detailed["status"] == "ok"].copy()
    if ok_df.empty:
        return pd.DataFrame()

    for col in NUMERIC_METRICS:
        if col in ok_df.columns:
            ok_df[col] = pd.to_numeric(ok_df[col], errors="coerce")

    group_cols = ["model", "dataset", "split_mode"]
    grouped = ok_df.groupby(group_cols, dropna=False)

    rows: List[Dict[str, Any]] = []
    for (model, dataset, split_mode), g in grouped:
        row: Dict[str, Any] = {
            "model": model,
            "dataset": dataset,
            "split_mode": split_mode,
            "n_rows": int(len(g)),
            "n_runs": int(g["run_id"].nunique()),
            "n_folds": int(g["fold"].notna().sum()),
        }

        for metric in NUMERIC_METRICS:
            if metric not in g.columns:
                continue
            s = pd.to_numeric(g[metric], errors="coerce")
            row[f"{metric}_mean"] = float(s.mean()) if s.notna().any() else np.nan
            row[f"{metric}_std"] = float(s.std(ddof=0)) if s.notna().any() else np.nan

        rows.append(row)

    agg = pd.DataFrame(rows)
    if agg.empty:
        return agg

    rank_scores: List[float] = []
    rank_sources: List[str] = []
    for _, row in agg.iterrows():
        chosen_score = -1e9
        chosen_metric = "none"
        for metric in rank_metrics_for_model(str(row.get("model", "")), aggregate=True):
            if metric in agg.columns and pd.notna(row.get(metric)):
                chosen_score = float(row[metric])
                chosen_metric = metric
                break
        rank_scores.append(chosen_score)
        rank_sources.append(chosen_metric)

    agg["rank_metric"] = rank_sources
    agg["rank_score"] = rank_scores
    agg = agg.sort_values(["rank_score", "n_rows"], ascending=[False, False])
    return agg


def collect_rows(artifacts_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    model_dirs = sorted([p for p in artifacts_dir.iterdir() if p.is_dir() and p.name != "compare_models"])
    for model_dir in model_dirs:
        first_level_dirs = sorted([p for p in model_dir.iterdir() if p.is_dir()])
        for first_level_dir in first_level_dirs:
            if first_level_dir.name in SPLIT_MODE_NAMES:
                dataset = "legacy"
                mode_dir = first_level_dir
                run_dirs = sorted([p for p in mode_dir.iterdir() if p.is_dir()])
                for run_dir in run_dirs:
                    rows.extend(collect_run_rows(model_dir, dataset, mode_dir, run_dir))
                continue

            dataset = first_level_dir.name
            mode_dirs = sorted([p for p in first_level_dir.iterdir() if p.is_dir()])
            for mode_dir in mode_dirs:
                if mode_dir.name not in SPLIT_MODE_NAMES:
                    continue
                run_dirs = sorted([p for p in mode_dir.iterdir() if p.is_dir()])
                for run_dir in run_dirs:
                    rows.extend(collect_run_rows(model_dir, dataset, mode_dir, run_dir))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts_dir", default="src/models/UGR16/artifacts")
    ap.add_argument("--out_dir", default=None)
    ap.add_argument("--datasets", nargs="*", default=None, help="Optional dataset names to include in the comparison")
    args = ap.parse_args()

    art = Path(args.artifacts_dir)
    if not art.exists():
        raise SystemExit(f"Does not exist: {art}")

    rows = collect_rows(art)
    if not rows:
        raise SystemExit("No metrics found in artifacts")

    detailed = pd.DataFrame(rows)
    if args.datasets:
        requested_datasets = {str(dataset) for dataset in args.datasets}
        detailed = detailed[detailed["dataset"].isin(requested_datasets)].copy()
        if detailed.empty:
            raise SystemExit(f"No metrics found for requested datasets: {sorted(requested_datasets)}")

    for col in NUMERIC_METRICS:
        if col in detailed.columns:
            detailed[col] = pd.to_numeric(detailed[col], errors="coerce")

    rank_data = detailed.apply(primary_score, axis=1, result_type="expand")
    detailed["rank_score"] = rank_data[0]
    detailed["rank_metric"] = rank_data[1]
    detailed["metric_warning"] = detailed.apply(metric_warning, axis=1)
    detailed = detailed.sort_values(["rank_score", "model", "dataset", "split_mode"], ascending=[False, True, True, True])

    skipped = detailed[detailed["status"] == "skipped"]
    missing = detailed[detailed["status"] == "missing_metrics"]
    aggregated = aggregate_rows(detailed)

    out_dir = Path(args.out_dir) if args.out_dir else (art / "compare_models" / pd.Timestamp.now().strftime("%Y%m%d_%H%M%S"))
    out_dir.mkdir(parents=True, exist_ok=True)

    detailed.to_csv(out_dir / "comparison.csv", index=False)
    (out_dir / "comparison.md").write_text(df_to_md(detailed), encoding="utf-8")

    if not aggregated.empty:
        aggregated.to_csv(out_dir / "comparison_aggregated.csv", index=False)
        (out_dir / "comparison_aggregated.md").write_text(df_to_md(aggregated), encoding="utf-8")

    if not skipped.empty:
        skipped.to_csv(out_dir / "comparison_skipped.csv", index=False)
        (out_dir / "comparison_skipped.md").write_text(df_to_md(skipped), encoding="utf-8")

    if not missing.empty:
        missing.to_csv(out_dir / "comparison_missing_metrics.csv", index=False)
        (out_dir / "comparison_missing_metrics.md").write_text(df_to_md(missing), encoding="utf-8")

    print("\n=== UGR16 MODEL COMPARISON (detailed) ===")
    print(df_to_md(detailed))
    if not aggregated.empty:
        print("\n=== UGR16 MODEL COMPARISON (aggregated) ===")
        print(df_to_md(aggregated))

    print("\nSaved:", out_dir)
    print(f"Rows: total={len(detailed)} ok={(detailed['status'] == 'ok').sum()} skipped={len(skipped)} missing={len(missing)}")


if __name__ == "__main__":
    main()