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


BASE_NUMERIC_METRICS = [
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

TOPK_BUDGETS = [10, 25, 50, 100, 250, 500]
DAILY_BUDGETS = [5, 10, 25, 50]
POLICY_NAMES = ["max_f2_on_val"] + [f"budget_daily_{budget}_on_val" for budget in DAILY_BUDGETS]
POLICY_METRICS = [
    "threshold",
    "alerts",
    "alerts_per_day",
    "attack_windows_found",
    "precision",
    "recall",
    "f1",
    "redteam_entities_found",
    "redteam_entity_recall",
    "attack_days_found",
    "attack_day_recall",
]
ENTITY_POLICY_NAMES = ["entity_max_f2_on_val"] + [f"entity_budget_{budget}_on_val" for budget in TOPK_BUDGETS] + [
    f"entity_budget_daily_{budget}_on_val" for budget in DAILY_BUDGETS
]
ENTITY_POLICY_METRICS = [
    "threshold",
    "entities",
    "redteam_entities",
    "selected_entities",
    "selected_entities_per_day",
    "redteam_entities_found",
    "entity_precision",
    "entity_recall",
    "entity_f1",
    "windows_in_selected_entities",
    "selected_entity_days",
    "selected_entity_days_per_day",
    "redteam_entity_days_found",
    "entity_day_precision",
    "entity_day_recall",
    "entity_day_f1",
    "attack_windows_found",
    "window_recall",
    "attack_days_found",
    "attack_day_recall",
]
OPERATIONAL_NUMERIC_METRICS = [
    "test_rows",
    "test_attack_windows",
    "test_attack_rate",
    "test_first_attack_rank",
    "test_median_attack_rank",
    "test_mean_attack_rank",
    "test_days",
    "test_attack_days",
    "test_entities",
    "test_redteam_entities",
    "test_first_redteam_entity_rank",
    "test_median_redteam_entity_rank",
    "test_mean_redteam_entity_rank",
    "test_entity_days",
    "test_redteam_entity_days",
]
for budget in TOPK_BUDGETS:
    OPERATIONAL_NUMERIC_METRICS.extend(
        [
            f"test_alerts_at_{budget}",
            f"test_attack_windows_found_at_{budget}",
            f"test_precision_at_{budget}",
            f"test_recall_at_{budget}",
            f"test_f1_at_{budget}",
            f"test_redteam_entity_recall_at_{budget}",
            f"test_entity_precision_at_{budget}",
            f"test_redteam_entities_found_at_{budget}",
        ]
    )
for budget in DAILY_BUDGETS:
    OPERATIONAL_NUMERIC_METRICS.extend(
        [
            f"test_alerts_at_daily_{budget}",
            f"test_alerts_per_day_at_{budget}",
            f"test_attack_windows_found_at_daily_{budget}",
            f"test_precision_at_daily_{budget}",
            f"test_recall_at_daily_{budget}",
            f"test_attack_days_found_at_daily_{budget}",
            f"test_attack_day_recall_at_daily_{budget}",
            f"test_entity_days_at_daily_{budget}",
            f"test_redteam_entity_days_found_at_daily_{budget}",
            f"test_entity_day_precision_at_daily_{budget}",
            f"test_entity_day_recall_at_daily_{budget}",
            f"test_entity_day_f1_at_daily_{budget}",
            f"test_attack_windows_found_in_entity_days_at_daily_{budget}",
            f"test_window_recall_in_entity_days_at_daily_{budget}",
            f"test_redteam_entities_found_in_entity_days_at_daily_{budget}",
            f"test_redteam_entity_recall_in_entity_days_at_daily_{budget}",
            f"test_attack_days_found_in_entity_days_at_daily_{budget}",
            f"test_attack_day_recall_in_entity_days_at_daily_{budget}",
        ]
    )
for policy_name in POLICY_NAMES:
    for metric_name in POLICY_METRICS:
        OPERATIONAL_NUMERIC_METRICS.append(f"test_policy_{policy_name}_{metric_name}")
for policy_name in ENTITY_POLICY_NAMES:
    for metric_name in ENTITY_POLICY_METRICS:
        OPERATIONAL_NUMERIC_METRICS.append(f"test_entity_policy_{policy_name}_{metric_name}")

NUMERIC_METRICS = BASE_NUMERIC_METRICS + OPERATIONAL_NUMERIC_METRICS

SUPERVISED_RANK_METRICS = [
    "test_policy_max_f2_on_val_recall",
    "test_policy_budget_daily_50_on_val_recall",
    "test_entity_policy_entity_budget_daily_5_on_val_entity_recall",
    "test_entity_policy_entity_budget_25_on_val_entity_recall",
    "test_recall_at_100",
    "test_redteam_entity_recall_at_25",
    "test_precision_at_100",
    "test_recall_at_daily_25",
    "test_pr_auc",
    "test_macro_f1",
    "test_macro_recall",
    "test_roc_auc",
    "test_accuracy",
    "test_best_f1",
]
ANOMALY_RANK_METRICS = [
    "test_policy_max_f2_on_val_recall",
    "test_policy_budget_daily_50_on_val_recall",
    "test_entity_policy_entity_budget_daily_5_on_val_entity_recall",
    "test_entity_policy_entity_budget_25_on_val_entity_recall",
    "test_recall_at_100",
    "test_redteam_entity_recall_at_25",
    "test_precision_at_100",
    "test_recall_at_daily_25",
    "test_pr_auc",
    "test_best_f1",
    "test_roc_auc",
    "test_macro_f1",
    "test_accuracy",
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


def normalize_operational_metrics(payload: Dict[str, Any]) -> Dict[str, Any]:
    test = payload.get("test", {}) if isinstance(payload, dict) else {}
    if not isinstance(test, dict):
        return {}
    row: Dict[str, Any] = {}
    scalar_keys = [
        "rows",
        "attack_windows",
        "attack_rate",
        "first_attack_rank",
        "median_attack_rank",
        "mean_attack_rank",
        "days",
        "attack_days",
        "entities",
        "redteam_entities",
        "first_redteam_entity_rank",
        "median_redteam_entity_rank",
        "mean_redteam_entity_rank",
        "entity_days",
        "redteam_entity_days",
    ]
    for key in scalar_keys:
        row[f"test_{key}"] = test.get(key)
    for budget in TOPK_BUDGETS:
        for key in [
            "alerts_at",
            "attack_windows_found_at",
            "precision_at",
            "recall_at",
            "f1_at",
            "redteam_entity_recall_at",
            "entity_precision_at",
            "redteam_entities_found_at",
        ]:
            metric = f"{key}_{budget}"
            row[f"test_{metric}"] = test.get(metric)
    for budget in DAILY_BUDGETS:
        for key in [
            "alerts_at_daily",
            "alerts_per_day_at",
            "attack_windows_found_at_daily",
            "precision_at_daily",
            "recall_at_daily",
            "attack_days_found_at_daily",
            "attack_day_recall_at_daily",
            "entity_days_at_daily",
            "redteam_entity_days_found_at_daily",
            "entity_day_precision_at_daily",
            "entity_day_recall_at_daily",
            "entity_day_f1_at_daily",
            "attack_windows_found_in_entity_days_at_daily",
            "window_recall_in_entity_days_at_daily",
            "redteam_entities_found_in_entity_days_at_daily",
            "redteam_entity_recall_in_entity_days_at_daily",
            "attack_days_found_in_entity_days_at_daily",
            "attack_day_recall_in_entity_days_at_daily",
        ]:
            metric = f"{key}_{budget}"
            row[f"test_{metric}"] = test.get(metric)
    policies = payload.get("policies", {}) if isinstance(payload, dict) else {}
    if isinstance(policies, dict):
        for policy_name in POLICY_NAMES:
            policy = policies.get(policy_name, {})
            policy_test = policy.get("test", {}) if isinstance(policy, dict) else {}
            if not isinstance(policy_test, dict):
                continue
            for metric_name in POLICY_METRICS:
                row[f"test_policy_{policy_name}_{metric_name}"] = policy_test.get(metric_name)
    entity_policies = payload.get("entity_policies", {}) if isinstance(payload, dict) else {}
    if isinstance(entity_policies, dict):
        for policy_name in ENTITY_POLICY_NAMES:
            policy = entity_policies.get(policy_name, {})
            policy_test = policy.get("test", {}) if isinstance(policy, dict) else {}
            if not isinstance(policy_test, dict):
                continue
            for metric_name in ENTITY_POLICY_METRICS:
                row[f"test_entity_policy_{policy_name}_{metric_name}"] = policy_test.get(metric_name)
    return row


def row_base(model: str, split_mode: str, run_id: str, fold: str | None) -> Dict[str, Any]:
    return {"model": model, "split_mode": split_mode, "run_id": run_id, "fold": fold, "status": "ok", "reason": None}


def is_anomaly_model(model: str) -> bool:
    name = str(model).lower()
    return "anomaly" in name or "isoforest" in name


def is_operational_model(model: str) -> bool:
    name = str(model).lower()
    return "operational_ensemble" in name or "operational" in name


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
    recall_at_100 = row.get("test_recall_at_100")
    if pd.notna(recall_at_100) and float(recall_at_100) <= 0.0:
        warnings.append("no_redteam_in_top100")
    if (not is_anomaly_model(model)) and (not is_operational_model(model)) and pd.isna(macro_f1):
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
            operational_path = fold_dir / "operational_metrics.json"
            if operational_path.exists():
                row.update(normalize_operational_metrics(read_json(operational_path)))
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
    operational_path = run_dir / "operational_metrics.json"
    if operational_path.exists():
        row.update(normalize_operational_metrics(read_json(operational_path)))
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
    parser.add_argument("--artifacts_dir", default="src/models/CSR-LANL/artifacts")
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
    print("\n=== CSR-LANL MODEL COMPARISON ===")
    print("Scope:", "all historical runs" if args.all_runs else "latest run per model/split")
    if args.split_modes:
        print("Split modes:", ", ".join(args.split_modes))
    print(df_to_md(detailed))
    if not aggregated.empty:
        print("\n=== CSR-LANL MODEL COMPARISON (aggregated) ===")
        print(df_to_md(aggregated))
    print("\nSaved:", out_dir)


if __name__ == "__main__":
    main()