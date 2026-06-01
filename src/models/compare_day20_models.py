#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import pandas as pd


DATASET_DIRS = [
    "CIC-IDS2017",
    "COWRIE_FULL",
    "CSR-LANL",
    "LAB-ALERTS",
    "UGR16",
    "UNSW-NB15",
]

BASE_METRIC_COLUMNS = [
    "test_accuracy",
    "test_macro_f1",
    "test_macro_recall",
    "test_logloss",
    "test_roc_auc",
    "test_pr_auc",
    "test_best_f1",
    "test_best_threshold",
    "test_ece",
]

OPERATIONAL_COLUMNS = [
    "test_rows",
    "test_attack_windows",
    "test_attack_rate",
    "test_first_attack_rank",
    "test_attack_windows_found_at_100",
    "test_recall_at_100",
    "test_redteam_entities_found_at_100",
    "test_redteam_entity_recall_at_100",
    "test_attack_windows_found_at_500",
    "test_recall_at_500",
    "test_redteam_entities_found_at_500",
    "test_redteam_entity_recall_at_500",
    "test_alerts_per_day_at_50",
    "test_attack_windows_found_at_daily_50",
    "test_recall_at_daily_50",
]

OUTPUT_COLUMNS = [
    "dataset_name",
    "report_source",
    "model",
    "model_dataset",
    "split_mode",
    "fold",
    "run_id",
    "status",
    "rank_metric",
    "rank_score",
    *BASE_METRIC_COLUMNS,
    *OPERATIONAL_COLUMNS,
    "metric_warning",
]

SUPERVISED_RANK_METRICS = [
    "test_macro_f1",
    "test_macro_recall",
    "test_pr_auc",
    "test_roc_auc",
    "test_accuracy",
    "test_best_f1",
]

ANOMALY_RANK_METRICS = [
    "test_pr_auc",
    "test_best_f1",
    "test_roc_auc",
    "test_macro_f1",
    "test_accuracy",
]

CSR_OPERATIONAL_RANK_METRICS = [
    "test_recall_at_100",
    "test_recall_at_500",
    "test_redteam_entity_recall_at_100",
    "test_redteam_entity_recall_at_500",
    "test_recall_at_daily_50",
    "test_pr_auc",
    "test_macro_f1",
]


def is_anomaly_model(model: Any) -> bool:
    name = str(model).lower()
    return "anomaly" in name or "isoforest" in name


def to_number(value: Any) -> Optional[float]:
    if value is None or pd.isna(value):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def first_available_score(row: pd.Series, metrics: Iterable[str]) -> tuple[float, str]:
    for metric in metrics:
        value = to_number(row.get(metric))
        if value is not None:
            return value, metric
    return -1e9, "none"


def fallback_rank(row: pd.Series, dataset_name: str, report_source: str) -> tuple[float, str]:
    if dataset_name == "CSR-LANL" and report_source == "operational_date_balanced":
        return first_available_score(row, CSR_OPERATIONAL_RANK_METRICS)
    metrics = ANOMALY_RANK_METRICS if is_anomaly_model(row.get("model")) else SUPERVISED_RANK_METRICS
    return first_available_score(row, metrics)


def find_latest_day20_comparison(compare_dir: Path, date_prefix: str) -> Optional[Path]:
    candidates = sorted(compare_dir.glob(f"{date_prefix}_*/comparison.csv"))
    return candidates[-1] if candidates else None


def find_comparison(dataset_dir: Path, date_prefix: str, prefer_csr_operational: bool) -> tuple[Optional[Path], str]:
    compare_dir = dataset_dir / "artifacts" / "compare_models"
    if not compare_dir.exists():
        return None, "missing_compare_dir"

    if dataset_dir.name == "CSR-LANL" and prefer_csr_operational:
        operational = compare_dir / "_validation_operational_date_balanced" / "comparison.csv"
        if operational.exists():
            return operational, "operational_date_balanced"

    latest = find_latest_day20_comparison(compare_dir, date_prefix)
    if latest is None:
        return None, "missing_day20_comparison"
    return latest, latest.parent.name


def normalize_columns(dataframe: pd.DataFrame, dataset_name: str, report_source: str) -> pd.DataFrame:
    df = dataframe.copy()
    df["dataset_name"] = dataset_name
    df["report_source"] = report_source

    if "dataset" in df.columns:
        df["model_dataset"] = df["dataset"]
    else:
        df["model_dataset"] = ""

    if "status" not in df.columns:
        df["status"] = "ok"
    if "fold" not in df.columns:
        df["fold"] = ""
    if "metric_warning" not in df.columns:
        df["metric_warning"] = ""

    if "rank_score" not in df.columns or "rank_metric" not in df.columns:
        rank_data = df.apply(lambda row: fallback_rank(row, dataset_name, report_source), axis=1, result_type="expand")
        df["rank_score"] = rank_data[0]
        df["rank_metric"] = rank_data[1]
    else:
        missing_rank = df["rank_score"].isna() | df["rank_metric"].isna()
        if missing_rank.any():
            rank_data = df[missing_rank].apply(
                lambda row: fallback_rank(row, dataset_name, report_source), axis=1, result_type="expand"
            )
            df.loc[missing_rank, "rank_score"] = rank_data[0]
            df.loc[missing_rank, "rank_metric"] = rank_data[1]

    for column in OUTPUT_COLUMNS:
        if column not in df.columns:
            df[column] = ""

    numeric_columns = ["rank_score", *BASE_METRIC_COLUMNS, *OPERATIONAL_COLUMNS]
    for column in numeric_columns:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    return df


def filter_day_rows(dataframe: pd.DataFrame, date_prefix: str) -> pd.DataFrame:
    df = dataframe.copy()
    if "run_id" not in df.columns:
        return df.iloc[0:0]
    df = df[df["run_id"].astype(str).str.startswith(date_prefix)].copy()
    if "status" in df.columns:
        df = df[df["status"].fillna("ok").astype(str).isin(["ok", "", "nan"])].copy()
    return df


def sort_candidates(dataframe: pd.DataFrame) -> pd.DataFrame:
    df = dataframe.copy()
    df["_entity500"] = pd.to_numeric(df.get("test_redteam_entity_recall_at_500"), errors="coerce").fillna(-1)
    df["_entity100"] = pd.to_numeric(df.get("test_redteam_entity_recall_at_100"), errors="coerce").fillna(-1)
    df["_win500"] = pd.to_numeric(df.get("test_recall_at_500"), errors="coerce").fillna(-1)
    df["_win100"] = pd.to_numeric(df.get("test_recall_at_100"), errors="coerce").fillna(-1)
    df["_macro_f1"] = pd.to_numeric(df.get("test_macro_f1"), errors="coerce").fillna(-1)
    df["_pr_auc"] = pd.to_numeric(df.get("test_pr_auc"), errors="coerce").fillna(-1)
    df["_roc_auc"] = pd.to_numeric(df.get("test_roc_auc"), errors="coerce").fillna(-1)
    first_rank = pd.to_numeric(df.get("test_first_attack_rank"), errors="coerce")
    df["_first_rank_sort"] = first_rank.fillna(1e18)
    df["_run_sort"] = df["run_id"].astype(str)

    return df.sort_values(
        [
            "rank_score",
            "_entity500",
            "_entity100",
            "_win500",
            "_win100",
            "_macro_f1",
            "_pr_auc",
            "_roc_auc",
            "_first_rank_sort",
            "_run_sort",
        ],
        ascending=[False, False, False, False, False, False, False, False, True, False],
    )


def dedupe_model_configs(dataframe: pd.DataFrame) -> pd.DataFrame:
    key_columns = ["model", "model_dataset", "split_mode", "fold"]
    return dataframe.drop_duplicates(subset=key_columns, keep="first").copy()


def load_top_models_for_dataset(
    dataset_dir: Path,
    date_prefix: str,
    top_n: int,
    prefer_csr_operational: bool,
) -> tuple[pd.DataFrame, Dict[str, Any]]:
    comparison_path, report_source = find_comparison(dataset_dir, date_prefix, prefer_csr_operational)
    source_info: Dict[str, Any] = {
        "dataset": dataset_dir.name,
        "report_source": report_source,
        "comparison_path": str(comparison_path) if comparison_path else None,
        "rows_after_filter": 0,
        "selected_rows": 0,
    }
    if comparison_path is None:
        return pd.DataFrame(columns=OUTPUT_COLUMNS), source_info

    raw = pd.read_csv(comparison_path)
    normalized = normalize_columns(raw, dataset_dir.name, report_source)
    day_rows = filter_day_rows(normalized, date_prefix)
    source_info["rows_after_filter"] = int(len(day_rows))
    if day_rows.empty:
        return pd.DataFrame(columns=OUTPUT_COLUMNS), source_info

    sorted_rows = sort_candidates(day_rows)
    selected = dedupe_model_configs(sorted_rows).head(top_n).copy()
    source_info["selected_rows"] = int(len(selected))
    return selected[OUTPUT_COLUMNS], source_info


def dataframe_to_markdown(dataframe: pd.DataFrame) -> str:
    df = dataframe.copy()
    columns = list(df.columns)
    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join("---" for _ in columns) + " |"
    rows: List[str] = []
    for _, row in df.iterrows():
        values: List[str] = []
        for column in columns:
            value = row[column]
            if pd.isna(value):
                values.append("")
            elif isinstance(value, float):
                values.append(f"{value:.6f}")
            else:
                values.append(str(value))
        rows.append("| " + " | ".join(values) + " |")
    return "\n".join([header, separator, *rows])


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Select the top N day-20 models for each dataset from comparison artifacts."
    )
    parser.add_argument("--models_root", default="src/models", help="Root directory containing dataset model folders.")
    parser.add_argument("--date", default="20260520", help="Run-id date prefix to filter, e.g. 20260520.")
    parser.add_argument("--top_n", type=int, default=2, help="Number of model configurations to keep per dataset.")
    parser.add_argument("--out_dir", default=None, help="Output directory for CSV/Markdown/JSON files.")
    parser.add_argument(
        "--csr_standard",
        action="store_true",
        help="Use CSR-LANL standard day-20 comparison instead of the operational date-balanced report.",
    )
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    models_root = Path(args.models_root)
    if not models_root.exists():
        raise SystemExit(f"No existe models_root: {models_root}")

    all_rows: List[pd.DataFrame] = []
    sources: List[Dict[str, Any]] = []
    for dataset_name in DATASET_DIRS:
        dataset_dir = models_root / dataset_name
        if not dataset_dir.exists():
            sources.append({"dataset": dataset_name, "report_source": "missing_dataset_dir", "comparison_path": None})
            continue
        selected, source_info = load_top_models_for_dataset(
            dataset_dir=dataset_dir,
            date_prefix=args.date,
            top_n=args.top_n,
            prefer_csr_operational=not args.csr_standard,
        )
        all_rows.append(selected)
        sources.append(source_info)

    if not all_rows:
        raise SystemExit("No se encontraron datasets configurados.")

    result = pd.concat(all_rows, ignore_index=True)
    if result.empty:
        raise SystemExit(f"No se encontraron modelos con run_id del dia {args.date}.")

    out_dir = Path(args.out_dir) if args.out_dir else models_root / "day20_comparison" / args.date
    out_dir.mkdir(parents=True, exist_ok=True)

    csv_path = out_dir / "top2_models.csv"
    md_path = out_dir / "top2_models.md"
    sources_path = out_dir / "sources.json"

    result.to_csv(csv_path, index=False)
    md_text = dataframe_to_markdown(result)
    md_path.write_text(md_text, encoding="utf-8")
    sources_path.write_text(json.dumps(sources, indent=2, ensure_ascii=False), encoding="utf-8")

    print(md_text)
    print(f"\nSaved CSV: {csv_path}")
    print(f"Saved Markdown: {md_path}")
    print(f"Saved sources: {sources_path}")


if __name__ == "__main__":
    main()