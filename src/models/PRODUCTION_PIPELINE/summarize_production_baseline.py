#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .model_registry import ModelRegistry, resolve_from_root
except ImportError:  # pragma: no cover - direct script fallback
    from model_registry import ModelRegistry, resolve_from_root


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def maybe_read_json(path: Path) -> Optional[Dict[str, Any]]:
    return read_json(path) if path.exists() else None


def rel_path(path_value: Optional[str]) -> str:
    if not path_value:
        return ""
    path = Path(path_value)
    root = resolve_from_root(".")
    if not path.is_absolute():
        return path_value.replace("\\", "/")
    try:
        return str(path.resolve().relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)


def fmt(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def inference_summary_path(model_id: str, run_id: str, split: str) -> Path:
    return resolve_from_root("src/models/PRODUCTION_PIPELINE/inference_runs") / model_id / run_id / f"{split}_summary.json"


def base_row(spec: Any) -> Dict[str, Any]:
    return {
        "domain": spec.domain,
        "dataset_key": spec.dataset_key,
        "model_id": spec.model_id,
        "version": spec.version,
        "model_type": spec.model_type,
        "pipeline": spec.pipeline,
        "status": spec.status,
        "threshold": spec.threshold,
        "policy_path": getattr(spec, "policy_path", None),
        "run_id": "",
        "metric_source": "active_registry_only",
        "rows_scored": "",
        "events_written": "",
        "precision": "",
        "recall": "",
        "f1": "",
        "accuracy": "",
        "alert_rate": "",
        "false_positive_rate": "",
        "first_attack_rank": "",
        "top10_attack_window_recall": "",
        "daily_budget10_attack_window_recall": "",
        "events_path": "",
        "notes": " | ".join(spec.notes or []),
    }


def apply_binary_summary(row: Dict[str, Any], summary: Dict[str, Any], source: str) -> None:
    metrics = summary.get("metrics", {})
    row.update(
        {
            "run_id": summary.get("run_id", ""),
            "metric_source": source,
            "rows_scored": summary.get("rows_scored", ""),
            "events_written": summary.get("events_written", ""),
            "threshold": summary.get("threshold", row.get("threshold")),
            "precision": metrics.get("precision", ""),
            "recall": metrics.get("recall", ""),
            "f1": metrics.get("f1", ""),
            "accuracy": metrics.get("accuracy", ""),
            "alert_rate": metrics.get("alert_rate", ""),
            "false_positive_rate": metrics.get("false_positive_rate", ""),
            "events_path": rel_path(summary.get("events_path")),
        }
    )


def apply_cic_policy(row: Dict[str, Any], policy_path: Optional[str]) -> None:
    if not policy_path:
        return
    policy = maybe_read_json(resolve_from_root(policy_path))
    if policy is None:
        return
    metrics = policy.get("holdout_test_metrics", {})
    selected_from = policy.get("selected_from", {})
    row.update(
        {
            "run_id": policy.get("run_id", selected_from.get("run_id", "")),
            "metric_source": "independent_policy_holdout",
            "threshold": policy.get("threshold", row.get("threshold")),
            "precision": metrics.get("precision", ""),
            "recall": metrics.get("recall", ""),
            "f1": metrics.get("f1", ""),
            "accuracy": metrics.get("accuracy", ""),
            "alert_rate": metrics.get("alert_rate", ""),
            "false_positive_rate": metrics.get("false_positive_rate", ""),
        }
    )


def apply_csr_summary(row: Dict[str, Any], summary: Dict[str, Any]) -> None:
    topk = summary.get("metrics", {}).get("topk", {})
    daily_budget = summary.get("metrics", {}).get("daily_budget", {})
    top10 = topk.get("top_10", {})
    budget10 = daily_budget.get("daily_budget_10", {})
    row.update(
        {
            "run_id": summary.get("run_id", ""),
            "metric_source": "entity_day_triage",
            "rows_scored": summary.get("rows_scored", ""),
            "events_written": summary.get("events_written", ""),
            "threshold": summary.get("event_threshold", row.get("threshold")),
            "first_attack_rank": topk.get("first_attack_rank", ""),
            "top10_attack_window_recall": top10.get("attack_window_recall", ""),
            "daily_budget10_attack_window_recall": budget10.get("attack_window_recall", ""),
            "events_path": rel_path(summary.get("events_path")),
        }
    )


def build_rows(args: argparse.Namespace) -> List[Dict[str, Any]]:
    registry = ModelRegistry.from_json(args.registry)
    rows: List[Dict[str, Any]] = []
    for spec_dict in registry.to_dict()["models"]:
        spec = registry.get(spec_dict["model_id"])
        row = base_row(spec)
        if spec.model_id == args.csr_model_id:
            summary = maybe_read_json(inference_summary_path(spec.model_id, args.csr_run_id, args.split))
            if summary is not None:
                apply_csr_summary(row, summary)
        elif spec.model_id == args.cic_model_id:
            apply_cic_policy(row, getattr(spec, "policy_path", None))
        elif spec.dataset_key in {"LAB-ALERTS", "UNSW-NB15", "UGR16"}:
            summary = maybe_read_json(inference_summary_path(spec.model_id, args.hgb_run_id, args.split))
            if summary is not None:
                apply_binary_summary(row, summary, "full_test_inference")
        rows.append(row)
    return rows


def write_csv(path: Path, rows: List[Dict[str, Any]], columns: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def write_markdown(path: Path, rows: List[Dict[str, Any]], columns: List[str], args: argparse.Namespace) -> None:
    lines = [
        "# Production Baseline Summary",
        "",
        f"Generated at UTC: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
        "This file summarizes the active production candidates and the latest full/specialist evidence used for comparison.",
        "",
        f"HGB full run: `{args.hgb_run_id}`",
        f"CSR full run: `{args.csr_run_id}`",
        "CIC metric source: independent calibration policy holdout.",
        "",
    ]
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("| " + " | ".join(["---"] * len(columns)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(fmt(row.get(column, "")) for column in columns) + " |")
    lines.extend(
        [
            "",
            "## Operational Notes",
            "",
            "- HGB rows use complete test inference. Exported SIEM events may be capped by `--max_events`, but metrics use all scored rows.",
            "- CIC uses the active independent threshold policy because this is the defensible full holdout result, not the small smoke run.",
            "- CSR-LANL is evaluated as entity-day SOC triage; precision/recall/F1 are intentionally empty for that row.",
            "- COWRIE is kept as multiclass taxonomy support, not as a binary benign/attack detector.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize active production baseline runs for comparison and thesis evidence.")
    parser.add_argument("--registry", default="src/models/PRODUCTION_PIPELINE/active_model_registry.json")
    parser.add_argument("--hgb_run_id", default="full_hgb_active_20260602")
    parser.add_argument("--csr_run_id", default="full_csr_active_20260602")
    parser.add_argument("--split", default="test")
    parser.add_argument("--cic_model_id", default="gru_cic_day_20260520_145849")
    parser.add_argument("--csr_model_id", default="isoforest_csr_entity_day_20260531_002323_fold0")
    parser.add_argument("--output_csv", default="src/models/PRODUCTION_PIPELINE/production_baseline_summary.csv")
    parser.add_argument("--output_md", default="src/models/PRODUCTION_PIPELINE/production_baseline_summary.md")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    columns = [
        "domain",
        "dataset_key",
        "model_id",
        "status",
        "threshold",
        "metric_source",
        "rows_scored",
        "events_written",
        "precision",
        "recall",
        "f1",
        "accuracy",
        "alert_rate",
        "false_positive_rate",
        "first_attack_rank",
        "top10_attack_window_recall",
        "daily_budget10_attack_window_recall",
        "policy_path",
        "events_path",
    ]
    rows = build_rows(args)
    output_csv = resolve_from_root(args.output_csv)
    output_md = resolve_from_root(args.output_md)
    write_csv(output_csv, rows, columns)
    write_markdown(output_md, rows, columns, args)
    print(f"Saved: {output_csv}")
    print(f"Saved: {output_md}")


if __name__ == "__main__":
    main()