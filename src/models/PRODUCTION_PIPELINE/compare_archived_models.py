#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from .model_registry import resolve_from_root
except ImportError:  # pragma: no cover - direct script fallback
    from model_registry import resolve_from_root


def read_json(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return payload


def metric(metrics: Dict[str, Any], key: str) -> Optional[float]:
    test = metrics.get("test", {}) if isinstance(metrics, dict) else {}
    value = test.get(key) if isinstance(test, dict) else None
    return float(value) if isinstance(value, (int, float)) else None


def metric_any(metrics: Dict[str, Any], keys: List[str]) -> Optional[float]:
    for key in keys:
        value = metric(metrics, key)
        if value is not None:
            return value
    return None


def rows_from_store(model_store: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for manifest_path in sorted(model_store.glob("*/*/manifest.json")):
        manifest = read_json(manifest_path)
        spec = manifest.get("model_spec", {})
        metrics = manifest.get("production_metrics", {})
        warnings = manifest.get("warnings", [])
        test_metrics = metrics.get("test", {}) if isinstance(metrics, dict) else {}
        rows.append(
            {
                "model_id": spec.get("model_id"),
                "version": spec.get("version"),
                "domain": spec.get("domain"),
                "dataset_key": spec.get("dataset_key"),
                "model_type": spec.get("model_type"),
                "status": spec.get("status"),
                "pipeline": spec.get("pipeline"),
                "split_mode": spec.get("split_mode"),
                "fold": spec.get("fold"),
                "threshold": test_metrics.get("threshold", spec.get("threshold")),
                "precision": metric(metrics, "precision"),
                "recall": metric(metrics, "recall"),
                "f1": metric(metrics, "f1"),
                "macro_f1": metric_any(metrics, ["macro_f1", "macro-F1"]),
                "macro_recall": metric_any(metrics, ["macro_recall", "macro-recall"]),
                "roc_auc": metric_any(metrics, ["roc_auc", "ROC-AUC"]),
                "pr_auc": metric_any(metrics, ["pr_auc", "PR-AUC"]),
                "accuracy": metric(metrics, "accuracy"),
                "alert_rate": metric(metrics, "alert_rate"),
                "warning_count": len(warnings) if isinstance(warnings, list) else 0,
                "archive_dir": manifest.get("archive_dir"),
            }
        )
    return rows


def format_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def write_csv(path: Path, rows: List[Dict[str, Any]], columns: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column) for column in columns})


def write_markdown(path: Path, rows: List[Dict[str, Any]], columns: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Production Model Comparison", "", "Generated from archived model manifests.", ""]
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("| " + " | ".join(["---"] * len(columns)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(format_value(row.get(column)) for column in columns) + " |")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare archived production candidate models.")
    parser.add_argument("--model_store", default="src/models/PRODUCTION_PIPELINE/model_store")
    parser.add_argument("--output_dir", default="src/models/PRODUCTION_PIPELINE/comparisons")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    model_store = resolve_from_root(args.model_store)
    output_dir = resolve_from_root(args.output_dir)
    rows = rows_from_store(model_store)
    rows.sort(key=lambda row: (str(row.get("domain")), str(row.get("dataset_key")), str(row.get("model_id"))))
    columns = [
        "model_id",
        "version",
        "domain",
        "dataset_key",
        "model_type",
        "status",
        "threshold",
        "precision",
        "recall",
        "f1",
        "macro_f1",
        "macro_recall",
        "roc_auc",
        "pr_auc",
        "accuracy",
        "alert_rate",
        "warning_count",
    ]
    write_csv(output_dir / "production_model_comparison.csv", rows, columns)
    write_markdown(output_dir / "production_model_comparison.md", rows, columns)
    print("Saved:", output_dir / "production_model_comparison.csv")
    print("Saved:", output_dir / "production_model_comparison.md")


if __name__ == "__main__":
    main()