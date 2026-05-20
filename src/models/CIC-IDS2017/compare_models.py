#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compare_artifacts import augment_row_metadata, selected_run_dirs


def read_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


SUPERVISED_RANK_METRICS = ["test_macro_f1", "test_macro_recall", "test_pr_auc", "test_roc_auc", "test_accuracy", "test_best_f1"]
ANOMALY_RANK_METRICS = ["test_pr_auc", "test_best_f1", "test_roc_auc", "test_macro_f1", "test_accuracy"]


def is_anomaly_model(model: str) -> bool:
    name = str(model).lower()
    return "anomaly" in name or "isoforest" in name


def rank_metrics_for_model(model: str) -> List[str]:
    return ANOMALY_RANK_METRICS if is_anomaly_model(model) else SUPERVISED_RANK_METRICS


def primary_score(row: pd.Series):
    for metric in rank_metrics_for_model(str(row.get("model", ""))):
        if pd.notna(row.get(metric)):
            return float(row[metric]), metric
    return -1e9, "none"


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


def build_row(model_dir: Path, mode_dir: Path, run_dir: Path, fold: str | None = None, artifact_dir: Path | None = None) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "model": model_dir.name,
        "split_mode": mode_dir.name,
        "run_id": run_dir.name,
        "fold": fold,
    }
    augment_row_metadata(row, run_dir, artifact_dir)
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts_dir", default="src/models/CIC-IDS2017/artifacts")
    ap.add_argument("--out_dir", default=None)
    ap.add_argument("--split_modes", nargs="*", default=None, help="Optional split modes to include")
    ap.add_argument("--all_runs", action="store_true", help="Include all historical runs instead of only the latest run per model/split")
    args = ap.parse_args()

    art = Path(args.artifacts_dir)
    if not art.exists():
        raise SystemExit(f"No existe: {art}")

    rows = []
    for model_dir in sorted([p for p in art.iterdir() if p.is_dir() and p.name != "compare_models"]):
        for mode_dir in sorted([p for p in model_dir.iterdir() if p.is_dir()]):
            for run_dir in selected_run_dirs(mode_dir, args.all_runs):
                # groupkfold folds
                fold_dirs = sorted([p for p in run_dir.glob("fold_*") if p.is_dir()])
                if fold_dirs:
                    for fd in fold_dirs:
                        mtest = fd / "metrics_test.json"
                        if mtest.exists():
                            mt = read_json(mtest)
                            row = build_row(model_dir, mode_dir, run_dir, fd.name, fd)
                            row.update({
                                "test_accuracy": mt.get("accuracy"),
                                "test_macro_f1": mt.get("macro_f1"),
                                "test_macro_recall": mt.get("macro_recall"),
                                "test_logloss": mt.get("logloss"),
                                "test_roc_auc": mt.get("roc_auc"),
                                "test_pr_auc": mt.get("pr_auc"),
                                "test_best_f1": mt.get("best_f1"),
                                "test_ece": mt.get("ece"),
                            })
                            rows.append(row)
                    continue

                mtest = run_dir / "metrics_test.json"
                if mtest.exists():
                    mt = read_json(mtest)
                    row = build_row(model_dir, mode_dir, run_dir)
                    row.update({
                        "test_accuracy": mt.get("accuracy"),
                        "test_macro_f1": mt.get("macro_f1"),
                        "test_macro_recall": mt.get("macro_recall"),
                        "test_logloss": mt.get("logloss"),
                        "test_roc_auc": mt.get("roc_auc"),
                        "test_pr_auc": mt.get("pr_auc"),
                        "test_best_f1": mt.get("best_f1"),
                        "test_ece": mt.get("ece"),
                    })
                    rows.append(row)
                else:
                    # fallback to results.json (older runs)
                    rj = run_dir / "results.json"
                    if rj.exists():
                        r = read_json(rj)
                        t = r.get("test", r)
                        row = build_row(model_dir, mode_dir, run_dir)
                        row.update({
                            "test_accuracy": t.get("accuracy"),
                            "test_macro_f1": t.get("macro_f1"),
                            "test_macro_recall": t.get("macro_recall"),
                            "test_logloss": t.get("test_logloss") or t.get("logloss"),
                            "test_roc_auc": t.get("roc_auc"),
                            "test_pr_auc": t.get("pr_auc"),
                            "test_best_f1": t.get("best_f1"),
                            "test_ece": t.get("ece"),
                        })
                        rows.append(row)

    if not rows:
        raise SystemExit("No se encontraron métricas en artifacts (metrics_test.json o results.json).")

    df = pd.DataFrame(rows)
    if args.split_modes:
        requested_modes = {str(mode) for mode in args.split_modes}
        df = df[df["split_mode"].isin(requested_modes)].copy()
        if df.empty:
            raise SystemExit(f"No metrics found for requested split modes: {sorted(requested_modes)}")

    rank_data = df.apply(primary_score, axis=1, result_type="expand")
    df["rank_score"] = rank_data[0]
    df["rank_metric"] = rank_data[1]
    df["metric_warning"] = df.apply(metric_warning, axis=1)
    df = df.sort_values(["rank_score", "model", "split_mode"], ascending=[False, True, True])

    out_dir = Path(args.out_dir) if args.out_dir else (art / "compare_models" / pd.Timestamp.now().strftime("%Y%m%d_%H%M%S"))
    out_dir.mkdir(parents=True, exist_ok=True)

    df.to_csv(out_dir / "comparison.csv", index=False)

    # Internal markdown export (no tabulate dependency)
    def _df_to_md(dataframe: pd.DataFrame) -> str:
        cols = list(dataframe.columns)
        header = "| " + " | ".join(str(c) for c in cols) + " |"
        sep = "| " + " | ".join("---" for _ in cols) + " |"
        rows_md = []
        for _, row in dataframe.iterrows():
            vals = []
            for c in cols:
                v = row[c]
                if pd.isna(v):
                    vals.append("")
                elif isinstance(v, float):
                    vals.append(f"{v:.4f}")
                else:
                    vals.append(str(v))
            rows_md.append("| " + " | ".join(vals) + " |")
        return "\n".join([header, sep] + rows_md)

    md_text = _df_to_md(df)
    (out_dir / "comparison.md").write_text(md_text, encoding="utf-8")

    print("\n=== MODEL COMPARISON ===")
    print("Scope:", "all historical runs" if args.all_runs else "latest run per model/split")
    if args.split_modes:
        print("Split modes:", ", ".join(args.split_modes))
    print(md_text)
    print("\nSaved:", out_dir)


if __name__ == "__main__":
    main()
