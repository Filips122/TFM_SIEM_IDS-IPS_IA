#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


def read_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts_dir", default="src/models/CIC-IDS2017/artifacts")
    ap.add_argument("--out_dir", default=None)
    args = ap.parse_args()

    art = Path(args.artifacts_dir)
    if not art.exists():
        raise SystemExit(f"No existe: {art}")

    rows = []
    for model_dir in sorted([p for p in art.iterdir() if p.is_dir() and p.name != "compare_models"]):
        for mode_dir in sorted([p for p in model_dir.iterdir() if p.is_dir()]):
            for run_dir in sorted([p for p in mode_dir.iterdir() if p.is_dir()]):
                # groupkfold folds
                fold_dirs = sorted([p for p in run_dir.glob("fold_*") if p.is_dir()])
                if fold_dirs:
                    for fd in fold_dirs:
                        mtest = fd / "metrics_test.json"
                        if mtest.exists():
                            mt = read_json(mtest)
                            rows.append({
                                "model": model_dir.name,
                                "split_mode": mode_dir.name,
                                "run_id": run_dir.name,
                                "fold": fd.name,
                                "test_accuracy": mt.get("accuracy"),
                                "test_macro_f1": mt.get("macro_f1"),
                                "test_macro_recall": mt.get("macro_recall"),
                                "test_logloss": mt.get("logloss"),
                                "test_roc_auc": mt.get("roc_auc"),
                                "test_ece": mt.get("ece"),
                            })
                    continue

                mtest = run_dir / "metrics_test.json"
                if mtest.exists():
                    mt = read_json(mtest)
                    rows.append({
                        "model": model_dir.name,
                        "split_mode": mode_dir.name,
                        "run_id": run_dir.name,
                        "fold": None,
                        "test_accuracy": mt.get("accuracy"),
                        "test_macro_f1": mt.get("macro_f1"),
                        "test_macro_recall": mt.get("macro_recall"),
                        "test_logloss": mt.get("logloss"),
                        "test_roc_auc": mt.get("roc_auc"),
                        "test_ece": mt.get("ece"),
                    })
                else:
                    # fallback to results.json (older runs)
                    rj = run_dir / "results.json"
                    if rj.exists():
                        r = read_json(rj)
                        t = r.get("test", r)
                        rows.append({
                            "model": model_dir.name,
                            "split_mode": mode_dir.name,
                            "run_id": run_dir.name,
                            "fold": None,
                            "test_accuracy": t.get("accuracy"),
                            "test_macro_f1": t.get("macro_f1"),
                            "test_macro_recall": t.get("macro_recall"),
                            "test_logloss": t.get("test_logloss") or t.get("logloss"),
                            "test_roc_auc": t.get("roc_auc"),
                            "test_ece": t.get("ece"),
                        })

    if not rows:
        raise SystemExit("No se encontraron métricas en artifacts (metrics_test.json o results.json).")

    df = pd.DataFrame(rows)

    # sort by roc_auc if present else macro_f1 else accuracy
    def sort_key(r):
        if pd.notna(r.get("test_roc_auc")):
            return float(r["test_roc_auc"])
        if pd.notna(r.get("test_macro_f1")):
            return float(r["test_macro_f1"])
        if pd.notna(r.get("test_accuracy")):
            return float(r["test_accuracy"])
        return -1e9

    df["_sort"] = df.apply(sort_key, axis=1)
    df = df.sort_values("_sort", ascending=False).drop(columns=["_sort"])

    out_dir = Path(args.out_dir) if args.out_dir else (art / "compare_models" / pd.Timestamp.now().strftime("%Y%m%d_%H%M%S"))
    out_dir.mkdir(parents=True, exist_ok=True)

    df.to_csv(out_dir / "comparison.csv", index=False)
    (out_dir / "comparison.md").write_text(df.to_markdown(index=False), encoding="utf-8")

    print("\n=== MODEL COMPARISON ===")
    print(df.to_markdown(index=False))
    print("\nSaved:", out_dir)


if __name__ == "__main__":
    main()
