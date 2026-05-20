#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from data_loader import load_splits
from metrics import evaluate_anomaly_scores
from reporting import save_anomaly_plots
from train_utils import artifacts_root, now_run_id, save_dataset_profile_ref, save_json


def run_one(split_mode: str, fold: int | None, epochs: int, out_dir) -> dict:
    tr, va, te = load_splits(split_mode=split_mode, dataset="NUSW-NB15", pipeline="anomaly", fold=fold)

    Xtr = tr.X.astype(np.float32)
    model = IsolationForest(
        n_estimators=epochs,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(Xtr)

    Xva = va.X.astype(np.float32)
    Xte = te.X.astype(np.float32)
    sva = -model.score_samples(Xva)
    ste = -model.score_samples(Xte)

    rep_val = evaluate_anomaly_scores(va.y, sva, positive_label="ATTACK")
    rep_test = evaluate_anomaly_scores(te.y, ste, positive_label="ATTACK")

    save_anomaly_plots(out_dir, "val", va.y, sva, positive_label="ATTACK")
    save_anomaly_plots(out_dir, "test", te.y, ste, positive_label="ATTACK")

    return {
        "val": {
            "roc_auc": rep_val.roc_auc,
            "pr_auc": rep_val.pr_auc,
            "best_f1": rep_val.best_f1,
            "best_threshold": rep_val.best_threshold,
        },
        "test": {
            "roc_auc": rep_test.roc_auc,
            "pr_auc": rep_test.pr_auc,
            "best_f1": rep_test.best_f1,
            "best_threshold": rep_test.best_threshold,
        },
        "model": model,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split_mode", default="random", choices=["random", "groupkfold", "official"])
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)
    ap.add_argument("--n_folds", type=int, default=8)
    ap.add_argument("--epochs", type=int, default=315)
    args = ap.parse_args()

    model_name = "anomaly_isoforest_NUSW-NB15"
    run_id = now_run_id()
    root = artifacts_root(model_name, args.split_mode, run_id)

    if args.split_mode != "groupkfold":
        try:
            out = run_one(args.split_mode, None, args.epochs, root)
        except FileNotFoundError as e:
            raise SystemExit(
                "Anomaly split is missing train_benign data. "
                "This usually means the selected dataset split has no BENIGN samples. "
                f"Details: {e}"
            )
        joblib.dump(out["model"], root / "model.joblib")
        save_json(root / "results.json", {"val": out["val"], "test": out["test"], "best_epoch": None})
        print("Saved:", root)
        return

    if (not args.all_folds) and (args.fold is None):
        args.fold = 0
    folds = range(args.n_folds) if args.all_folds else [args.fold]

    summary = {}
    for f in folds:
        if f is None:
            raise SystemExit("groupkfold requires --all_folds or --fold")
        fold_dir = root / f"fold_{f}"
        fold_dir.mkdir(parents=True, exist_ok=True)
        save_dataset_profile_ref(fold_dir, "groupkfold", f)
        try:
            out = run_one("groupkfold", f, args.epochs, fold_dir)
        except FileNotFoundError as e:
            print(f"[skip] fold_{f}: missing anomaly train data ({e})")
            summary[f"fold_{f}"] = {"skipped": True, "reason": "missing_train_benign"}
            continue
        joblib.dump(out["model"], fold_dir / "model.joblib")
        save_json(fold_dir / "results.json", {"val": out["val"], "test": out["test"], "best_epoch": None})
        summary[f"fold_{f}"] = {"val": out["val"], "test": out["test"]}

    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()
