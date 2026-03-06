#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from train_utils import artifacts_root, now_run_id, save_json
from data_loader import load_splits
from metrics import evaluate_anomaly_scores


def run_one(dataset: str, split_mode: str, fold: int | None, epochs: int) -> dict:
    tr, va, te = load_splits(split_mode=split_mode, dataset=dataset, pipeline="anomaly", fold=fold)

    # train es solo BENIGN
    Xtr = tr.X.astype(np.float32)

    model = IsolationForest(
        n_estimators=epochs,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(Xtr)

    # scores: higher => more anomalous/attack
    Xva = va.X.astype(np.float32)
    Xte = te.X.astype(np.float32)
    sva = -model.score_samples(Xva)
    ste = -model.score_samples(Xte)

    rep_val = evaluate_anomaly_scores(va.y, sva, positive_label="ATTACK")
    rep_test = evaluate_anomaly_scores(te.y, ste, positive_label="ATTACK")

    return {
        "val": {"roc_auc": rep_val.roc_auc, "pr_auc": rep_val.pr_auc, "best_f1": rep_val.best_f1, "best_threshold": rep_val.best_threshold},
        "test": {"roc_auc": rep_test.roc_auc, "pr_auc": rep_test.pr_auc, "best_f1": rep_test.best_f1, "best_threshold": rep_test.best_threshold},
        "model": model,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="TrafficLabelling", choices=["TrafficLabelling", "MachineLearningCVE"])
    ap.add_argument("--split_mode", required=True, choices=["day", "groupkfold"])
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)
    ap.add_argument("--epochs", type=int, default=300)
    args = ap.parse_args()

    model_name = f"anomaly_isoforest_{args.dataset}"
    run_id = now_run_id()
    root = artifacts_root(model_name, args.split_mode, run_id)

    if args.split_mode == "day":
        out = run_one(args.dataset, "day", None, args.epochs)
        joblib.dump(out["model"], root / "model.joblib")
        save_json(root / "results.json", {"val": out["val"], "test": out["test"], "best_epoch": None})
        print("Saved:", root)
        return

    # dev default: only fold 4
    if (not args.all_folds) and (args.fold is None):
        args.fold = 4

    folds = range(8) if args.all_folds else [args.fold]
    summary = {}
    for f in folds:
        if f is None:
            raise SystemExit("groupkfold requiere --all_folds o --fold.")
        fold_dir = root / f"fold_{f}"
        fold_dir.mkdir(parents=True, exist_ok=True)
        out = run_one(args.dataset, "groupkfold", f)
        joblib.dump(out["model"], fold_dir / "model.joblib")
        save_json(fold_dir / "results.json", {"val": out["val"], "test": out["test"], "best_epoch": None})
        summary[f"fold_{f}"] = {"val": out["val"], "test": out["test"]}
    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()
