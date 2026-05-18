#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from data_loader import EmptySplitError, load_splits
from reporting import plot_corr_matrix, save_metrics_and_plots, save_staged_classification_history
from train_utils import artifacts_root, fit_label_encoder, now_run_id, save_json, save_label_encoder


def run_one(split_mode: str, fold: int | None, sample_frac: float | None, epochs: int, out_dir, dataset: str) -> dict:
    train, val, test = load_splits(split_mode=split_mode, dataset=dataset, pipeline="binary", fold=fold, sample_frac=sample_frac)
    encoder = fit_label_encoder(train.y)
    y_train = encoder.transform(train.y.astype(str))
    y_val = encoder.transform(val.y.astype(str))
    y_test = encoder.transform(test.y.astype(str))
    X_train = train.X.astype(np.float32)
    X_val = val.X.astype(np.float32)
    X_test = test.X.astype(np.float32)
    model = HistGradientBoostingClassifier(max_iter=epochs, learning_rate=0.08, max_depth=3, early_stopping=True, validation_fraction=0.15, random_state=42)
    model.fit(X_train, y_train)
    save_staged_classification_history(out_dir, model, X_train, y_train, X_val, y_val, encoder.classes_)
    p_train = model.predict_proba(X_train)
    p_val = model.predict_proba(X_val)
    p_test = model.predict_proba(X_test)
    metrics_train = save_metrics_and_plots(out_dir, "train", y_train, p_train, encoder.classes_)
    metrics_val = save_metrics_and_plots(out_dir, "val", y_val, p_val, encoder.classes_)
    metrics_test = save_metrics_and_plots(out_dir, "test", y_test, p_test, encoder.classes_)
    plot_corr_matrix(X_train, out_dir / "plots" / "corr_matrix.png")
    joblib.dump(model, out_dir / "model.joblib")
    save_label_encoder(out_dir, encoder)
    return {"best_iter": int(getattr(model, "n_iter_", model.max_iter)), "train": metrics_train, "val": metrics_val, "test": metrics_test}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    parser.add_argument("--dataset", default="LAB-ALERTS")
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--n_folds", type=int, default=5)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--epochs", type=int, default=215)
    args = parser.parse_args()
    root = artifacts_root("offline_LAB_ALERTS_binary_hgb", args.split_mode, now_run_id())
    if args.split_mode != "groupkfold":
        try:
            out = run_one(args.split_mode, None, args.sample_frac, args.epochs, root, args.dataset)
        except (FileNotFoundError, EmptySplitError) as exc:
            raise SystemExit(f"{args.dataset} binary split is missing or empty: {exc}")
        save_json(root / "results.json", {"best_iter": out["best_iter"], "test": out["test"]})
        print("Saved:", root)
        return
    folds = range(args.n_folds) if args.all_folds else [0 if args.fold is None else args.fold]
    summary = {}
    for fold in folds:
        fold_dir = root / f"fold_{fold}"
        fold_dir.mkdir(parents=True, exist_ok=True)
        try:
            out = run_one("groupkfold", int(fold), args.sample_frac, args.epochs, fold_dir, args.dataset)
        except (FileNotFoundError, EmptySplitError) as exc:
            summary[f"fold_{fold}"] = {"skipped": True, "reason": str(exc)}
            continue
        save_json(fold_dir / "results.json", {"best_iter": out["best_iter"], "test": out["test"]})
        summary[f"fold_{fold}"] = {"best_iter": out["best_iter"], "test": out["test"]}
    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()