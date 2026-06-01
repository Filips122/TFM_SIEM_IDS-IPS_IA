#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.utils.class_weight import compute_sample_weight

from data_loader import EmptySplitError, load_splits
from reporting import plot_corr_matrix, save_metrics_and_plots, save_staged_classification_history
from train_utils import artifacts_root, fit_label_encoder, now_run_id, save_dataset_profile_ref, save_json, save_label_encoder


SPLIT_MODE_CHOICES = ["date", "random", "groupkfold", "redteam_stratified_groupkfold"]
GROUP_FOLD_SPLIT_MODES = {"groupkfold", "redteam_stratified_groupkfold"}


def run_one(
    datasets_base: str,
    split_mode: str,
    fold: int | None,
    sample_frac: float | None,
    epochs: int,
    out_dir,
    dataset: str,
    class_weight: str,
) -> dict:
    train, val, test = load_splits(datasets_base=datasets_base, split_mode=split_mode, dataset=dataset, pipeline="binary", fold=fold, sample_frac=sample_frac)
    encoder = fit_label_encoder(train.y)
    if len(encoder.classes_) < 2:
        raise EmptySplitError(f"Binary trainer requires at least two classes in train split, got {list(encoder.classes_)}")
    y_train = encoder.transform(train.y.astype(str))
    y_val = encoder.transform(val.y.astype(str))
    y_test = encoder.transform(test.y.astype(str))
    X_train = train.X.astype(np.float32)
    X_val = val.X.astype(np.float32)
    X_test = test.X.astype(np.float32)
    model = HistGradientBoostingClassifier(max_iter=epochs, learning_rate=0.08, max_depth=3, early_stopping=True, validation_fraction=0.15, random_state=42)
    sample_weight = compute_sample_weight(class_weight="balanced", y=y_train) if class_weight == "balanced" else None
    model.fit(X_train, y_train, sample_weight=sample_weight)
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
    parser.add_argument("--datasets_base", default="src/models/CSR-LANL/datasets")
    parser.add_argument("--split_mode", default="date", choices=SPLIT_MODE_CHOICES)
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--n_folds", type=int, default=5)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--epochs", type=int, default=215)
    parser.add_argument("--class_weight", default="none", choices=["none", "balanced"])
    args = parser.parse_args()
    root = artifacts_root(
        "offline_CSR_LANL_binary_hgb",
        args.split_mode,
        now_run_id(),
        run_config={"sample_frac": args.sample_frac, "epochs": args.epochs, "datasets_base": args.datasets_base, "class_weight": args.class_weight},
    )
    if args.split_mode not in GROUP_FOLD_SPLIT_MODES:
        save_dataset_profile_ref(root, args.datasets_base, args.split_mode, args.dataset)
        try:
            out = run_one(args.datasets_base, args.split_mode, None, args.sample_frac, args.epochs, root, args.dataset, args.class_weight)
        except (FileNotFoundError, EmptySplitError) as exc:
            raise SystemExit(f"{args.dataset} binary split is missing, empty, or single-class: {exc}")
        save_json(root / "results.json", {"best_iter": out["best_iter"], "test": out["test"]})
        print("Saved:", root)
        return
    folds = range(args.n_folds) if args.all_folds else [0 if args.fold is None else args.fold]
    summary = {}
    for fold in folds:
        fold_dir = root / f"fold_{fold}"
        fold_dir.mkdir(parents=True, exist_ok=True)
        save_dataset_profile_ref(fold_dir, args.datasets_base, args.split_mode, args.dataset, int(fold))
        try:
            out = run_one(args.datasets_base, args.split_mode, int(fold), args.sample_frac, args.epochs, fold_dir, args.dataset, args.class_weight)
        except (FileNotFoundError, EmptySplitError) as exc:
            summary[f"fold_{fold}"] = {"skipped": True, "reason": str(exc)}
            continue
        save_json(fold_dir / "results.json", {"best_iter": out["best_iter"], "test": out["test"]})
        summary[f"fold_{fold}"] = {"best_iter": out["best_iter"], "test": out["test"]}
    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()