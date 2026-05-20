#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder

from data_loader import load_splits
from reporting import plot_corr_matrix, save_metrics_and_plots, save_staged_classification_history
from train_utils import artifacts_root, now_run_id, save_dataset_profile_ref, save_json, save_label_encoder


def assert_eval_labels_seen_in_train(train_y: np.ndarray, val_y: np.ndarray, test_y: np.ndarray) -> None:
    train_labels = set(map(str, train_y))
    unseen_val = sorted(set(map(str, val_y)) - train_labels)
    unseen_test = sorted(set(map(str, test_y)) - train_labels)
    if unseen_val or unseen_test:
        raise SystemExit(
            "Evaluation labels absent from multiclass train split. "
            f"unseen_val={unseen_val}; unseen_test={unseen_test}. "
            "Regenerate the dataset after normalizing attack categories or change the split."
        )


def run_one(split_mode: str, fold: int | None, sample_frac: float | None, epochs: int, out_dir) -> dict:
    tr, va, te = load_splits(
        split_mode=split_mode,
        dataset="NUSW-NB15",
        pipeline="multiclass",
        fold=fold,
        sample_frac=sample_frac,
        seed=42,
    )

    assert_eval_labels_seen_in_train(tr.y, va.y, te.y)

    le = LabelEncoder().fit(tr.y.astype(str))
    ytr = le.transform(tr.y.astype(str))
    yva = le.transform(va.y.astype(str))
    yte = le.transform(te.y.astype(str))

    Xtr = tr.X.astype(np.float32)
    Xva = va.X.astype(np.float32)
    Xte = te.X.astype(np.float32)

    model = HistGradientBoostingClassifier(
        max_iter=epochs,
        learning_rate=0.1,
        max_depth=4,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=7,
        tol=1e-4,
        random_state=42,
    )
    model.fit(Xtr, ytr)
    save_staged_classification_history(out_dir, model, Xtr, ytr, Xva, yva, le.classes_)

    ptr = model.predict_proba(Xtr)
    pva = model.predict_proba(Xva)
    pte = model.predict_proba(Xte)

    m_tr = save_metrics_and_plots(out_dir, "train", ytr, ptr, le.classes_, make_roc_and_calibration=False)
    m_va = save_metrics_and_plots(out_dir, "val", yva, pva, le.classes_, make_roc_and_calibration=False)
    m_te = save_metrics_and_plots(out_dir, "test", yte, pte, le.classes_, make_roc_and_calibration=True)

    plot_corr_matrix(Xtr, out_dir / "plots" / "corr_matrix.png")

    joblib.dump(model, out_dir / "model.joblib")
    save_label_encoder(out_dir, le)

    return {
        "best_iter": int(getattr(model, "n_iter_", model.max_iter)),
        "test": m_te,
        "val": m_va,
        "train": m_tr,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split_mode", default="random", choices=["random", "groupkfold", "official"])
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)
    ap.add_argument("--n_folds", type=int, default=8)
    ap.add_argument("--sample_frac", type=float, default=None)
    ap.add_argument("--epochs", type=int, default=265)
    args = ap.parse_args()

    model_name = "offline_NUSW_multiclass_hgb"
    run_id = now_run_id()
    root = artifacts_root(model_name, args.split_mode, run_id)

    if args.split_mode != "groupkfold":
        out = run_one(args.split_mode, None, args.sample_frac, args.epochs, root)
        save_json(root / "results.json", {"best_iter": out["best_iter"], "test": out["test"]})
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
        out = run_one("groupkfold", f, args.sample_frac, args.epochs, fold_dir)
        save_json(fold_dir / "results.json", {"best_iter": out["best_iter"], "test": out["test"]})
        summary[f"fold_{f}"] = {"best_iter": out["best_iter"], "test": out["test"]}

    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()
