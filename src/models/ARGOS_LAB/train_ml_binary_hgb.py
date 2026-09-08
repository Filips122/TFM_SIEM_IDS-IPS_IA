#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gradient-boosted trees for the ARGOS-LAB binary window task.

Always state the feature regime. The same script run three ways answers three
different questions:

    --feature_set full         how recoverable is the labelling rule?     (ceiling)
    --feature_set nosignature  behaviour + agent/calendar context
    --feature_set behavioral   behaviour only                             (honest)

And on the posture-excluded dataset it answers the one that matters:

    --dataset ARGOS-LAB-NOPOSTURE --feature_set behavioral

Class weighting is on by default because the window-level minority class is
~2% of rows, and the decision threshold is tuned on validation rather than
left at argmax.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
from sklearn.ensemble import HistGradientBoostingClassifier

from data_loader import EmptySplitError, load_splits
from reporting import best_threshold, permutation_importance_report, plot_corr_matrix, save_metrics_and_plots
from train_utils import (
    align_labels,
    artifacts_root,
    fit_label_encoder,
    now_run_id,
    run_header,
    save_json,
    save_label_encoder,
    set_seed,
)


def run_one(split_mode: str, fold: int | None, out_dir: Path, args) -> dict:
    train, val, test = load_splits(
        split_mode=split_mode,
        dataset=args.dataset,
        pipeline=args.pipeline,
        fold=fold,
        feature_set=args.feature_set,
        sample_frac=args.sample_frac,
        seed=args.seed,
        exclude_posture_windows=args.exclude_posture_windows,
    )
    encoder = fit_label_encoder(train.y)
    y_train = align_labels(encoder, train.y)
    y_val = align_labels(encoder, val.y)
    y_test = align_labels(encoder, test.y)

    print(f"  train={len(train):,}  val={len(val):,}  test={len(test):,}  "
          f"features={len(train.feature_names)}  classes={list(map(str, encoder.classes_))}")

    model = HistGradientBoostingClassifier(
        max_iter=args.epochs,
        learning_rate=args.learning_rate,
        max_depth=args.max_depth,
        l2_regularization=args.l2,
        early_stopping=True,
        validation_fraction=0.15,
        n_iter_no_change=args.patience,
        class_weight="balanced" if args.class_weight else None,
        random_state=args.seed,
    )
    model.fit(train.X, y_train)

    p_train = model.predict_proba(train.X)
    p_val = model.predict_proba(val.X)
    p_test = model.predict_proba(test.X)

    # Tune on validation only, then apply the same threshold to test.
    threshold = best_threshold(y_val, p_val, encoder.classes_) if len(encoder.classes_) == 2 else None
    posture = {name: (split.meta["posture_ratio"].to_numpy() if "posture_ratio" in split.meta else None)
               for name, split in (("train", train), ("val", val), ("test", test))}

    metrics = {
        "train": save_metrics_and_plots(out_dir, "train", y_train, p_train, encoder.classes_, threshold, posture["train"]),
        "val": save_metrics_and_plots(out_dir, "val", y_val, p_val, encoder.classes_, threshold, posture["val"]),
        "test": save_metrics_and_plots(out_dir, "test", y_test, p_test, encoder.classes_, threshold, posture["test"]),
    }

    plot_corr_matrix(train.X, out_dir / "plots" / "corr_matrix.png", train.feature_names)
    if args.importance:
        print("  computing permutation importance ...", flush=True)
        importance = permutation_importance_report(
            model.predict_proba, test.X, y_test, test.feature_names, out_dir, encoder.classes_,
            n_repeats=args.importance_repeats, seed=args.seed,
        )
        top = list(importance.items())[:8]
        print("  top features: " + ", ".join(f"{name}={value:.4f}" for name, value in top))

    joblib.dump(model, out_dir / "model.joblib")
    save_label_encoder(out_dir, encoder)
    save_json(out_dir / "feature_names.json", {"feature_set": args.feature_set, "features": train.feature_names})
    return {"best_iter": int(getattr(model, "n_iter_", args.epochs)), "threshold": threshold, **metrics}


def summarize(tag: str, metrics: dict) -> None:
    test = metrics["test"]
    print(f"  [{tag}] balanced_acc={test['balanced_accuracy']:.4f}  macro_f1={test['macro_f1']:.4f}  "
          f"mcc={test.get('mcc', float('nan')):.4f}  roc_auc={test.get('roc_auc') or float('nan'):.4f}  "
          f"pr_auc_minority={test.get('pr_auc_minority') or float('nan'):.4f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="HistGradientBoosting on ARGOS-LAB windows")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    parser.add_argument("--dataset", default="ARGOS-LAB")
    parser.add_argument("--pipeline", default="binary", choices=["binary", "multiclass", "taxonomy"])
    parser.add_argument("--feature_set", default="behavioral", choices=["full", "nosignature", "behavioral"])
    parser.add_argument("--exclude_posture_windows", action="store_true",
                        help="drop scanner-dominated windows at load time (posture_ratio >= 0.5)")
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--n_folds", type=int, default=4)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--epochs", type=int, default=300)
    parser.add_argument("--learning_rate", type=float, default=0.08)
    parser.add_argument("--max_depth", type=int, default=6)
    parser.add_argument("--l2", type=float, default=1.0)
    parser.add_argument("--patience", type=int, default=15)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--class_weight", action="store_true", default=True)
    parser.add_argument("--no_class_weight", dest="class_weight", action="store_false")
    parser.add_argument("--importance", action="store_true", default=True)
    parser.add_argument("--no_importance", dest="importance", action="store_false")
    parser.add_argument("--importance_repeats", type=int, default=3)
    args = parser.parse_args()

    set_seed(args.seed)
    model_name = f"ml_{args.pipeline}_hgb"
    root = artifacts_root(model_name, args.split_mode, f"{args.dataset}__{args.feature_set}", now_run_id())
    run_header(
        f"train_ml_{args.pipeline}_hgb (ARGOS-LAB)",
        dataset=args.dataset, split_mode=args.split_mode, feature_set=args.feature_set,
        class_weight=args.class_weight, out=root,
    )

    if args.split_mode != "groupkfold":
        try:
            out = run_one(args.split_mode, None, root, args)
        except (FileNotFoundError, EmptySplitError) as exc:
            raise SystemExit(f"{args.dataset} {args.pipeline} split is missing or empty: {exc}")
        summarize(args.feature_set, out)
        save_json(root / "results.json", {
            "args": vars(args), "best_iter": out["best_iter"], "threshold": out["threshold"],
            "val": out["val"], "test": out["test"],
        })
        print("Saved:", root)
        return

    folds = range(args.n_folds) if args.all_folds else [0 if args.fold is None else args.fold]
    summary = {}
    for fold in folds:
        fold_dir = root / f"fold_{fold}"
        fold_dir.mkdir(parents=True, exist_ok=True)
        print(f"-- fold {fold} (leave-one-agent-out)")
        try:
            out = run_one("groupkfold", int(fold), fold_dir, args)
        except (FileNotFoundError, EmptySplitError, SystemExit) as exc:
            print(f"  [skip] {exc}")
            summary[f"fold_{fold}"] = {"skipped": True, "reason": str(exc)}
            continue
        summarize(f"fold_{fold}", out)
        save_json(fold_dir / "results.json", {"best_iter": out["best_iter"], "threshold": out["threshold"], "test": out["test"]})
        summary[f"fold_{fold}"] = {"best_iter": out["best_iter"], "test": out["test"]}
    save_json(root / "summary.json", {"args": vars(args), "folds": summary})
    print("Saved:", root)


if __name__ == "__main__":
    main()
