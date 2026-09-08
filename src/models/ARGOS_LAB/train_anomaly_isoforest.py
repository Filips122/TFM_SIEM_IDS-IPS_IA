#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Isolation Forest anomaly detection on ARGOS-LAB windows.

No label is used for fitting, which is what makes this the defensible framing
for a weakly-labelled SIEM capture: the model ranks windows by how unusual they
are, and the weak labels are only consulted afterwards to score the ranking.

Fitting policies (`--train_policy`):
  quiet   (default) fit on routine windows, defined without labels as those
          below the 60th percentile of alert_count in the training period
  benign  the classic novelty-detection setup. Degenerate on this dataset:
          97.8% of BENIGN alerts are vulnerability-scanner output, so a model
          fitted on them learns "not Trivy" rather than "not normal"
  all     fit on every training window and let contamination handle the mix
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from data_loader import EmptySplitError, load_splits
from metrics import evaluate_anomaly_both_directions
from reporting import save_anomaly_plots
from train_utils import artifacts_root, now_run_id, run_header, save_json, set_seed, standardize_apply, standardize_fit


def run_one(split_mode: str, fold: int | None, out_dir: Path, args) -> dict:
    train, val, test = load_splits(
        split_mode=split_mode,
        dataset=args.dataset,
        pipeline="anomaly",
        fold=fold,
        feature_set=args.feature_set,
        seed=args.seed,
        exclude_posture_windows=args.exclude_posture_windows,
        anomaly_train_policy=args.train_policy,
    )
    Xtr, mean, std = standardize_fit(train.X.astype(np.float32))
    Xva = standardize_apply(val.X.astype(np.float32), mean, std)
    Xte = standardize_apply(test.X.astype(np.float32), mean, std)
    print(f"  fit={len(Xtr):,} (policy={args.train_policy})  val={len(Xva):,}  test={len(Xte):,}  features={Xtr.shape[1]}")

    contamination = args.contamination if args.contamination > 0 else "auto"
    model = IsolationForest(
        n_estimators=args.n_estimators,
        max_samples=min(args.max_samples, len(Xtr)),
        contamination=contamination,
        random_state=args.seed,
        n_jobs=-1,
    )
    model.fit(Xtr)

    # Higher score == more anomalous.
    val_scores = -model.score_samples(Xva)
    test_scores = -model.score_samples(Xte)
    val_report = evaluate_anomaly_both_directions(val.y, val_scores)
    test_report = evaluate_anomaly_both_directions(test.y, test_scores)
    save_anomaly_plots(out_dir, "val", val.y, val_scores)
    save_anomaly_plots(out_dir, "test", test.y, test_scores)

    joblib.dump({"model": model, "mean": mean, "std": std}, out_dir / "model.joblib")
    np.save(out_dir / "test_scores.npy", test_scores)
    return {"val": val_report, "test": test_report}


def summarize(tag: str, report: dict) -> None:
    attack, rare = report["test"]["attack"], report["test"]["rare"]
    print(f"  [{tag}] ATTACK-direction roc_auc={attack['roc_auc']:.4f}")
    print(f"  {'':<{len(tag) + 4}} rare-class '{rare.get('positive_label', 'ATTACK')}' "
          f"(prevalence {rare['pr_auc_baseline']:.4f}): roc_auc={rare['roc_auc']:.4f}  "
          f"pr_auc={rare['pr_auc']:.4f} (lift {rare['pr_auc_lift']:.2f}x)  "
          f"P@1%={rare['precision_at_1pct']:.4f}  P@5%={rare['precision_at_5pct']:.4f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Isolation Forest on ARGOS-LAB windows")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    parser.add_argument("--dataset", default="ARGOS-LAB")
    parser.add_argument("--feature_set", default="behavioral", choices=["full", "nosignature", "behavioral"])
    parser.add_argument("--train_policy", default="quiet", choices=["quiet", "benign", "all"])
    parser.add_argument("--exclude_posture_windows", action="store_true")
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--n_folds", type=int, default=4)
    parser.add_argument("--n_estimators", type=int, default=400)
    parser.add_argument("--max_samples", type=int, default=65536)
    parser.add_argument("--contamination", type=float, default=-1.0, help="<=0 selects 'auto'")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    set_seed(args.seed)
    root = artifacts_root("anomaly_isoforest", args.split_mode,
                          f"{args.dataset}__{args.feature_set}__{args.train_policy}", now_run_id())
    run_header(
        "train_anomaly_isoforest (ARGOS-LAB)",
        dataset=args.dataset, split_mode=args.split_mode, feature_set=args.feature_set,
        train_policy=args.train_policy, out=root,
    )

    if args.split_mode != "groupkfold":
        try:
            out = run_one(args.split_mode, None, root, args)
        except (FileNotFoundError, EmptySplitError) as exc:
            raise SystemExit(f"{args.dataset} anomaly split is missing or empty: {exc}")
        summarize(args.train_policy, out)
        save_json(root / "results.json", {"args": vars(args), **out})
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
        except (FileNotFoundError, EmptySplitError) as exc:
            print(f"  [skip] {exc}")
            summary[f"fold_{fold}"] = {"skipped": True, "reason": str(exc)}
            continue
        summarize(f"fold_{fold}", out)
        save_json(fold_dir / "results.json", out)
        summary[f"fold_{fold}"] = out
    save_json(root / "summary.json", {"args": vars(args), "folds": summary})
    print("Saved:", root)


if __name__ == "__main__":
    main()
