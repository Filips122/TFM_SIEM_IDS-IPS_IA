#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quantify how much of the weak label is recoverable without detecting anything.

The ARGOS-LAB labels come from a rule engine, so before reporting any detection
result we need to know how much of the target a model can reach by simply
re-deriving that rule. This script fits deliberately trivial classifiers and
reports what each achieves:

  * single-feature stumps (agent_id alone, decoder alone, hour alone, ...)
  * one model per feature group (behavioral / context / signature)
  * the three named feature regimes

If a one-feature model reaches the same score as the full model, the task is
label reconstruction, not intrusion detection. Run this first; every other
result in this folder should be read against its output.

Usage:
    python leakage_audit.py --split_mode date
"""

from __future__ import annotations

import argparse
from typing import Dict, List

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, balanced_accuracy_score, f1_score, roc_auc_score

from data_loader import EmptySplitError, load_split
from feature_spec import FEATURE_GROUPS, FEATURE_SETS
from train_utils import artifacts_root, fit_label_encoder, now_run_id, run_header, save_json, set_seed

# Individually suspicious columns: each was either an input to the labelling
# policy or is confounded with it by the capture layout.
SINGLE_FEATURE_PROBES = [
    "agent_id_code",
    "decoder_code",
    "grp_trivy_ratio",
    "grp_auth_failed_ratio",
    "grp_invalid_login_ratio",
    "rule_level_mean",
    "rule_level_max",
    "event_hour",
    "top_rule_share",
    "mitre_tagged_ratio",
    # behavioral controls, for contrast
    "alert_count",
    "unique_src_ip",
    "src_ip_entropy_norm",
    "new_src_ip_ratio",
]


def score_subset(
    columns: List[str],
    train,
    test,
    encoder,
    y_train: np.ndarray,
    y_test: np.ndarray,
    max_iter: int,
    seed: int,
) -> Dict[str, float]:
    index = {name: position for position, name in enumerate(train.feature_names)}
    positions = [index[name] for name in columns if name in index]
    if not positions:
        return {"error": "no matching columns"}

    Xtr = train.X[:, positions]
    Xte = test.X[:, positions]
    model = HistGradientBoostingClassifier(
        max_iter=max_iter, learning_rate=0.1, max_depth=4,
        early_stopping=True, validation_fraction=0.15,
        class_weight="balanced", random_state=seed,
    )
    model.fit(Xtr, y_train)
    proba = model.predict_proba(Xte)
    pos = list(map(str, encoder.classes_)).index("ATTACK") if "ATTACK" in list(map(str, encoder.classes_)) else 1
    y_binary = (y_test == pos).astype(int)
    prediction = proba.argmax(axis=1)

    out = {
        "n_features": len(positions),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, prediction)),
        "macro_f1": float(f1_score(y_test, prediction, average="macro", zero_division=0)),
    }
    if len(np.unique(y_binary)) > 1:
        out["roc_auc"] = float(roc_auc_score(y_binary, proba[:, pos]))
        out["pr_auc"] = float(average_precision_score(y_binary, proba[:, pos]))
        out["pr_auc_baseline"] = float(y_binary.mean())
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit weak-label leakage in ARGOS-LAB")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--dataset", default="ARGOS-LAB")
    parser.add_argument("--pipeline", default="binary", choices=["binary", "multiclass", "taxonomy"])
    parser.add_argument("--max_iter", type=int, default=120)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    set_seed(args.seed)
    run_header(
        "leakage_audit (ARGOS-LAB)",
        split_mode=args.split_mode,
        pipeline=args.pipeline,
        fold=args.fold,
    )

    common = dict(split_mode=args.split_mode, dataset=args.dataset, pipeline=args.pipeline, fold=args.fold, feature_set="full")
    try:
        train = load_split(split="train", **common)
        test = load_split(split="test", feature_cols=None, **common)
    except (FileNotFoundError, EmptySplitError) as exc:
        raise SystemExit(f"Cannot load {args.dataset}: {exc}")

    encoder = fit_label_encoder(train.y)
    y_train = encoder.transform(train.y.astype(str))
    y_test = encoder.transform(test.y.astype(str))
    print(f"train={len(train):,} rows  test={len(test):,} rows  classes={list(map(str, encoder.classes_))}")
    print(f"test positive rate = {float((test.y == 'ATTACK').mean()):.4f}\n")

    results: Dict[str, Dict] = {"single_feature": {}, "feature_group": {}, "feature_set": {}}

    print("-- single-feature probes " + "-" * 46)
    for name in SINGLE_FEATURE_PROBES:
        if name not in train.feature_names:
            continue
        outcome = score_subset([name], train, test, encoder, y_train, y_test, args.max_iter, args.seed)
        results["single_feature"][name] = outcome
        print(f"  {name:<26} PR-AUC={outcome.get('pr_auc', float('nan')):.4f}  "
              f"ROC-AUC={outcome.get('roc_auc', float('nan')):.4f}  "
              f"balanced_acc={outcome['balanced_accuracy']:.4f}")

    print("\n-- feature groups " + "-" * 53)
    for name, columns in FEATURE_GROUPS.items():
        outcome = score_subset(columns, train, test, encoder, y_train, y_test, args.max_iter, args.seed)
        results["feature_group"][name] = outcome
        print(f"  {name:<26} PR-AUC={outcome.get('pr_auc', float('nan')):.4f}  "
              f"ROC-AUC={outcome.get('roc_auc', float('nan')):.4f}  "
              f"balanced_acc={outcome['balanced_accuracy']:.4f}  (n={outcome['n_features']})")

    print("\n-- named feature regimes " + "-" * 46)
    for name, columns in FEATURE_SETS.items():
        outcome = score_subset(columns, train, test, encoder, y_train, y_test, args.max_iter, args.seed)
        results["feature_set"][name] = outcome
        print(f"  {name:<26} PR-AUC={outcome.get('pr_auc', float('nan')):.4f}  "
              f"ROC-AUC={outcome.get('roc_auc', float('nan')):.4f}  "
              f"balanced_acc={outcome['balanced_accuracy']:.4f}  (n={outcome['n_features']})")

    single = results["single_feature"]
    best_single = max(single.items(), key=lambda kv: kv[1].get("pr_auc", 0.0)) if single else (None, {})
    full_pr = results["feature_set"].get("full", {}).get("pr_auc", float("nan"))
    behavioral_pr = results["feature_set"].get("behavioral", {}).get("pr_auc", float("nan"))

    verdict = {
        "best_single_feature": best_single[0],
        "best_single_feature_pr_auc": best_single[1].get("pr_auc"),
        "full_regime_pr_auc": full_pr,
        "behavioral_regime_pr_auc": behavioral_pr,
        "single_feature_recovers_full": bool(best_single[1].get("pr_auc", 0.0) >= 0.98 * (full_pr or 0.0)),
        "interpretation": (
            "If `single_feature_recovers_full` is true, the supervised binary task is label "
            "reconstruction: one column reproduces the whole model. Report the behavioral regime "
            "and the unsupervised anomaly results as the detection findings, and treat the full "
            "regime purely as an upper bound on label recoverability."
        ),
    }
    print("\n-- verdict " + "-" * 60)
    print(f"  best single feature      : {verdict['best_single_feature']} (PR-AUC {verdict['best_single_feature_pr_auc']:.4f})")
    print(f"  full regime PR-AUC       : {full_pr:.4f}")
    print(f"  behavioral regime PR-AUC : {behavioral_pr:.4f}")
    print(f"  one column ~= full model : {verdict['single_feature_recovers_full']}")

    root = artifacts_root("leakage_audit", args.split_mode, "audit", now_run_id())
    save_json(root / "results.json", {"args": vars(args), "results": results, "verdict": verdict})
    print(f"\nSaved: {root}")


if __name__ == "__main__":
    main()
