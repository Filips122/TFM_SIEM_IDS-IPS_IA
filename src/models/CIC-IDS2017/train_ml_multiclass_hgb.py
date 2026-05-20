#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder

from train_utils import artifacts_root, load_splits, now_run_id, save_json
from reporting import save_metrics_and_plots, plot_corr_matrix, save_staged_classification_history


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split_mode", default="random", choices=["random", "day", "groupkfold"])
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)
    ap.add_argument("--sample_frac", type=float, default=None)
    ap.add_argument("--epochs", type=int, default=265)
    args = ap.parse_args()

    model_name = "offline_ML_multiclass_hgb"
    run_id = now_run_id()
    root = artifacts_root(model_name, args.split_mode, run_id, run_config={"sample_frac": args.sample_frac, "epochs": args.epochs})

    def run_one(split_mode: str, fold: int | None, out_dir):
        tr, va, te = load_splits(split_mode=split_mode, dataset="MachineLearningCVE", pipeline="multiclass", fold=fold, sample_frac=args.sample_frac)
        le = LabelEncoder().fit(tr.y.astype(str))
        ytr = le.transform(tr.y.astype(str))
        yva = le.transform(va.y.astype(str))
        yte = le.transform(te.y.astype(str))

        Xtr = tr.X.astype(np.float32)
        Xva = va.X.astype(np.float32)
        Xte = te.X.astype(np.float32)

        model = HistGradientBoostingClassifier(
            max_iter=args.epochs,
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
        m_te = save_metrics_and_plots(out_dir, "test", yte, pte, le.classes_, make_roc_and_calibration=True)  # calibration only

        plot_corr_matrix(Xtr, out_dir / "plots" / "corr_matrix.png")

        joblib.dump(model, out_dir / "model.joblib")
        (out_dir / "label_map.json").write_text(
            __import__("json").dumps({c: int(i) for i, c in enumerate(le.classes_)}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        save_json(out_dir / "results.json", {"best_iter": int(getattr(model, "n_iter_", model.max_iter)), "test": m_te})
        return {"best_iter": int(getattr(model, "n_iter_", model.max_iter)), "test": m_te}

    if args.split_mode != "groupkfold":
        run_one(args.split_mode, None, root)
        print("Saved:", root)
        return

    if (not args.all_folds) and (args.fold is None):
        args.fold = 4
    folds = range(8) if args.all_folds else [args.fold]
    summary = {}
    for f in folds:
        if f is None:
            raise SystemExit("groupkfold requiere --all_folds o --fold.")
        fold_dir = root / f"fold_{f}"
        fold_dir.mkdir(parents=True, exist_ok=True)
        out = run_one("groupkfold", f, fold_dir)
        summary[f"fold_{f}"] = out
    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()
