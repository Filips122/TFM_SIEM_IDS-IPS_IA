from __future__ import annotations

import argparse

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from data_loader import EmptySplitError, load_splits
from metrics import evaluate_anomaly_scores
from reporting import save_anomaly_plots
from train_utils import artifacts_root, now_run_id, save_json


def run_one(split_mode: str, fold: int | None, epochs: int, out_dir, dataset: str) -> dict:
    tr, va, te = load_splits(split_mode=split_mode, dataset=dataset, pipeline="anomaly", fold=fold)

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
    ap.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)
    ap.add_argument("--n_folds", type=int, default=8)
    ap.add_argument("--epochs", type=int, default=300)
    ap.add_argument("--dataset", type=str, default="UGR16")
    args = ap.parse_args()

    model_name = "anomaly_isoforest_UGR16"
    run_id = now_run_id()
    root = artifacts_root(model_name, args.split_mode, run_id, dataset=args.dataset)

    if args.split_mode != "groupkfold":
        try:
<<<<<<< HEAD
            out = run_one(args.split_mode, None, args.epochs, root)
        except (FileNotFoundError, EmptySplitError) as e:
            raise SystemExit(
                "UGR16 anomaly split is missing or empty. "
=======
            out = run_one(args.split_mode, None, args.epochs, root, args.dataset)
        except (FileNotFoundError, EmptySplitError) as e:
            raise SystemExit(
                f"{args.dataset} anomaly split is missing or empty. "
>>>>>>> cc9f15f8d4b66ce443abe6fec2dedc28528ef8f1
                "This usually means preprocessing did not generate BENIGN train rows or the split is incomplete. "
                f"Details: {e}"
            )
        joblib.dump(out["model"], root / "model.joblib")
        save_json(root / "results.json", {"dataset": args.dataset, "val": out["val"], "test": out["test"], "best_epoch": None})
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
        try:
<<<<<<< HEAD
            out = run_one("groupkfold", f, args.epochs, fold_dir)
=======
            out = run_one("groupkfold", f, args.epochs, fold_dir, args.dataset)
>>>>>>> cc9f15f8d4b66ce443abe6fec2dedc28528ef8f1
        except (FileNotFoundError, EmptySplitError) as e:
            print(f"[skip] fold_{f}: {e}")
            summary[f"fold_{f}"] = {"skipped": True, "reason": str(e)}
            continue
        joblib.dump(out["model"], fold_dir / "model.joblib")
        save_json(fold_dir / "results.json", {"dataset": args.dataset, "val": out["val"], "test": out["test"], "best_epoch": None})
        summary[f"fold_{f}"] = {"dataset": args.dataset, "val": out["val"], "test": out["test"]}

    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()
