from __future__ import annotations

import argparse

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from data_loader import EmptySplitError, load_splits_bounded
from metrics import evaluate_anomaly_scores
from reporting import save_anomaly_plots
from train_utils import artifacts_root, now_run_id, save_json


def _safe_anomaly_metrics(y_true: np.ndarray, scores: np.ndarray) -> dict:
    y = np.array([1 if str(value) == "ATTACK" else 0 for value in y_true], dtype=int)
    if len(y) == 0 or len(np.unique(y)) < 2:
        return {
            "roc_auc": None,
            "pr_auc": None,
            "best_f1": None,
            "best_threshold": None,
            "warning": "split has fewer than two classes after bounded loading",
        }

    report = evaluate_anomaly_scores(y_true, scores, positive_label="ATTACK")
    return {
        "roc_auc": report.roc_auc,
        "pr_auc": report.pr_auc,
        "best_f1": report.best_f1,
        "best_threshold": report.best_threshold,
    }


def run_one(
    split_mode: str,
    fold: int | None,
    epochs: int,
    out_dir,
    dataset: str,
    max_train_rows: int | None,
    max_eval_rows: int | None,
    sample_frac: float | None,
    n_jobs: int,
    seed: int,
    shuffle_files: bool,
) -> dict:
    tr, va, te = load_splits_bounded(
        split_mode=split_mode,
        dataset=dataset,
        pipeline="anomaly",
        fold=fold,
        max_train_rows=max_train_rows,
        max_eval_rows=max_eval_rows,
        sample_frac=sample_frac,
        seed=seed,
        shuffle_files=shuffle_files,
    )

    Xtr = tr.X.astype(np.float32)
    model = IsolationForest(
        n_estimators=epochs,
        contamination="auto",
        random_state=seed,
        n_jobs=n_jobs,
    )
    model.fit(Xtr)

    Xva = va.X.astype(np.float32)
    Xte = te.X.astype(np.float32)
    sva = -model.score_samples(Xva)
    ste = -model.score_samples(Xte)

    rep_val = _safe_anomaly_metrics(va.y, sva)
    rep_test = _safe_anomaly_metrics(te.y, ste)

    save_anomaly_plots(out_dir, "val", va.y, sva, positive_label="ATTACK")
    save_anomaly_plots(out_dir, "test", te.y, ste, positive_label="ATTACK")

    return {
        "val": rep_val,
        "test": rep_test,
        "data": {
            "train_rows_loaded": int(len(tr.X)),
            "val_rows_loaded": int(len(va.X)),
            "test_rows_loaded": int(len(te.X)),
            "n_features": int(tr.X.shape[1]) if tr.X.ndim == 2 else 0,
            "max_train_rows": max_train_rows,
            "max_eval_rows": max_eval_rows,
            "sample_frac": sample_frac,
            "shuffle_files": shuffle_files,
            "seed": seed,
            "n_jobs": n_jobs,
        },
        "model": model,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)
    ap.add_argument("--n_folds", type=int, default=8)
    ap.add_argument("--epochs", type=int, default=315)
    ap.add_argument("--dataset", type=str, default="UGR16")
    ap.add_argument("--max_train_rows", type=int, default=500_000)
    ap.add_argument("--max_eval_rows", type=int, default=200_000)
    ap.add_argument("--sample_frac", type=float, default=None)
    ap.add_argument("--n_jobs", type=int, default=1)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--no_shuffle_files", action="store_true")
    args = ap.parse_args()

    model_name = "anomaly_isoforest_UGR16"
    run_id = now_run_id()
    root = artifacts_root(model_name, args.split_mode, run_id, dataset=args.dataset, run_config={"sample_frac": args.sample_frac, "epochs": args.epochs, "max_train_rows": args.max_train_rows, "max_eval_rows": args.max_eval_rows, "n_jobs": args.n_jobs})

    if args.split_mode != "groupkfold":
        try:
            out = run_one(
                args.split_mode,
                None,
                args.epochs,
                root,
                args.dataset,
                args.max_train_rows,
                args.max_eval_rows,
                args.sample_frac,
                args.n_jobs,
                args.seed,
                not args.no_shuffle_files,
            )
        except (FileNotFoundError, EmptySplitError) as e:
            raise SystemExit(
                f"{args.dataset} anomaly split is missing or empty. "
                "This usually means preprocessing did not generate BENIGN train rows or the split is incomplete. "
                f"Details: {e}"
            )
        joblib.dump(out["model"], root / "model.joblib")
        save_json(
            root / "results.json",
            {"dataset": args.dataset, "val": out["val"], "test": out["test"], "data": out["data"], "best_epoch": None},
        )
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
            out = run_one(
                "groupkfold",
                f,
                args.epochs,
                fold_dir,
                args.dataset,
                args.max_train_rows,
                args.max_eval_rows,
                args.sample_frac,
                args.n_jobs,
                args.seed + f,
                not args.no_shuffle_files,
            )
        except (FileNotFoundError, EmptySplitError) as e:
            print(f"[skip] fold_{f}: {e}")
            summary[f"fold_{f}"] = {"skipped": True, "reason": str(e)}
            continue
        joblib.dump(out["model"], fold_dir / "model.joblib")
        save_json(
            fold_dir / "results.json",
            {"dataset": args.dataset, "val": out["val"], "test": out["test"], "data": out["data"], "best_epoch": None},
        )
        summary[f"fold_{f}"] = {"dataset": args.dataset, "val": out["val"], "test": out["test"], "data": out["data"]}

    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()
