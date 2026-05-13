from __future__ import annotations

import argparse

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder

from data_loader import EmptySplitError, load_persisted_label_map, load_splits
from reporting import plot_corr_matrix, save_metrics_and_plots
from train_utils import artifacts_root, now_run_id, save_json, save_label_encoder, validate_persisted_label_map


def run_one(split_mode: str, fold: int | None, sample_frac: float | None, epochs: int, out_dir, dataset: str) -> dict:
    tr, va, te = load_splits(
        split_mode=split_mode,
        dataset=dataset,
        pipeline="multiclass",
        fold=fold,
        sample_frac=sample_frac,
        seed=42,
    )

    le = LabelEncoder().fit(tr.y.astype(str))
    validate_persisted_label_map(
<<<<<<< HEAD
        load_persisted_label_map(split_mode=split_mode, dataset="UGR16", pipeline="multiclass", fold=fold),
        le,
        context=f"UGR16 multiclass split_mode={split_mode} fold={fold}",
=======
        load_persisted_label_map(split_mode=split_mode, dataset=dataset, pipeline="multiclass", fold=fold),
        le,
        context=f"{dataset} multiclass split_mode={split_mode} fold={fold}",
>>>>>>> cc9f15f8d4b66ce443abe6fec2dedc28528ef8f1
    )
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
    ap.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)
    ap.add_argument("--n_folds", type=int, default=8)
    ap.add_argument("--sample_frac", type=float, default=None)
    ap.add_argument("--epochs", type=int, default=250)
    ap.add_argument("--dataset", type=str, default="UGR16")
    args = ap.parse_args()

    model_name = "offline_UGR16_multiclass_hgb"
    run_id = now_run_id()
    root = artifacts_root(model_name, args.split_mode, run_id, dataset=args.dataset)

    if args.split_mode != "groupkfold":
        try:
<<<<<<< HEAD
            out = run_one(args.split_mode, None, args.sample_frac, args.epochs, root)
        except (FileNotFoundError, EmptySplitError) as e:
            raise SystemExit(
                "UGR16 multiclass split is missing or empty. "
                "Ensure preprocessing completed and produced train, val, and test rows. "
                f"Details: {e}"
            )
        save_json(root / "results.json", {"best_iter": out["best_iter"], "test": out["test"]})
=======
            out = run_one(args.split_mode, None, args.sample_frac, args.epochs, root, args.dataset)
        except (FileNotFoundError, EmptySplitError) as e:
            raise SystemExit(
                f"{args.dataset} multiclass split is missing or empty. "
                "Ensure preprocessing completed and produced train, val, and test rows. "
                f"Details: {e}"
            )
        save_json(root / "results.json", {"dataset": args.dataset, "best_iter": out["best_iter"], "test": out["test"]})
>>>>>>> cc9f15f8d4b66ce443abe6fec2dedc28528ef8f1
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
            out = run_one("groupkfold", f, args.sample_frac, args.epochs, fold_dir)
=======
            out = run_one("groupkfold", f, args.sample_frac, args.epochs, fold_dir, args.dataset)
>>>>>>> cc9f15f8d4b66ce443abe6fec2dedc28528ef8f1
        except (FileNotFoundError, EmptySplitError) as e:
            print(f"[skip] fold_{f}: {e}")
            summary[f"fold_{f}"] = {"skipped": True, "reason": str(e)}
            continue
<<<<<<< HEAD
        save_json(fold_dir / "results.json", {"best_iter": out["best_iter"], "test": out["test"]})
        summary[f"fold_{f}"] = {"best_iter": out["best_iter"], "test": out["test"]}
=======
        save_json(fold_dir / "results.json", {"dataset": args.dataset, "best_iter": out["best_iter"], "test": out["test"]})
        summary[f"fold_{f}"] = {"dataset": args.dataset, "best_iter": out["best_iter"], "test": out["test"]}
>>>>>>> cc9f15f8d4b66ce443abe6fec2dedc28528ef8f1

    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()