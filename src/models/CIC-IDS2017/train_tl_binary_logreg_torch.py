#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import numpy as np
import torch
import torch.nn as nn

from models_torch import TorchLogReg
from train_utils import (
    TorchTrainConfig, artifacts_root, fit_label_encoder, get_device, history_to_csv,
    load_splits, now_run_id, save_json, save_label_encoder, save_scaler_stats,
    set_seed, standardize_apply, standardize_fit, torch_dataloaders_from_numpy,
    train_torch_classifier,
)
from reporting import plot_history, predict_proba_torch, save_metrics_and_plots, plot_corr_matrix


def run_one(split_mode: str, fold: int | None, cfg: TorchTrainConfig, sample_frac: float | None, out_dir) -> dict:
    tr, va, te = load_splits(
        split_mode=split_mode,
        dataset="TrafficLabelling",
        pipeline="binary",
        fold=fold,
        sample_frac=sample_frac,
        seed=cfg.seed,
    )

    le = fit_label_encoder(tr.y)
    ytr = le.transform(tr.y).astype(np.int64)
    yva = le.transform(va.y).astype(np.int64)
    yte = le.transform(te.y).astype(np.int64)

    Xtr = tr.X.astype(np.float32)
    Xva = va.X.astype(np.float32)
    Xte = te.X.astype(np.float32)

    Xtr, mean, std = standardize_fit(Xtr)
    Xva = standardize_apply(Xva, mean, std)
    Xte = standardize_apply(Xte, mean, std)

    device = get_device()
    set_seed(cfg.seed)

    model = TorchLogReg(in_features=Xtr.shape[1], n_classes=len(le.classes_)).to(device)
    criterion = nn.CrossEntropyLoss()
    opt = torch.optim.AdamW(model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)

    tr_loader, va_loader = torch_dataloaders_from_numpy(Xtr, ytr, Xva, yva, batch_size=cfg.batch_size)

    # save best checkpoint during training
    cfg.checkpoint_path = out_dir / "best_model.pt"
    best_state, history, best_epoch = train_torch_classifier(
        model, tr_loader, va_loader, criterion, opt, device, cfg, run_name="online_TL_logreg", n_classes=len(le.classes_)
    )
    model.load_state_dict(best_state)

    # probs
    p_tr = predict_proba_torch(model, Xtr, device, batch_size=cfg.batch_size)
    p_va = predict_proba_torch(model, Xva, device, batch_size=cfg.batch_size)
    p_te = predict_proba_torch(model, Xte, device, batch_size=cfg.batch_size)

    # metrics + plots
    m_tr = save_metrics_and_plots(out_dir, "train", ytr, p_tr, le.classes_, make_roc_and_calibration=False)
    m_va = save_metrics_and_plots(out_dir, "val", yva, p_va, le.classes_, make_roc_and_calibration=False)
    m_te = save_metrics_and_plots(out_dir, "test", yte, p_te, le.classes_, make_roc_and_calibration=True)

    # training curves
    history_to_csv(out_dir / "history.csv", history)
    plot_history(out_dir / "history.csv", out_dir / "plots")

    # correlation matrix (tabular)
    plot_corr_matrix(Xtr, out_dir / "plots" / "corr_matrix.png")

    # artifacts
    save_label_encoder(out_dir, le)
    save_scaler_stats(out_dir, mean, std)
    torch.save(best_state, out_dir / "best_model.pt")  # final overwrite just in case

    return {
        "best_epoch": best_epoch,
        "test": m_te,
        "val": m_va,
        "train": m_tr,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split_mode", required=True, choices=["day", "groupkfold"])
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)
    ap.add_argument("--sample_frac", type=float, default=None, help="Ej: 0.1 para 10% (dev)")

    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--batch_size", type=int, default=8192)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--weight_decay", type=float, default=1e-4)
    ap.add_argument("--patience", type=int, default=7)
    ap.add_argument("--gap_weight", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=42)

    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--log_every_batches", type=int, default=20)
    ap.add_argument("--max_eval_samples", type=int, default=200000)
    args = ap.parse_args()

    cfg = TorchTrainConfig(
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        weight_decay=args.weight_decay,
        patience=args.patience,
        gap_weight=args.gap_weight,
        seed=args.seed,
        verbose=(not args.quiet),
        log_every_batches=args.log_every_batches,
        max_eval_samples=args.max_eval_samples,
    )

    model_name = "online_TL_binary_logreg_torch"
    run_id = now_run_id()
    root = artifacts_root(model_name, args.split_mode, run_id)

    if args.split_mode == "day":
        out = run_one("day", None, cfg, args.sample_frac, root)
        save_json(root / "results.json", {"best_epoch": out["best_epoch"], "test": out["test"]})
        print("Saved:", root)
        return

    # groupkfold: default fold 4 for dev
    if (not args.all_folds) and (args.fold is None):
        args.fold = 4

    folds = range(8) if args.all_folds else [args.fold]
    summary = {}
    for f in folds:
        if f is None:
            raise SystemExit("groupkfold requiere --all_folds o --fold.")
        fold_dir = root / f"fold_{f}"
        fold_dir.mkdir(parents=True, exist_ok=True)

        out = run_one("groupkfold", f, cfg, args.sample_frac, fold_dir)
        save_json(fold_dir / "results.json", {"best_epoch": out["best_epoch"], "test": out["test"]})
        summary[f"fold_{f}"] = {"best_epoch": out["best_epoch"], "test": out["test"]}

    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()
