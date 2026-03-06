#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import numpy as np
import torch
import torch.nn as nn

from models_torch import MLP
from train_utils import (
    TorchTrainConfig, artifacts_root, fit_label_encoder, get_device, history_to_csv,
    load_splits, now_run_id, save_json, save_label_encoder, save_scaler_stats,
    set_seed, standardize_apply, standardize_fit, torch_dataloaders_from_numpy,
    train_torch_classifier,
)
from reporting import plot_history, predict_proba_torch, save_metrics_and_plots, plot_corr_matrix


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=5)
    ap.add_argument("--batch_size", type=int, default=8192)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--weight_decay", type=float, default=1e-4)
    ap.add_argument("--patience", type=int, default=7)
    ap.add_argument("--gap_weight", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--hidden", type=int, default=512)
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--dropout", type=float, default=0.2)
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

    model_name = "offline_ML_binary_mlp"
    run_id = now_run_id()
    root = artifacts_root(model_name, "random", run_id)

    set_seed(cfg.seed)
    device = get_device()

    # TRAIN en random
    tr, va, te = load_splits(split_mode="random", dataset="MachineLearningCVE", pipeline="binary")

    le = fit_label_encoder(tr.y)
    ytr = le.transform(tr.y).astype(np.int64)
    yva = le.transform(va.y).astype(np.int64)
    yte = le.transform(te.y).astype(np.int64)

    Xtr = tr.X.astype(np.float32); Xva = va.X.astype(np.float32); Xte = te.X.astype(np.float32)
    Xtr, mean, std = standardize_fit(Xtr)
    Xva = standardize_apply(Xva, mean, std)
    Xte = standardize_apply(Xte, mean, std)

    model = MLP(in_features=Xtr.shape[1], n_classes=len(le.classes_), hidden=args.hidden, depth=args.depth, dropout=args.dropout).to(device)
    crit = nn.CrossEntropyLoss()
    opt = torch.optim.AdamW(model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)

    tr_loader, va_loader = torch_dataloaders_from_numpy(Xtr, ytr, Xva, yva, batch_size=cfg.batch_size)

    cfg.checkpoint_path = root / "best_model.pt"
    best_state, history, best_epoch = train_torch_classifier(
        model, tr_loader, va_loader, crit, opt, device, cfg, run_name="offline_ML_mlp", n_classes=len(le.classes_)
    )
    model.load_state_dict(best_state)

    # Save basics
    save_label_encoder(root, le)
    save_scaler_stats(root, mean, std)
    torch.save(best_state, root / "best_model.pt")
    history_to_csv(root / "history.csv", history)
    plot_history(root / "history.csv", root / "plots")

    # Metrics + plots (random)
    p_tr = predict_proba_torch(model, Xtr, device, batch_size=cfg.batch_size)
    p_va = predict_proba_torch(model, Xva, device, batch_size=cfg.batch_size)
    p_te = predict_proba_torch(model, Xte, device, batch_size=cfg.batch_size)

    m_tr = save_metrics_and_plots(root, "train", ytr, p_tr, le.classes_, make_roc_and_calibration=False)
    m_va = save_metrics_and_plots(root, "val", yva, p_va, le.classes_, make_roc_and_calibration=False)
    m_te = save_metrics_and_plots(root, "test", yte, p_te, le.classes_, make_roc_and_calibration=True)

    plot_corr_matrix(Xtr, root / "plots" / "corr_matrix.png")

    # Optional reports (day + groupkfold fold_4) without re-training
    # day report
    day_root = root / "report_day"
    dtr, dva, dte = load_splits(split_mode="day", dataset="MachineLearningCVE", pipeline="binary")
    dytr = le.transform(dtr.y).astype(np.int64)
    dyva = le.transform(dva.y).astype(np.int64)
    dyte = le.transform(dte.y).astype(np.int64)

    dXtr = standardize_apply(dtr.X.astype(np.float32), mean, std)
    dXva = standardize_apply(dva.X.astype(np.float32), mean, std)
    dXte = standardize_apply(dte.X.astype(np.float32), mean, std)

    dp_te = predict_proba_torch(model, dXte, device, batch_size=cfg.batch_size)
    m_day_test = save_metrics_and_plots(day_root, "test", dyte, dp_te, le.classes_, make_roc_and_calibration=True)

    # groupkfold report: ONLY fold_4
    k_root = root / "report_groupkfold" / "fold_4"
    ktr, kva, kte = load_splits(split_mode="groupkfold", dataset="MachineLearningCVE", pipeline="binary", fold=4)
    kyte = le.transform(kte.y).astype(np.int64)
    kXte = standardize_apply(kte.X.astype(np.float32), mean, std)
    kp_te = predict_proba_torch(model, kXte, device, batch_size=cfg.batch_size)
    m_kfold4_test = save_metrics_and_plots(k_root, "test", kyte, kp_te, le.classes_, make_roc_and_calibration=True)

    save_json(root / "results.json", {
        "best_epoch": best_epoch,
        "random_test": m_te,
        "day_test": m_day_test,
        "groupkfold_fold4_test": m_kfold4_test,
    })
    print("Saved:", root)


if __name__ == "__main__":
    main()
