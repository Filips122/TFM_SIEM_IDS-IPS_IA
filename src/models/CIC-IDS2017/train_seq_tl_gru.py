#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import numpy as np
import torch
import torch.nn as nn

from models_torch import GRUClassifier
from sequence_loader import load_sequence_split
from train_utils import (
    TorchTrainConfig, artifacts_root, fit_label_encoder, get_device, history_to_csv,
    now_run_id, save_json, save_label_encoder, save_scaler_stats,
    set_seed, standardize_apply, standardize_fit,
    train_torch_classifier,
)
from reporting import plot_history, predict_proba_torch, save_metrics_and_plots


def flatten_seq(X: np.ndarray) -> np.ndarray:
    N, T, F = X.shape
    return X.reshape(N, T * F)


def unflatten_seq(Xf: np.ndarray, T: int, F: int) -> np.ndarray:
    return Xf.reshape(len(Xf), T, F)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["day", "groupkfold"])
    ap.add_argument("--task", default="binary", choices=["binary", "multiclass_grouped", "multiclass"])
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)

    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--batch_size", type=int, default=2048)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--weight_decay", type=float, default=1e-4)
    ap.add_argument("--patience", type=int, default=7)
    ap.add_argument("--gap_weight", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=42)

    ap.add_argument("--hidden", type=int, default=128)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--dropout", type=float, default=0.1)
    ap.add_argument("--bidirectional", action="store_true")

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

    model_name = f"seq_TL_{args.task}_gru" + ("_bi" if args.bidirectional else "")
    run_id = now_run_id()
    root = artifacts_root(model_name, args.mode, run_id)

    set_seed(cfg.seed)
    device = get_device()

    def run_fold(fold: int | None, out_dir):
        Xtr, ytr_s, T, F = load_sequence_split(mode=args.mode, task=args.task, split="train", fold=fold)
        Xva, yva_s, _, _ = load_sequence_split(mode=args.mode, task=args.task, split="val", fold=fold)
        Xte, yte_s, _, _ = load_sequence_split(mode=args.mode, task=args.task, split="test", fold=fold)

        le = fit_label_encoder(ytr_s)
        ytr = le.transform(ytr_s).astype(np.int64)
        yva = le.transform(yva_s).astype(np.int64)
        yte = le.transform(yte_s).astype(np.int64)

        # scale (flatten then unflatten)
        Xtrf = flatten_seq(Xtr).astype(np.float32)
        Xvaf = flatten_seq(Xva).astype(np.float32)
        Xtef = flatten_seq(Xte).astype(np.float32)

        Xtrf, mean, std = standardize_fit(Xtrf)
        Xvaf = standardize_apply(Xvaf, mean, std)
        Xtef = standardize_apply(Xtef, mean, std)

        Xtr = unflatten_seq(Xtrf, T, F)
        Xva = unflatten_seq(Xvaf, T, F)
        Xte = unflatten_seq(Xtef, T, F)

        model = GRUClassifier(
            n_features=F,
            n_classes=len(le.classes_),
            hidden=args.hidden,
            n_layers=args.layers,
            dropout=args.dropout,
            bidirectional=args.bidirectional,
        ).to(device)

        crit = nn.CrossEntropyLoss()
        opt = torch.optim.AdamW(model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)

        ds_tr = torch.utils.data.TensorDataset(torch.from_numpy(Xtr), torch.from_numpy(ytr))
        ds_va = torch.utils.data.TensorDataset(torch.from_numpy(Xva), torch.from_numpy(yva))
        tr_loader = torch.utils.data.DataLoader(ds_tr, batch_size=cfg.batch_size, shuffle=True, pin_memory=True)
        va_loader = torch.utils.data.DataLoader(ds_va, batch_size=cfg.batch_size, shuffle=False, pin_memory=True)

        cfg.checkpoint_path = out_dir / "best_model.pt"
        best_state, history, best_epoch = train_torch_classifier(
            model, tr_loader, va_loader, crit, opt, device, cfg, run_name=f"{model_name}", n_classes=len(le.classes_)
        )
        model.load_state_dict(best_state)

        # probs
        p_tr = predict_proba_torch(model, Xtr, device, batch_size=cfg.batch_size)
        p_va = predict_proba_torch(model, Xva, device, batch_size=cfg.batch_size)
        p_te = predict_proba_torch(model, Xte, device, batch_size=cfg.batch_size)

        m_tr = save_metrics_and_plots(out_dir, "train", ytr, p_tr, le.classes_, make_roc_and_calibration=False)
        m_va = save_metrics_and_plots(out_dir, "val", yva, p_va, le.classes_, make_roc_and_calibration=False)
        m_te = save_metrics_and_plots(out_dir, "test", yte, p_te, le.classes_, make_roc_and_calibration=True)

        save_label_encoder(out_dir, le)
        save_scaler_stats(out_dir, mean, std)
        torch.save(best_state, out_dir / "best_model.pt")
        history_to_csv(out_dir / "history.csv", history)
        plot_history(out_dir / "history.csv", out_dir / "plots")
        save_json(out_dir / "results.json", {"best_epoch": best_epoch, "test": m_te, "T": T, "F": F})
        return {"best_epoch": best_epoch, "test": m_te}

    if args.mode == "day":
        run_fold(None, root)
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
        summary[f"fold_{f}"] = run_fold(f, fold_dir)

    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()
