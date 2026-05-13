#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse

import numpy as np
import torch
import torch.nn as nn

from data_loader import EmptySplitError, load_persisted_label_map, load_splits
from models_torch import MLP
from reporting import plot_corr_matrix, plot_history, predict_proba_torch, save_metrics_and_plots
from train_utils import (
    artifacts_root,
    fit_label_encoder,
    get_device,
    now_run_id,
    save_json,
    save_label_encoder,
    save_scaler_stats,
    set_seed,
    standardize_apply,
    standardize_fit,
    validate_persisted_label_map,
)


def make_loader(X: np.ndarray, y: np.ndarray, batch_size: int, shuffle: bool):
    ds = torch.utils.data.TensorDataset(torch.from_numpy(X), torch.from_numpy(y))
    return torch.utils.data.DataLoader(ds, batch_size=batch_size, shuffle=shuffle, num_workers=0, pin_memory=True)


def run_one(split_mode: str, fold: int | None, out_dir, args) -> dict:
    tr, va, te = load_splits(
        split_mode=split_mode,
        dataset="UGR16",
        pipeline="binary",
        fold=fold,
        sample_frac=args.sample_frac,
        seed=args.seed,
    )

    le = fit_label_encoder(tr.y)
    validate_persisted_label_map(
        load_persisted_label_map(split_mode=split_mode, dataset="UGR16", pipeline="binary", fold=fold),
        le,
        context=f"UGR16 binary split_mode={split_mode} fold={fold}",
    )
    ytr = le.transform(tr.y.astype(str)).astype(np.int64)
    yva = le.transform(va.y.astype(str)).astype(np.int64)
    yte = le.transform(te.y.astype(str)).astype(np.int64)

    Xtr = tr.X.astype(np.float32)
    Xva = va.X.astype(np.float32)
    Xte = te.X.astype(np.float32)

    Xtr, mean, std = standardize_fit(Xtr)
    Xva = standardize_apply(Xva, mean, std)
    Xte = standardize_apply(Xte, mean, std)

    device = get_device()
    model = MLP(
        in_features=Xtr.shape[1],
        n_classes=len(le.classes_),
        hidden=args.hidden,
        depth=args.depth,
        dropout=args.dropout,
    ).to(device)

    crit = nn.CrossEntropyLoss()
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)

    tr_loader = make_loader(Xtr, ytr, args.batch_size, shuffle=True)
    va_loader = make_loader(Xva, yva, args.batch_size, shuffle=False)

    best_state = None
    best_loss = float("inf")
    best_epoch = 0
    bad = 0
    history = []

    for epoch in range(1, args.epochs + 1):
        model.train()
        tot = 0.0
        n = 0
        c = 0
        for xb, yb in tr_loader:
            xb = xb.to(device, non_blocking=True)
            yb = yb.to(device, non_blocking=True)
            xb = torch.nan_to_num(xb, nan=0.0, posinf=0.0, neginf=0.0)

            opt.zero_grad(set_to_none=True)
            logits = model(xb)
            loss = crit(logits, yb)
            loss.backward()
            if args.grad_clip_norm > 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), args.grad_clip_norm)
            opt.step()

            bs = xb.shape[0]
            tot += float(loss.item()) * bs
            n += bs
            c += int((logits.argmax(dim=1) == yb).sum().item())

        train_loss = tot / max(n, 1)
        train_acc = c / max(n, 1)

        model.eval()
        vtot = 0.0
        vn = 0
        vc = 0
        with torch.no_grad():
            for xb, yb in va_loader:
                xb = xb.to(device, non_blocking=True)
                yb = yb.to(device, non_blocking=True)
                xb = torch.nan_to_num(xb, nan=0.0, posinf=0.0, neginf=0.0)
                logits = model(xb)
                vloss = crit(logits, yb)
                bs = xb.shape[0]
                vtot += float(vloss.item()) * bs
                vn += bs
                vc += int((logits.argmax(dim=1) == yb).sum().item())

        val_loss = vtot / max(vn, 1)
        val_acc = vc / max(vn, 1)
        history.append({"epoch": epoch, "train_loss": train_loss, "train_acc": train_acc, "val_loss": val_loss, "val_acc": val_acc})

        if val_loss < (best_loss - args.min_delta):
            best_loss = val_loss
            best_epoch = epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            bad = 0
        else:
            bad += 1

        if bad >= args.patience:
            break

    if best_state is not None:
        model.load_state_dict(best_state)

    p_tr = predict_proba_torch(model, Xtr, device, batch_size=args.batch_size)
    p_va = predict_proba_torch(model, Xva, device, batch_size=args.batch_size)
    p_te = predict_proba_torch(model, Xte, device, batch_size=args.batch_size)

    m_tr = save_metrics_and_plots(out_dir, "train", ytr, p_tr, le.classes_, make_roc_and_calibration=False)
    m_va = save_metrics_and_plots(out_dir, "val", yva, p_va, le.classes_, make_roc_and_calibration=False)
    m_te = save_metrics_and_plots(out_dir, "test", yte, p_te, le.classes_, make_roc_and_calibration=True)
    plot_corr_matrix(Xtr, out_dir / "plots" / "corr_matrix.png")

    import pandas as pd

    pd.DataFrame(history).to_csv(out_dir / "history.csv", index=False)
    plot_history(out_dir / "history.csv", out_dir / "plots")

    torch.save(model.state_dict(), out_dir / "best_model.pt")
    save_label_encoder(out_dir, le)
    save_scaler_stats(out_dir, mean, std)

    return {"best_epoch": best_epoch, "train": m_tr, "val": m_va, "test": m_te}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)
    ap.add_argument("--n_folds", type=int, default=8)
    ap.add_argument("--sample_frac", type=float, default=None)
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--batch_size", type=int, default=8192)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--weight_decay", type=float, default=1e-4)
    ap.add_argument("--patience", type=int, default=7)
    ap.add_argument("--min_delta", type=float, default=0.0)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--hidden", type=int, default=512)
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--dropout", type=float, default=0.2)
    ap.add_argument("--grad_clip_norm", type=float, default=1.0)
    args = ap.parse_args()

    set_seed(args.seed)

    model_name = "offline_UGR16_binary_mlp"
    run_id = now_run_id()
    root = artifacts_root(model_name, args.split_mode, run_id)

    if args.split_mode != "groupkfold":
        try:
            out = run_one(args.split_mode, None, root, args)
        except (FileNotFoundError, EmptySplitError) as e:
            raise SystemExit(
                "UGR16 binary split is missing or empty. "
                "Ensure preprocessing completed and produced train, val, and test rows. "
                f"Details: {e}"
            )
        save_json(root / "results.json", {"best_epoch": out["best_epoch"], "test": out["test"]})
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
            out = run_one("groupkfold", f, fold_dir, args)
        except (FileNotFoundError, EmptySplitError) as e:
            print(f"[skip] fold_{f}: {e}")
            summary[f"fold_{f}"] = {"skipped": True, "reason": str(e)}
            continue
        save_json(fold_dir / "results.json", {"best_epoch": out["best_epoch"], "test": out["test"]})
        summary[f"fold_{f}"] = {"best_epoch": out["best_epoch"], "test": out["test"]}

    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()
