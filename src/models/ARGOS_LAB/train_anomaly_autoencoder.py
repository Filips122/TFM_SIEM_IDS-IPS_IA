#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep autoencoder anomaly detection on ARGOS-LAB windows.

The autoencoder is fitted only to reconstruct routine traffic; per-window
reconstruction error becomes the anomaly score. Labels are never seen during
fitting, only when scoring the resulting ranking.

Compared with the Isolation Forest baseline this model can capture correlations
between features (for example: high alert_count is normal for the scanner agent
but not for a web host), which axis-aligned tree splits approximate poorly.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from data_loader import EmptySplitError, load_splits
from metrics import evaluate_anomaly_both_directions
from models_torch import TabularAutoencoder
from reporting import plot_history, save_anomaly_plots
from train_utils import (
    artifacts_root,
    get_device,
    now_run_id,
    run_header,
    save_json,
    save_scaler_stats,
    set_seed,
    standardize_apply,
    standardize_fit,
)


@torch.no_grad()
def reconstruction_scores(model: TabularAutoencoder, X: np.ndarray, device, batch_size: int) -> np.ndarray:
    model.eval()
    out = []
    for start in range(0, len(X), batch_size):
        batch = torch.from_numpy(X[start : start + batch_size]).to(device)
        batch = torch.nan_to_num(batch, nan=0.0, posinf=0.0, neginf=0.0)
        out.append(((model(batch) - batch) ** 2).mean(dim=1).cpu().numpy())
    return np.concatenate(out) if out else np.zeros(0, dtype=np.float32)


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

    # Clip standardized features: a handful of windows hold 5,470 alerts and
    # their squared error would otherwise dominate the whole training signal.
    for matrix in (Xtr, Xva, Xte):
        np.clip(matrix, -args.clip, args.clip, out=matrix)

    device = get_device()
    print(f"  fit={len(Xtr):,} (policy={args.train_policy})  val={len(Xva):,}  test={len(Xte):,}  "
          f"features={Xtr.shape[1]}  device={device}")

    # Hold out a slice of the fitting set purely to early-stop on reconstruction
    # loss; no label is involved.
    rng = np.random.default_rng(args.seed)
    order = rng.permutation(len(Xtr))
    cut = max(1, int(len(order) * (1.0 - args.val_fraction)))
    fit_idx, holdout_idx = order[:cut], order[cut:]
    X_fit, X_hold = Xtr[fit_idx], Xtr[holdout_idx]

    model = TabularAutoencoder(Xtr.shape[1], latent=args.latent, hidden=args.hidden, dropout=args.dropout).to(device)
    criterion = nn.MSELoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)

    fit_loader = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(torch.from_numpy(X_fit)),
        batch_size=args.batch_size, shuffle=True, num_workers=0, pin_memory=True, drop_last=True,
    )

    best_state, best_loss, best_epoch, bad = None, float("inf"), 0, 0
    history = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        total, seen = 0.0, 0
        for (xb,) in fit_loader:
            xb = torch.nan_to_num(xb.to(device, non_blocking=True), nan=0.0, posinf=0.0, neginf=0.0)
            optimizer.zero_grad(set_to_none=True)
            loss = criterion(model(xb), xb)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total += float(loss.item()) * xb.shape[0]
            seen += xb.shape[0]
        train_loss = total / max(seen, 1)
        hold_loss = float(reconstruction_scores(model, X_hold, device, args.batch_size).mean()) if len(X_hold) else train_loss
        history.append({"epoch": epoch, "train_loss": train_loss, "val_loss": hold_loss})

        if hold_loss < best_loss - args.min_delta:
            best_loss, best_epoch, bad = hold_loss, epoch, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
        if epoch % max(1, args.epochs // 10) == 0 or epoch == 1:
            print(f"    epoch {epoch:>3}  train_loss={train_loss:.5f}  holdout_loss={hold_loss:.5f}", flush=True)
        if bad >= args.patience:
            print(f"    early stop at epoch {epoch} (best {best_epoch}, loss={best_loss:.5f})")
            break

    if best_state is not None:
        model.load_state_dict(best_state)

    val_scores = reconstruction_scores(model, Xva, device, args.batch_size)
    test_scores = reconstruction_scores(model, Xte, device, args.batch_size)
    val_report = evaluate_anomaly_both_directions(val.y, val_scores)
    test_report = evaluate_anomaly_both_directions(test.y, test_scores)
    save_anomaly_plots(out_dir, "val", val.y, val_scores)
    save_anomaly_plots(out_dir, "test", test.y, test_scores)

    pd.DataFrame(history).to_csv(out_dir / "history.csv", index=False)
    plot_history(out_dir / "history.csv", out_dir / "plots")
    torch.save(model.state_dict(), out_dir / "best_model.pt")
    save_scaler_stats(out_dir, mean, std)
    np.save(out_dir / "test_scores.npy", test_scores)
    return {"best_epoch": best_epoch, "val": val_report, "test": test_report}


def summarize(tag: str, report: dict) -> None:
    attack, rare = report["test"]["attack"], report["test"]["rare"]
    print(f"  [{tag}] ATTACK-direction roc_auc={attack['roc_auc']:.4f}")
    print(f"  {'':<{len(tag) + 4}} rare-class '{rare.get('positive_label', 'ATTACK')}' "
          f"(prevalence {rare['pr_auc_baseline']:.4f}): roc_auc={rare['roc_auc']:.4f}  "
          f"pr_auc={rare['pr_auc']:.4f} (lift {rare['pr_auc_lift']:.2f}x)  "
          f"P@1%={rare['precision_at_1pct']:.4f}  P@5%={rare['precision_at_5pct']:.4f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Deep autoencoder anomaly detection on ARGOS-LAB windows")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    parser.add_argument("--dataset", default="ARGOS-LAB")
    parser.add_argument("--feature_set", default="behavioral", choices=["full", "nosignature", "behavioral"])
    parser.add_argument("--train_policy", default="quiet", choices=["quiet", "benign", "all"])
    parser.add_argument("--exclude_posture_windows", action="store_true")
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--n_folds", type=int, default=4)
    parser.add_argument("--epochs", type=int, default=80)
    parser.add_argument("--batch_size", type=int, default=512)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--weight_decay", type=float, default=1e-5)
    parser.add_argument("--latent", type=int, default=12)
    parser.add_argument("--hidden", type=int, default=96)
    parser.add_argument("--dropout", type=float, default=0.1)
    parser.add_argument("--clip", type=float, default=8.0, help="clip standardized features to +/- this many sigmas")
    parser.add_argument("--val_fraction", type=float, default=0.15)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--min_delta", type=float, default=1e-6)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    set_seed(args.seed)
    root = artifacts_root("dl_anomaly_autoencoder", args.split_mode,
                          f"{args.dataset}__{args.feature_set}__{args.train_policy}", now_run_id())
    run_header(
        "train_anomaly_autoencoder (ARGOS-LAB)",
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
