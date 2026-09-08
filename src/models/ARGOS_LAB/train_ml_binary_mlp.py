#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep dense classifier (PyTorch) for ARGOS-LAB windows.

Same three feature regimes as the HGB baseline, so the two are directly
comparable. Trained with inverse-frequency class weights and early stopping on
validation macro-F1 rather than loss, because with a 2% minority class the loss
keeps improving while the model quietly predicts the majority for everything.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import f1_score

from data_loader import EmptySplitError, load_splits
from models_torch import MLP
from reporting import best_threshold, permutation_importance_report, plot_history, predict_proba_torch, save_metrics_and_plots
from train_utils import (
    align_labels,
    artifacts_root,
    class_weights,
    fit_label_encoder,
    get_device,
    now_run_id,
    run_header,
    save_json,
    save_label_encoder,
    save_scaler_stats,
    set_seed,
    standardize_apply,
    standardize_fit,
)


def make_loader(X: np.ndarray, y: np.ndarray, batch_size: int, shuffle: bool):
    dataset = torch.utils.data.TensorDataset(torch.from_numpy(X), torch.from_numpy(y))
    return torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=shuffle, num_workers=0, pin_memory=True)


def run_one(split_mode: str, fold: int | None, out_dir: Path, args) -> dict:
    train, val, test = load_splits(
        split_mode=split_mode,
        dataset=args.dataset,
        pipeline=args.pipeline,
        fold=fold,
        feature_set=args.feature_set,
        sample_frac=args.sample_frac,
        seed=args.seed,
        exclude_posture_windows=args.exclude_posture_windows,
    )
    encoder = fit_label_encoder(train.y)
    y_train = align_labels(encoder, train.y).astype(np.int64)
    y_val = align_labels(encoder, val.y).astype(np.int64)
    y_test = align_labels(encoder, test.y).astype(np.int64)
    n_classes = len(encoder.classes_)

    Xtr, mean, std = standardize_fit(train.X.astype(np.float32))
    Xva = standardize_apply(val.X.astype(np.float32), mean, std)
    Xte = standardize_apply(test.X.astype(np.float32), mean, std)

    device = get_device()
    print(f"  train={len(Xtr):,}  val={len(Xva):,}  test={len(Xte):,}  "
          f"features={Xtr.shape[1]}  classes={list(map(str, encoder.classes_))}  device={device}")

    model = MLP(Xtr.shape[1], n_classes, hidden=args.hidden, depth=args.depth, dropout=args.dropout).to(device)
    weights = class_weights(y_train, n_classes) if args.class_weight else np.ones(n_classes, dtype=np.float32)
    criterion = nn.CrossEntropyLoss(weight=torch.from_numpy(weights).to(device))
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="max", factor=0.5, patience=max(1, args.patience // 2))

    train_loader = make_loader(Xtr, y_train, args.batch_size, shuffle=True)
    val_loader = make_loader(Xva, y_val, args.batch_size, shuffle=False)

    best_state, best_score, best_epoch, bad = None, -1.0, 0, 0
    history = []

    for epoch in range(1, args.epochs + 1):
        model.train()
        total, seen, correct = 0.0, 0, 0
        for xb, yb in train_loader:
            xb = torch.nan_to_num(xb.to(device, non_blocking=True), nan=0.0, posinf=0.0, neginf=0.0)
            yb = yb.to(device, non_blocking=True)
            optimizer.zero_grad(set_to_none=True)
            logits = model(xb)
            loss = criterion(logits, yb)
            loss.backward()
            if args.grad_clip_norm > 0:
                nn.utils.clip_grad_norm_(model.parameters(), args.grad_clip_norm)
            optimizer.step()
            total += float(loss.item()) * xb.shape[0]
            seen += xb.shape[0]
            correct += int((logits.argmax(dim=1) == yb).sum().item())

        model.eval()
        vtotal, vseen, predictions = 0.0, 0, []
        with torch.no_grad():
            for xb, yb in val_loader:
                xb = torch.nan_to_num(xb.to(device, non_blocking=True), nan=0.0, posinf=0.0, neginf=0.0)
                yb = yb.to(device, non_blocking=True)
                logits = model(xb)
                vtotal += float(criterion(logits, yb).item()) * xb.shape[0]
                vseen += xb.shape[0]
                predictions.append(logits.argmax(dim=1).cpu().numpy())
        val_pred = np.concatenate(predictions) if predictions else np.zeros(0, dtype=int)
        val_f1 = float(f1_score(y_val, val_pred, average="macro", zero_division=0))

        history.append({
            "epoch": epoch,
            "train_loss": total / max(seen, 1),
            "train_acc": correct / max(seen, 1),
            "val_loss": vtotal / max(vseen, 1),
            "val_macro_f1": val_f1,
        })
        scheduler.step(val_f1)

        # Selection on macro-F1: with a 2% minority class, val_loss can keep
        # falling while the model collapses onto the majority class.
        if val_f1 > best_score + args.min_delta:
            best_score, best_epoch, bad = val_f1, epoch, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
        if epoch % max(1, args.epochs // 10) == 0 or epoch == 1:
            print(f"    epoch {epoch:>3}  train_loss={history[-1]['train_loss']:.4f}  "
                  f"val_loss={history[-1]['val_loss']:.4f}  val_macro_f1={val_f1:.4f}", flush=True)
        if bad >= args.patience:
            print(f"    early stop at epoch {epoch} (best {best_epoch}, macro_f1={best_score:.4f})")
            break

    if best_state is not None:
        model.load_state_dict(best_state)

    p_train = predict_proba_torch(model, Xtr, device, args.batch_size)
    p_val = predict_proba_torch(model, Xva, device, args.batch_size)
    p_test = predict_proba_torch(model, Xte, device, args.batch_size)
    threshold = best_threshold(y_val, p_val, encoder.classes_) if n_classes == 2 else None
    posture = {name: (split.meta["posture_ratio"].to_numpy() if "posture_ratio" in split.meta else None)
               for name, split in (("train", train), ("val", val), ("test", test))}

    metrics = {
        "train": save_metrics_and_plots(out_dir, "train", y_train, p_train, encoder.classes_, threshold, posture["train"]),
        "val": save_metrics_and_plots(out_dir, "val", y_val, p_val, encoder.classes_, threshold, posture["val"]),
        "test": save_metrics_and_plots(out_dir, "test", y_test, p_test, encoder.classes_, threshold, posture["test"]),
    }

    pd.DataFrame(history).to_csv(out_dir / "history.csv", index=False)
    plot_history(out_dir / "history.csv", out_dir / "plots")
    if args.importance:
        print("  computing permutation importance ...", flush=True)
        permutation_importance_report(
            lambda matrix: predict_proba_torch(model, matrix, device, args.batch_size),
            Xte, y_test, test.feature_names, out_dir, encoder.classes_,
            n_repeats=args.importance_repeats, seed=args.seed,
        )

    torch.save(model.state_dict(), out_dir / "best_model.pt")
    save_label_encoder(out_dir, encoder)
    save_scaler_stats(out_dir, mean, std)
    save_json(out_dir / "feature_names.json", {"feature_set": args.feature_set, "features": train.feature_names})
    return {"best_epoch": best_epoch, "threshold": threshold, **metrics}


def summarize(tag: str, metrics: dict) -> None:
    test = metrics["test"]
    print(f"  [{tag}] balanced_acc={test['balanced_accuracy']:.4f}  macro_f1={test['macro_f1']:.4f}  "
          f"mcc={test.get('mcc', float('nan')):.4f}  roc_auc={test.get('roc_auc') or float('nan'):.4f}  "
          f"pr_auc_minority={test.get('pr_auc_minority') or float('nan'):.4f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="PyTorch MLP on ARGOS-LAB windows")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    parser.add_argument("--dataset", default="ARGOS-LAB")
    parser.add_argument("--pipeline", default="binary", choices=["binary", "multiclass", "taxonomy"])
    parser.add_argument("--feature_set", default="behavioral", choices=["full", "nosignature", "behavioral"])
    parser.add_argument("--exclude_posture_windows", action="store_true")
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--n_folds", type=int, default=4)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--batch_size", type=int, default=1024)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--weight_decay", type=float, default=1e-4)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--min_delta", type=float, default=1e-4)
    parser.add_argument("--hidden", type=int, default=256)
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--dropout", type=float, default=0.3)
    parser.add_argument("--grad_clip_norm", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--class_weight", action="store_true", default=True)
    parser.add_argument("--no_class_weight", dest="class_weight", action="store_false")
    parser.add_argument("--importance", action="store_true", default=False)
    parser.add_argument("--importance_repeats", type=int, default=2)
    args = parser.parse_args()

    set_seed(args.seed)
    model_name = f"dl_{args.pipeline}_mlp"
    root = artifacts_root(model_name, args.split_mode, f"{args.dataset}__{args.feature_set}", now_run_id())
    run_header(
        f"train_ml_{args.pipeline}_mlp (ARGOS-LAB)",
        dataset=args.dataset, split_mode=args.split_mode, feature_set=args.feature_set, out=root,
    )

    if args.split_mode != "groupkfold":
        try:
            out = run_one(args.split_mode, None, root, args)
        except (FileNotFoundError, EmptySplitError) as exc:
            raise SystemExit(f"{args.dataset} {args.pipeline} split is missing or empty: {exc}")
        summarize(args.feature_set, out)
        save_json(root / "results.json", {"args": vars(args), "best_epoch": out["best_epoch"],
                                          "threshold": out["threshold"], "val": out["val"], "test": out["test"]})
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
        except (FileNotFoundError, EmptySplitError, SystemExit) as exc:
            print(f"  [skip] {exc}")
            summary[f"fold_{fold}"] = {"skipped": True, "reason": str(exc)}
            continue
        summarize(f"fold_{fold}", out)
        save_json(fold_dir / "results.json", {"best_epoch": out["best_epoch"], "test": out["test"]})
        summary[f"fold_{fold}"] = {"best_epoch": out["best_epoch"], "test": out["test"]}
    save_json(root / "summary.json", {"args": vars(args), "folds": summary})
    print("Saved:", root)


if __name__ == "__main__":
    main()
