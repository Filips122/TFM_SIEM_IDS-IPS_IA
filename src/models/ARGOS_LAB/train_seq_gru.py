#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GRU classifier over per-agent ARGOS-LAB window sequences.

Run prepare_sequence_dataset.py first. The model reads the last N windows of an
agent and classifies the final one, so its input is the shape of an activity
burst over time rather than a single snapshot.

Standardization statistics are computed on the training sequences only and then
applied to val/test, so no test-set information reaches the scaler.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import f1_score

from models_torch import GRUSequenceClassifier
from reporting import best_threshold, plot_history, save_metrics_and_plots
from train_utils import (
    align_labels,
    artifacts_root,
    class_weights,
    fit_label_encoder,
    get_device,
    now_run_id,
    resolve_from_root,
    run_header,
    save_json,
    save_label_encoder,
    set_seed,
)


def load_sequences(root: Path, split: str) -> tuple[np.ndarray, np.ndarray]:
    X_path, y_path = root / f"X_{split}.npy", root / f"y_{split}.npy"
    if not X_path.exists():
        raise SystemExit(f"Missing {X_path}. Run prepare_sequence_dataset.py first.")
    return np.load(X_path).astype(np.float32), np.load(y_path, allow_pickle=True)


def standardize_sequences(Xtr: np.ndarray, *others: np.ndarray):
    """Per-feature statistics pooled over batch and time, fitted on train."""
    flat = Xtr.reshape(-1, Xtr.shape[-1])
    mean = flat.mean(axis=0)
    std = flat.std(axis=0)
    std[std < 1e-6] = 1.0
    scale = lambda X: ((X - mean) / std).astype(np.float32)
    return scale(Xtr), [scale(X) for X in others], mean, std


@torch.no_grad()
def predict_proba(model, X: np.ndarray, device, batch_size: int) -> np.ndarray:
    model.eval()
    out = []
    for start in range(0, len(X), batch_size):
        batch = torch.from_numpy(X[start : start + batch_size]).to(device)
        batch = torch.nan_to_num(batch, nan=0.0, posinf=0.0, neginf=0.0)
        out.append(torch.softmax(model(batch), dim=1).cpu().numpy())
    return np.concatenate(out) if out else np.zeros((0, 2), dtype=np.float32)


def main() -> None:
    parser = argparse.ArgumentParser(description="GRU sequence classifier for ARGOS-LAB")
    parser.add_argument("--seq_dir", default=None, help="sequence folder from prepare_sequence_dataset.py")
    parser.add_argument("--split_mode", default="date", choices=["date", "groupkfold"])
    parser.add_argument("--dataset", default="ARGOS-LAB")
    parser.add_argument("--pipeline", default="binary", choices=["binary", "multiclass", "taxonomy"])
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--feature_set", default="behavioral", choices=["full", "nosignature", "behavioral"])
    parser.add_argument("--seq_len", type=int, default=12)
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--batch_size", type=int, default=512)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--weight_decay", type=float, default=1e-4)
    parser.add_argument("--hidden", type=int, default=128)
    parser.add_argument("--layers", type=int, default=1)
    parser.add_argument("--dropout", type=float, default=0.2)
    parser.add_argument("--bidirectional", action="store_true")
    parser.add_argument("--patience", type=int, default=8)
    parser.add_argument("--min_delta", type=float, default=1e-4)
    parser.add_argument("--grad_clip_norm", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--class_weight", action="store_true", default=True)
    parser.add_argument("--no_class_weight", dest="class_weight", action="store_false")
    args = parser.parse_args()

    set_seed(args.seed)
    if args.seq_dir:
        seq_root = resolve_from_root(args.seq_dir)
    else:
        base = resolve_from_root("src/models/ARGOS_LAB/datasets") / args.split_mode / args.dataset
        if args.split_mode == "groupkfold":
            base = base / f"fold_{args.fold if args.fold is not None else 0}"
        seq_root = base / "sequences" / f"{args.pipeline}__{args.feature_set}__L{args.seq_len}"

    root = artifacts_root("dl_seq_gru", args.split_mode, f"{args.dataset}__{args.feature_set}__L{args.seq_len}", now_run_id())
    run_header(
        "train_seq_gru (ARGOS-LAB)",
        dataset=args.dataset, pipeline=args.pipeline, feature_set=args.feature_set,
        seq_len=args.seq_len, sequences=seq_root, out=root,
    )

    Xtr, ytr = load_sequences(seq_root, "train")
    Xva, yva = load_sequences(seq_root, "val")
    Xte, yte = load_sequences(seq_root, "test")
    Xtr, (Xva, Xte), mean, std = standardize_sequences(Xtr, Xva, Xte)

    encoder = fit_label_encoder(ytr)
    ytr_i = align_labels(encoder, ytr).astype(np.int64)
    yva_i = align_labels(encoder, yva).astype(np.int64)
    yte_i = align_labels(encoder, yte).astype(np.int64)
    n_classes = len(encoder.classes_)

    device = get_device()
    print(f"  train={Xtr.shape}  val={Xva.shape}  test={Xte.shape}  "
          f"classes={list(map(str, encoder.classes_))}  device={device}")

    model = GRUSequenceClassifier(
        in_features=Xtr.shape[-1], n_classes=n_classes, hidden=args.hidden,
        layers=args.layers, dropout=args.dropout, bidirectional=args.bidirectional,
    ).to(device)
    weights = class_weights(ytr_i, n_classes) if args.class_weight else np.ones(n_classes, dtype=np.float32)
    criterion = nn.CrossEntropyLoss(weight=torch.from_numpy(weights).to(device))
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)

    loader = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(torch.from_numpy(Xtr), torch.from_numpy(ytr_i)),
        batch_size=args.batch_size, shuffle=True, num_workers=0, pin_memory=True,
    )

    best_state, best_score, best_epoch, bad = None, -1.0, 0, 0
    history = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        total, seen, correct = 0.0, 0, 0
        for xb, yb in loader:
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

        p_val = predict_proba(model, Xva, device, args.batch_size)
        val_f1 = float(f1_score(yva_i, p_val.argmax(axis=1), average="macro", zero_division=0))
        history.append({"epoch": epoch, "train_loss": total / max(seen, 1),
                        "train_acc": correct / max(seen, 1), "val_macro_f1": val_f1})

        if val_f1 > best_score + args.min_delta:
            best_score, best_epoch, bad = val_f1, epoch, 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
        if epoch % max(1, args.epochs // 10) == 0 or epoch == 1:
            print(f"    epoch {epoch:>3}  train_loss={history[-1]['train_loss']:.4f}  val_macro_f1={val_f1:.4f}", flush=True)
        if bad >= args.patience:
            print(f"    early stop at epoch {epoch} (best {best_epoch}, macro_f1={best_score:.4f})")
            break

    if best_state is not None:
        model.load_state_dict(best_state)

    p_train = predict_proba(model, Xtr, device, args.batch_size)
    p_val = predict_proba(model, Xva, device, args.batch_size)
    p_test = predict_proba(model, Xte, device, args.batch_size)
    threshold = best_threshold(yva_i, p_val, encoder.classes_) if n_classes == 2 else None

    metrics = {
        "train": save_metrics_and_plots(root, "train", ytr_i, p_train, encoder.classes_, threshold),
        "val": save_metrics_and_plots(root, "val", yva_i, p_val, encoder.classes_, threshold),
        "test": save_metrics_and_plots(root, "test", yte_i, p_test, encoder.classes_, threshold),
    }
    test = metrics["test"]
    print(f"  [seq_gru] balanced_acc={test['balanced_accuracy']:.4f}  macro_f1={test['macro_f1']:.4f}  "
          f"mcc={test.get('mcc', float('nan')):.4f}  roc_auc={test.get('roc_auc') or float('nan'):.4f}")

    pd.DataFrame(history).to_csv(root / "history.csv", index=False)
    plot_history(root / "history.csv", root / "plots")
    torch.save(model.state_dict(), root / "best_model.pt")
    save_label_encoder(root, encoder)
    save_json(root / "scaler.json", {"mean": mean.tolist(), "std": std.tolist()})
    spec_path = seq_root / "sequence_spec.json"
    save_json(root / "results.json", {
        "args": vars(args),
        "sequence_spec": json.loads(spec_path.read_text(encoding="utf-8")) if spec_path.exists() else None,
        "best_epoch": best_epoch, "threshold": threshold,
        "val": metrics["val"], "test": metrics["test"],
    })
    print("Saved:", root)


if __name__ == "__main__":
    main()
