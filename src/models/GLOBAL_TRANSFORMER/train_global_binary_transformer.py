#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, f1_score, log_loss, precision_recall_curve, recall_score, roc_auc_score, auc
from torch.utils.data import DataLoader, TensorDataset

from data_loader import GlobalSplit, load_splits
from global_schema import resolve_from_root
from models import GlobalFTTransformer


PROFILE_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "fast": {"epochs": 12, "d_model": 96, "n_layers": 2, "n_heads": 4, "dropout": 0.25, "batch_size": 4096, "patience": 4},
    "balanced": {"epochs": 35, "d_model": 128, "n_layers": 3, "n_heads": 4, "dropout": 0.25, "batch_size": 4096, "patience": 7},
    "conservative": {"epochs": 60, "d_model": 128, "n_layers": 3, "n_heads": 4, "dropout": 0.35, "batch_size": 4096, "patience": 10},
}


def now_run_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.localtime())


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def set_seed(seed: int) -> None:
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def fit_standardizer(split: GlobalSplit) -> tuple[np.ndarray, np.ndarray]:
    mean = split.features.mean(axis=0).astype(np.float32)
    std = split.features.std(axis=0).astype(np.float32)
    std[std < 1e-6] = 1.0
    return mean, std


def apply_standardizer(split: GlobalSplit, mean: np.ndarray, std: np.ndarray) -> GlobalSplit:
    features = ((split.features - mean) / std).astype(np.float32, copy=False)
    np.nan_to_num(features, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return GlobalSplit(features, split.target, split.dataset_id, split.dataset_name, split.feature_names)


def make_loader(split: GlobalSplit, batch_size: int, shuffle: bool) -> DataLoader:
    dataset = TensorDataset(
        torch.from_numpy(split.features.astype(np.float32, copy=False)),
        torch.from_numpy(split.dataset_id.astype(np.int64, copy=False)),
        torch.from_numpy(split.target.astype(np.int64, copy=False)),
    )
    return DataLoader(dataset, batch_size=batch_size, shuffle=shuffle, pin_memory=torch.cuda.is_available())


def predict_proba(model: nn.Module, split: GlobalSplit, device: torch.device, batch_size: int) -> np.ndarray:
    model.eval()
    probabilities: List[np.ndarray] = []
    loader = make_loader(split, batch_size=batch_size, shuffle=False)
    with torch.no_grad():
        for features, dataset_id, _ in loader:
            logits = model(features.to(device), dataset_id.to(device))
            probs = torch.softmax(logits, dim=1).detach().cpu().numpy()
            probabilities.append(probs)
    return np.concatenate(probabilities, axis=0) if probabilities else np.empty((0, 2), dtype=np.float32)


def pr_auc_score(y_true: np.ndarray, y_score: np.ndarray) -> float | None:
    if len(np.unique(y_true)) < 2:
        return None
    precision, recall, _ = precision_recall_curve(y_true, y_score)
    return float(auc(recall, precision))


def expected_calibration_error(y_true: np.ndarray, proba: np.ndarray, n_bins: int = 15) -> float:
    confidences = np.max(proba, axis=1)
    predictions = np.argmax(proba, axis=1)
    correct = (predictions == y_true).astype(np.float32)
    ece = 0.0
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    for start, stop in zip(bins[:-1], bins[1:]):
        mask = (confidences > start) & (confidences <= stop)
        if not np.any(mask):
            continue
        ece += float(np.abs(correct[mask].mean() - confidences[mask].mean()) * mask.mean())
    return float(ece)


def classification_metrics(split: GlobalSplit, proba: np.ndarray) -> Dict[str, Any]:
    y_true = split.target
    y_pred = np.argmax(proba, axis=1)
    metrics: Dict[str, Any] = {
        "rows": int(len(y_true)),
        "attack_rows": int(np.sum(y_true == 1)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "logloss": None,
        "roc_auc": None,
        "pr_auc": None,
        "ece": expected_calibration_error(y_true, proba),
    }
    try:
        metrics["logloss"] = float(log_loss(y_true, proba, labels=[0, 1]))
    except ValueError:
        metrics["logloss"] = None
    if len(np.unique(y_true)) >= 2:
        metrics["roc_auc"] = float(roc_auc_score(y_true, proba[:, 1]))
        metrics["pr_auc"] = pr_auc_score(y_true, proba[:, 1])
    return metrics


def metrics_by_dataset(split: GlobalSplit, proba: np.ndarray) -> Dict[str, Dict[str, Any]]:
    output: Dict[str, Dict[str, Any]] = {}
    for dataset_name in sorted(set(split.dataset_name.astype(str))):
        mask = split.dataset_name.astype(str) == dataset_name
        subset = GlobalSplit(split.features[mask], split.target[mask], split.dataset_id[mask], split.dataset_name[mask], split.feature_names)
        output[dataset_name] = classification_metrics(subset, proba[mask])
    return output


def train_epoch(model: nn.Module, loader: DataLoader, criterion: nn.Module, optimizer: torch.optim.Optimizer, device: torch.device) -> float:
    model.train()
    total_loss = 0.0
    total_rows = 0
    for features, dataset_id, target in loader:
        features = features.to(device)
        dataset_id = dataset_id.to(device)
        target = target.to(device)
        optimizer.zero_grad(set_to_none=True)
        logits = model(features, dataset_id)
        loss = criterion(logits, target)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=2.0)
        optimizer.step()
        total_loss += float(loss.detach().cpu()) * len(target)
        total_rows += len(target)
    return total_loss / max(1, total_rows)


def class_weights(target: np.ndarray, device: torch.device) -> torch.Tensor:
    counts = np.bincount(target, minlength=2).astype(np.float32)
    counts[counts == 0.0] = 1.0
    weights = counts.sum() / (2.0 * counts)
    return torch.tensor(weights, dtype=torch.float32, device=device)


def parse_dataset_filter(values: Iterable[str] | None) -> list[str] | None:
    if not values:
        return None
    output: list[str] = []
    for value in values:
        output.extend([item.strip() for item in str(value).split(",") if item.strip()])
    return output or None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train GLOBAL_BINARY_V1 FTTransformer.")
    parser.add_argument("--dataset_root", default="src/models/GLOBAL_TRANSFORMER/datasets/GLOBAL_BINARY_V1")
    parser.add_argument("--artifact_root", default="src/models/GLOBAL_TRANSFORMER/artifacts")
    parser.add_argument("--version", default="GLOBAL_BINARY_V1")
    parser.add_argument("--profile", default="balanced", choices=sorted(PROFILE_DEFAULTS))
    parser.add_argument("--include_datasets", nargs="*", default=None)
    parser.add_argument("--exclude_datasets", nargs="*", default=None)
    parser.add_argument("--holdout_dataset", default=None)
    parser.add_argument("--run_id", default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=None)
    parser.add_argument("--batch_size", type=int, default=None)
    parser.add_argument("--d_model", type=int, default=None)
    parser.add_argument("--n_layers", type=int, default=None)
    parser.add_argument("--n_heads", type=int, default=None)
    parser.add_argument("--dropout", type=float, default=None)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--weight_decay", type=float, default=1e-4)
    parser.add_argument("--patience", type=int, default=None)
    parser.add_argument("--class_weight", default="balanced", choices=["none", "balanced"])
    parser.add_argument("--disable_dataset_embedding", action="store_true")
    parser.add_argument("--dry_run", action="store_true")
    return parser.parse_args()


def apply_profile(args: argparse.Namespace) -> argparse.Namespace:
    defaults = PROFILE_DEFAULTS[args.profile]
    for key, value in defaults.items():
        if getattr(args, key) is None:
            setattr(args, key, value)
    return args


def main() -> None:
    args = apply_profile(parse_args())
    set_seed(args.seed)
    include_datasets = parse_dataset_filter(args.include_datasets)
    exclude_datasets = parse_dataset_filter(args.exclude_datasets)
    if args.holdout_dataset:
        exclude_datasets = sorted(set((exclude_datasets or []) + [args.holdout_dataset]))
        test_include_datasets = [args.holdout_dataset]
    else:
        test_include_datasets = include_datasets

    train_split, val_split, _ = load_splits(args.dataset_root, include_datasets=include_datasets, exclude_datasets=exclude_datasets)
    test_split = load_splits(args.dataset_root, include_datasets=test_include_datasets, exclude_datasets=None)[2]
    mean, std = fit_standardizer(train_split)
    train_split = apply_standardizer(train_split, mean, std)
    val_split = apply_standardizer(val_split, mean, std)
    test_split = apply_standardizer(test_split, mean, std)

    n_features = train_split.features.shape[1]
    n_datasets = int(max(train_split.dataset_id.max(), val_split.dataset_id.max(), test_split.dataset_id.max())) + 1
    run_id = args.run_id or now_run_id()
    run_name = "global_fttransformer_binary"
    if args.holdout_dataset:
        run_name += f"_holdout_{args.holdout_dataset}"
    elif args.disable_dataset_embedding:
        run_name += "_no_dataset_embedding"
    artifact_dir = resolve_from_root(args.artifact_root) / run_name / args.version / run_id
    if args.dry_run:
        print(json.dumps({"args": vars(args), "n_features": n_features, "n_datasets": n_datasets, "artifact_dir": str(artifact_dir)}, indent=2))
        return

    artifact_dir.mkdir(parents=True, exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = GlobalFTTransformer(
        n_features=n_features,
        n_datasets=n_datasets,
        d_model=args.d_model,
        n_layers=args.n_layers,
        n_heads=args.n_heads,
        dropout=args.dropout,
        use_dataset_embedding=not args.disable_dataset_embedding,
    ).to(device)
    criterion = nn.CrossEntropyLoss(weight=class_weights(train_split.target, device) if args.class_weight == "balanced" else None)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    train_loader = make_loader(train_split, batch_size=args.batch_size, shuffle=True)

    best_macro_f1 = -math.inf
    best_state = None
    best_epoch = 0
    patience_left = args.patience
    history: List[Dict[str, Any]] = []

    for epoch in range(1, args.epochs + 1):
        train_loss = train_epoch(model, train_loader, criterion, optimizer, device)
        val_proba = predict_proba(model, val_split, device, args.batch_size)
        val_metrics = classification_metrics(val_split, val_proba)
        history.append({"epoch": epoch, "train_loss": train_loss, **{f"val_{k}": v for k, v in val_metrics.items() if isinstance(v, (int, float))}})
        print(f"epoch={epoch} train_loss={train_loss:.6f} val_macro_f1={val_metrics['macro_f1']:.6f} val_roc_auc={val_metrics['roc_auc']}")
        if val_metrics["macro_f1"] > best_macro_f1:
            best_macro_f1 = float(val_metrics["macro_f1"])
            best_epoch = epoch
            best_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
            patience_left = args.patience
        else:
            patience_left -= 1
            if patience_left <= 0:
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    train_proba = predict_proba(model, train_split, device, args.batch_size)
    val_proba = predict_proba(model, val_split, device, args.batch_size)
    test_proba = predict_proba(model, test_split, device, args.batch_size)
    results = {
        "version": args.version,
        "profile": args.profile,
        "best_epoch": best_epoch,
        "device": str(device),
        "args": vars(args),
        "train": classification_metrics(train_split, train_proba),
        "val": classification_metrics(val_split, val_proba),
        "test": classification_metrics(test_split, test_proba),
        "test_by_dataset": metrics_by_dataset(test_split, test_proba),
    }
    torch.save(model.state_dict(), artifact_dir / "model.pt")
    np.savez(artifact_dir / "standardizer.npz", mean=mean, std=std)
    write_json(artifact_dir / "history.json", history)
    write_json(artifact_dir / "results.json", results)
    print("Saved:", artifact_dir)


if __name__ == "__main__":
    main()