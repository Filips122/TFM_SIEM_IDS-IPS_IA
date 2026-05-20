#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from sklearn.preprocessing import LabelEncoder

# Local imports (same folder)
from data_loader import load_splits, load_split
from metrics import evaluate_classification, evaluate_anomaly_scores


# -----------------------------
# Paths / utilities
# -----------------------------
def repo_root() -> Path:
    # <root>/src/models/CIC-IDS2017/train_utils.py
    return Path(__file__).resolve().parents[3]


def resolve_from_root(p: Union[str, Path]) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


def now_run_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def set_seed(seed: int = 42) -> None:
    import random
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    # deterministic=False because performance
    torch.backends.cudnn.benchmark = True


def get_device() -> torch.device:
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def save_json(path: Path, obj: Dict) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def save_run_metadata(root: Path, model_name: str, split_mode: str, run_id: str, dataset: str = "CIC-IDS2017", run_config: Optional[Dict[str, object]] = None) -> None:
    payload: Dict[str, object] = {
        "dataset": dataset,
        "model_name": model_name,
        "split_mode": split_mode,
        "run_id": run_id,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifact_root": str(root),
    }
    if run_config is not None:
        payload["run_config"] = run_config
        if "sample_frac" in run_config:
            payload["sample_frac"] = run_config.get("sample_frac")
    save_json(root / "run_metadata.json", payload)


# -----------------------------
# Standardization (NaN-safe)
# -----------------------------
def _nan_to_num_(X: np.ndarray) -> np.ndarray:
    # in-place where possible; if read-only it will raise (callers should ensure writable)
    return np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)


def standardize_fit(X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    NaN/Inf-safe standardization.
    - Replaces NaN/Inf with 0 before stats.
    - Uses nanmean/nanstd to be robust.
    """
    X = np.array(X, copy=True)  # ensure writable
    _nan_to_num_(X)
    mean = np.nanmean(X, axis=0, keepdims=True)
    std = np.nanstd(X, axis=0, keepdims=True)
    std = np.where(std < 1e-8, 1.0, std)
    Xz = (X - mean) / std
    _nan_to_num_(Xz)
    return Xz.astype(np.float32, copy=False), mean.squeeze().astype(np.float32), std.squeeze().astype(np.float32)


def standardize_apply(X: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    X = np.array(X, copy=True)
    _nan_to_num_(X)
    std2 = np.where(std < 1e-8, 1.0, std)
    Xz = (X - mean) / std2
    _nan_to_num_(Xz)
    return Xz.astype(np.float32, copy=False)


# -----------------------------
# Training (PyTorch)
# -----------------------------
@dataclass
class TorchTrainConfig:
    epochs: int = 30
    batch_size: int = 8192
    lr: float = 1e-3
    weight_decay: float = 1e-4

    # requested
    patience: int = 7

    # anti-overfitting: val_loss + gap_weight * max(0, val_loss-train_loss)
    gap_weight: float = 0.5
    min_delta: float = 0.0
    seed: int = 42

    # logging / progress
    verbose: bool = True
    log_every_batches: int = 20  # tqdm postfix update frequency

    # evaluation
    max_eval_samples: Optional[int] = 200_000
    compute_auc: bool = True

    # amp
    use_amp: bool = True

    # checkpoint on improvement
    checkpoint_path: Optional[Union[str, Path]] = None

    # gradient clipping
    grad_clip_norm: float = 1.0


@dataclass
class TorchHistoryRow:
    epoch: int
    train_loss: float
    train_acc: float
    val_loss: float
    val_acc: float
    score: float
    val_auc: Optional[float] = None


def _fmt_epoch(ep: int, total: int) -> str:
    return f"{ep:02d}" if total < 100 else f"{ep:03d}"


def _safe_softmax_logits(logits: torch.Tensor) -> torch.Tensor:
    # replace NaNs to avoid propagating to metrics
    logits = torch.nan_to_num(logits, nan=0.0, posinf=0.0, neginf=0.0)
    return torch.softmax(logits, dim=1)


def _eval_loss_acc_auc(
    model: torch.nn.Module,
    loader: torch.utils.data.DataLoader,
    criterion,
    device: torch.device,
    n_classes: int,
    max_samples: Optional[int],
    compute_auc: bool,
) -> Tuple[float, float, Optional[float]]:
    """
    Returns: loss, acc, roc_auc (binary)
    """
    model.eval()
    total_loss = 0.0
    n = 0
    correct = 0

    y_true_buf = []
    y_score_buf = []

    with torch.no_grad():
        for xb, yb in loader:
            xb = xb.to(device, non_blocking=True)
            yb = yb.to(device, non_blocking=True)

            xb = torch.nan_to_num(xb, nan=0.0, posinf=0.0, neginf=0.0)

            logits = model(xb)
            loss = criterion(logits, yb)

            bs = xb.shape[0]
            total_loss += float(loss.item()) * bs
            n += bs

            pred = logits.argmax(dim=1)
            correct += int((pred == yb).sum().item())

            if compute_auc and n_classes == 2:
                if (max_samples is None) or (sum(len(a) for a in y_true_buf) < max_samples):
                    probs = _safe_softmax_logits(logits)[:, 1].detach().cpu().numpy()
                    yt = yb.detach().cpu().numpy()
                    if max_samples is not None:
                        remain = max_samples - sum(len(a) for a in y_true_buf)
                        probs = probs[:remain]
                        yt = yt[:remain]
                    y_true_buf.append(yt.astype(np.int32, copy=False))
                    y_score_buf.append(probs.astype(np.float32, copy=False))

    loss_out = total_loss / max(n, 1)
    acc_out = float(correct / max(n, 1))

    auc_out = None
    if compute_auc and n_classes == 2 and y_true_buf:
        from sklearn.metrics import roc_auc_score
        yt = np.concatenate(y_true_buf)
        ys = np.concatenate(y_score_buf)
        mask = np.isfinite(ys)
        yt = yt[mask]
        ys = ys[mask]
        if len(yt) and len(np.unique(yt)) > 1:
            auc_out = float(roc_auc_score(yt, ys))

    return float(loss_out), float(acc_out), auc_out


def train_torch_classifier(
    model: torch.nn.Module,
    train_loader: torch.utils.data.DataLoader,
    val_loader: torch.utils.data.DataLoader,
    criterion,
    optimizer: torch.optim.Optimizer,
    device: torch.device,
    cfg: TorchTrainConfig,
    run_name: str = "",
    n_classes: Optional[int] = None,
) -> Tuple[Dict[str, torch.Tensor], List[TorchHistoryRow], int]:
    """
    Early stopping with patience (default 7).
    "Best" chosen by score = val_loss + gap_weight * max(0, val_loss - train_loss).
    Saves best checkpoint to cfg.checkpoint_path whenever it improves (to avoid losing it on crashes).
    """
    if n_classes is None:
        # best-effort for CE classifiers
        n_classes = getattr(getattr(model, "linear", None), "out_features", None) or 2
    n_classes = int(n_classes)

    try:
        from tqdm import tqdm
        has_tqdm = True
    except Exception:
        tqdm = None
        has_tqdm = False

    best_state: Optional[Dict[str, torch.Tensor]] = None
    best_score = float("inf")
    best_epoch = -1
    bad = 0
    history: List[TorchHistoryRow] = []

    # AMP (new API when available)
    use_amp = bool(cfg.use_amp and (device.type == "cuda"))
    try:
        autocast = torch.amp.autocast
        GradScaler = torch.amp.GradScaler
        autocast_kwargs = {"device_type": "cuda"} if device.type == "cuda" else {"device_type": "cpu"}
    except Exception:
        autocast = torch.cuda.amp.autocast
        GradScaler = torch.cuda.amp.GradScaler
        autocast_kwargs = {}

    scaler = GradScaler(enabled=use_amp)

    if cfg.verbose:
        tag = f"[{run_name}] " if run_name else ""
        print(f"{tag}Training start | epochs={cfg.epochs} | device={device} | batches/epoch={len(train_loader)}")

    ckpt_path = Path(cfg.checkpoint_path).resolve() if cfg.checkpoint_path else None
    if ckpt_path is not None:
        ensure_dir(ckpt_path.parent)

    for epoch in range(1, cfg.epochs + 1):
        model.train()
        total = 0.0
        n = 0
        correct = 0

        it = train_loader
        if has_tqdm and cfg.verbose:
            it = tqdm(train_loader, desc=f"{run_name} train e{epoch:02d}".strip(), leave=False)

        for bi, (xb, yb) in enumerate(it, start=1):
            xb = xb.to(device, non_blocking=True)
            yb = yb.to(device, non_blocking=True)

            xb = torch.nan_to_num(xb, nan=0.0, posinf=0.0, neginf=0.0)

            optimizer.zero_grad(set_to_none=True)
            with autocast(**autocast_kwargs, enabled=use_amp):
                logits = model(xb)
                loss = criterion(logits, yb)

            if use_amp:
                scaler.scale(loss).backward()
                if cfg.grad_clip_norm and cfg.grad_clip_norm > 0:
                    scaler.unscale_(optimizer)
                    torch.nn.utils.clip_grad_norm_(model.parameters(), cfg.grad_clip_norm)
                scaler.step(optimizer)
                scaler.update()
            else:
                loss.backward()
                if cfg.grad_clip_norm and cfg.grad_clip_norm > 0:
                    torch.nn.utils.clip_grad_norm_(model.parameters(), cfg.grad_clip_norm)
                optimizer.step()

            bs = xb.shape[0]
            total += float(loss.item()) * bs
            n += bs

            pred = logits.argmax(dim=1)
            correct += int((pred == yb).sum().item())

            if has_tqdm and cfg.verbose and cfg.log_every_batches and (bi % cfg.log_every_batches == 0):
                tr_loss_sofar = total / max(n, 1)
                tr_acc_sofar = correct / max(n, 1)
                try:
                    it.set_postfix({"loss": f"{tr_loss_sofar:.4f}", "acc": f"{tr_acc_sofar:.4f}"})
                except Exception:
                    pass

        train_loss = float(total / max(n, 1))
        train_acc = float(correct / max(n, 1))

        val_loss, val_acc, val_auc = _eval_loss_acc_auc(
            model=model,
            loader=val_loader,
            criterion=criterion,
            device=device,
            n_classes=n_classes,
            max_samples=cfg.max_eval_samples,
            compute_auc=cfg.compute_auc,
        )

        score = float(val_loss + cfg.gap_weight * max(0.0, val_loss - train_loss))
        history.append(TorchHistoryRow(
            epoch=epoch,
            train_loss=train_loss,
            train_acc=train_acc,
            val_loss=float(val_loss),
            val_acc=float(val_acc),
            score=score,
            val_auc=val_auc,
        ))

        # log epoch summary (single line)
        if cfg.verbose:
            extra = f" | val_auc {val_auc:.4f}" if val_auc is not None else ""
            print(
                f"epoch {_fmt_epoch(epoch, cfg.epochs)} | "
                f"train loss {train_loss:.4f} acc {train_acc:.4f} | "
                f"val loss {val_loss:.4f} acc {val_acc:.4f}{extra}"
            )

        improved = (best_score - score) > cfg.min_delta
        if improved:
            best_score = score
            best_epoch = epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            bad = 0

            # save checkpoint immediately
            if ckpt_path is not None:
                torch.save(best_state, ckpt_path)
        else:
            bad += 1

        if bad >= cfg.patience:
            if cfg.verbose:
                print(f"Early stopping at epoch={epoch} | best_epoch={best_epoch} | best_score={best_score:.6f}")
            break

    if best_state is None:
        best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        best_epoch = history[-1].epoch if history else 0
        if ckpt_path is not None:
            torch.save(best_state, ckpt_path)

    if cfg.verbose:
        print(f"Training end | best_epoch={best_epoch}")

    return best_state, history, best_epoch


def history_to_csv(path: Path, history: List[TorchHistoryRow]) -> None:
    ensure_dir(path.parent)
    df = pd.DataFrame([asdict(r) for r in history])
    df.to_csv(path, index=False)


# -----------------------------
# Artifacts helpers
# -----------------------------
def artifacts_root(model_name: str, split_mode: str, run_id: Optional[str] = None, run_config: Optional[Dict[str, object]] = None) -> Path:
    run_id = run_id or now_run_id()
    root = resolve_from_root(f"src/models/CIC-IDS2017/artifacts/{model_name}/{split_mode}/{run_id}")
    ensure_dir(root)
    save_run_metadata(root, model_name, split_mode, run_id, run_config=run_config)
    return root


def fit_label_encoder(y_train: np.ndarray) -> LabelEncoder:
    """
    LabelEncoder estable: si es binario y existe BENIGN, forzamos:
      BENIGN -> 0
      (lo no benigno) -> 1

    Esto hace coherente que AUC/ROC se calcule contra la clase positiva (índice 1).
    """
    le = LabelEncoder()
    y = y_train.astype(str)
    le.fit(y)
    # Reorden estable para binario con BENIGN
    if len(le.classes_) == 2:
        classes = list(map(str, le.classes_))
        benign = None
        for c in classes:
            if c.upper() == 'BENIGN':
                benign = c
                break
        if benign is not None:
            other = [c for c in classes if c != benign]
            if other:
                le.classes_ = np.array([benign, other[0]], dtype=le.classes_.dtype)
    return le


def save_label_encoder(root: Path, le: LabelEncoder) -> None:
    mapping = {cls: int(i) for i, cls in enumerate(le.classes_)}
    save_json(root / "label_map.json", mapping)


def save_scaler_stats(root: Path, mean: np.ndarray, std: np.ndarray) -> None:
    ensure_dir(root)
    np.save(root / "x_mean.npy", mean)
    np.save(root / "x_std.npy", std)


def torch_dataloaders_from_numpy(
    X_train: np.ndarray, y_train: np.ndarray,
    X_val: np.ndarray, y_val: np.ndarray,
    batch_size: int,
    num_workers: int = 0,
) -> Tuple[torch.utils.data.DataLoader, torch.utils.data.DataLoader]:
    ds_tr = torch.utils.data.TensorDataset(torch.from_numpy(X_train), torch.from_numpy(y_train))
    ds_va = torch.utils.data.TensorDataset(torch.from_numpy(X_val), torch.from_numpy(y_val))
    tr_loader = torch.utils.data.DataLoader(ds_tr, batch_size=batch_size, shuffle=True, num_workers=num_workers, pin_memory=True)
    va_loader = torch.utils.data.DataLoader(ds_va, batch_size=batch_size, shuffle=False, num_workers=num_workers, pin_memory=True)
    return tr_loader, va_loader
