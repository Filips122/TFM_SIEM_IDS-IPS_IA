#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, Optional, Union

import numpy as np
import torch
from sklearn.preprocessing import LabelEncoder

from data_loader import load_splits


def repo_root() -> Path:
    # <root>/src/models/UNSW-NB15/train_utils.py
    return Path(__file__).resolve().parents[3]


def resolve_from_root(p: Union[str, Path]) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def now_run_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def save_json(path: Path, obj: Dict) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def artifacts_root(model_name: str, split_mode: str, run_id: Optional[str] = None) -> Path:
    run_id = run_id or now_run_id()
    root = resolve_from_root(f"src/models/UNSW-NB15/artifacts/{model_name}/{split_mode}/{run_id}")
    ensure_dir(root)
    return root


def fit_label_encoder(y_train: np.ndarray) -> LabelEncoder:
    """
    Stable binary encoding:
      BENIGN -> 0
      ATTACK -> 1
    when both are present.
    """
    le = LabelEncoder()
    y = y_train.astype(str)
    le.fit(y)
    if len(le.classes_) == 2:
        classes = list(map(str, le.classes_))
        if "BENIGN" in classes and "ATTACK" in classes:
            le.classes_ = np.array(["BENIGN", "ATTACK"], dtype=le.classes_.dtype)
    return le


def save_label_encoder(path: Path, le: LabelEncoder) -> Dict[str, int]:
    mapping = {str(c): int(i) for i, c in enumerate(le.classes_)}
    save_json(path / "label_map.json", mapping)
    return mapping


def set_seed(seed: int = 42) -> None:
    import random

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.benchmark = True


def get_device() -> torch.device:
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def standardize_fit(X: np.ndarray):
    X = np.array(X, copy=True)
    X = np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    mean = np.nanmean(X, axis=0, keepdims=True)
    std = np.nanstd(X, axis=0, keepdims=True)
    std = np.where(std < 1e-8, 1.0, std)
    Xz = (X - mean) / std
    Xz = np.nan_to_num(Xz, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return Xz.astype(np.float32, copy=False), mean.squeeze().astype(np.float32), std.squeeze().astype(np.float32)


def standardize_apply(X: np.ndarray, mean: np.ndarray, std: np.ndarray):
    X = np.array(X, copy=True)
    X = np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    std2 = np.where(std < 1e-8, 1.0, std)
    Xz = (X - mean) / std2
    Xz = np.nan_to_num(Xz, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return Xz.astype(np.float32, copy=False)


def save_scaler_stats(path: Path, mean: np.ndarray, std: np.ndarray) -> None:
    ensure_dir(path)
    np.save(path / "x_mean.npy", mean)
    np.save(path / "x_std.npy", std)
