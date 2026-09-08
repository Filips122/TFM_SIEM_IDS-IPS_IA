#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import random
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import numpy as np
from sklearn.preprocessing import LabelEncoder


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_from_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root() / candidate).resolve()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def now_run_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def save_json(path: Path, payload: Dict) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def artifacts_root(model_name: str, split_mode: str, feature_set: str, run_id: Optional[str] = None) -> Path:
    """Artifacts are keyed by feature regime as well as split mode, because the
    same model trained on `full` and on `behavioral` are different experiments
    and must not overwrite each other."""
    run_id = run_id or now_run_id()
    root = resolve_from_root(f"src/models/ARGOS_LAB/artifacts/{model_name}/{split_mode}/{feature_set}/{run_id}")
    ensure_dir(root)
    return root


def fit_label_encoder(y_train: np.ndarray) -> LabelEncoder:
    encoder = LabelEncoder()
    encoder.fit(y_train.astype(str))
    classes = list(map(str, encoder.classes_))
    if len(classes) == 2 and {"BENIGN", "ATTACK"} == set(classes):
        encoder.classes_ = np.array(["BENIGN", "ATTACK"], dtype=encoder.classes_.dtype)
    return encoder


def save_label_encoder(path: Path, encoder: LabelEncoder) -> Dict[str, int]:
    mapping = {str(label): int(index) for index, label in enumerate(encoder.classes_)}
    save_json(path / "label_map.json", mapping)
    return mapping


def align_labels(encoder: LabelEncoder, y: np.ndarray) -> np.ndarray:
    """Encode labels, dropping nothing: unseen classes raise loudly rather than
    silently mapping to 0."""
    known = set(map(str, encoder.classes_))
    unseen = sorted(set(map(str, y)) - known)
    if unseen:
        raise SystemExit(f"Split contains classes absent from the training split: {unseen}")
    return encoder.transform(y.astype(str))


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except Exception:
        pass


def get_device():
    import torch

    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def standardize_fit(X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std < 1e-6] = 1.0
    return ((X - mean) / std).astype(np.float32), mean.astype(np.float32), std.astype(np.float32)


def standardize_apply(X: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    return ((X - mean) / std).astype(np.float32)


def save_scaler_stats(path: Path, mean: np.ndarray, std: np.ndarray) -> None:
    save_json(path / "scaler.json", {"mean": mean.tolist(), "std": std.tolist()})


def class_weights(y: np.ndarray, n_classes: int) -> np.ndarray:
    """Inverse-frequency weights. Essential here: the window-level minority
    class is ~2% of rows."""
    counts = np.bincount(y.astype(int), minlength=n_classes).astype(np.float64)
    counts[counts == 0] = 1.0
    weights = counts.sum() / (n_classes * counts)
    return weights.astype(np.float32)


def run_header(title: str, **fields) -> None:
    print(f"== {title} ==")
    for key, value in fields.items():
        print(f"{key:<16}: {value}")
    print(flush=True)
