#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Optional, Union

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


def read_json_optional(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def dataset_profile_path(split_mode: str, fold: Optional[int] = None) -> Path:
    base = resolve_from_root(f"src/models/UNSW-NB15/datasets/{split_mode}/NUSW-NB15")
    if split_mode == "groupkfold" and fold is not None:
        return base / f"fold_{fold}" / "dataset_profile.json"
    return base / "dataset_profile.json"


def dataset_profile_reference(split_mode: str, fold: Optional[int] = None) -> Dict[str, Any]:
    path = dataset_profile_path(split_mode, fold)
    profile = read_json_optional(path)
    if profile is None:
        return {
            "status": "missing",
            "path": str(path),
        }

    config = profile.get("config", {}) if isinstance(profile, dict) else {}
    return {
        "status": "ok",
        "path": str(path),
        "dataset": profile.get("dataset"),
        "split_mode": config.get("split_mode"),
        "source_set": config.get("source_set"),
        "feature_count": profile.get("feature_count"),
        "input_file_count": profile.get("input_file_count"),
        "config_fingerprint": profile.get("config_fingerprint"),
        "fold": fold,
    }


def save_dataset_profile_ref(root: Path, split_mode: str, fold: Optional[int] = None) -> Dict[str, Any]:
    ref = dataset_profile_reference(split_mode, fold)
    save_json(root / "dataset_profile_ref.json", ref)
    return ref


def save_run_metadata(root: Path, model_name: str, split_mode: str, run_id: str, dataset: str = "NUSW-NB15", run_config: Optional[Dict[str, Any]] = None) -> None:
    payload: Dict[str, Any] = {
        "dataset": dataset,
        "model_name": model_name,
        "split_mode": split_mode,
        "run_id": run_id,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifact_root": str(root),
        "dataset_profile": dataset_profile_reference(split_mode),
    }
    if run_config is not None:
        payload["run_config"] = run_config
        if "sample_frac" in run_config:
            payload["sample_frac"] = run_config.get("sample_frac")
    save_json(root / "run_metadata.json", payload)


def artifacts_root(model_name: str, split_mode: str, run_id: Optional[str] = None, run_config: Optional[Dict[str, Any]] = None) -> Path:
    run_id = run_id or now_run_id()
    root = resolve_from_root(f"src/models/UNSW-NB15/artifacts/{model_name}/{split_mode}/{run_id}")
    ensure_dir(root)
    save_run_metadata(root, model_name, split_mode, run_id, run_config=run_config)
    save_dataset_profile_ref(root, split_mode)
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
