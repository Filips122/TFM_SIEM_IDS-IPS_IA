#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Split loading for ARGOS-LAB.

Adds one thing over the sibling dataset loaders: every load is scoped to a
named feature regime (see feature_spec.FEATURE_SETS), so an experiment can
never accidentally train on the columns the weak labeller used.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import numpy as np
import pandas as pd

from feature_spec import resolve_feature_set

DEFAULT_BASE = "src/models/ARGOS_LAB/datasets"
DEFAULT_DATASET = "ARGOS-LAB"

ANOMALY_FOLDERS = {
    "benign": "train_benign",
    "quiet": "train_quiet",
    "all": "train_all",
    "val": "val_mixed",
    "test": "test_mixed",
}


class EmptySplitError(ValueError):
    pass


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_from_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root() / candidate).resolve()


@dataclass
class LoadedSplit:
    X: np.ndarray
    y: np.ndarray
    feature_names: List[str]
    meta: pd.DataFrame

    def __len__(self) -> int:
        return int(self.X.shape[0])


def mode_root(base: str | Path, split_mode: str, dataset: str, fold: Optional[int] = None) -> Path:
    root = resolve_from_root(base) / split_mode / dataset
    if split_mode == "groupkfold":
        if fold is None:
            raise ValueError("split_mode=groupkfold requires fold=<int>")
        return root / f"fold_{fold}"
    return root


def split_folder(base: str | Path, split_mode: str, dataset: str, pipeline: str, split: str, fold: Optional[int] = None) -> Path:
    root = mode_root(base, split_mode, dataset, fold)
    if pipeline == "anomaly":
        if split not in ANOMALY_FOLDERS:
            raise ValueError(f"Unknown anomaly split '{split}'. Choose from {sorted(ANOMALY_FOLDERS)}")
        return root / "anomaly" / ANOMALY_FOLDERS[split]
    return root / pipeline / split


def list_parquets(folder: Path) -> List[Path]:
    if not folder.exists():
        return []
    return sorted(path for path in folder.rglob("*.parquet") if path.is_file())


def load_feature_columns(base: str | Path, split_mode: str, dataset: str, fold: Optional[int] = None) -> List[str]:
    root = mode_root(base, split_mode, dataset, fold)
    path = root / "feature_columns.json"
    if not path.exists() and split_mode == "groupkfold":
        path = resolve_from_root(base) / split_mode / dataset / "feature_columns.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing feature_columns.json: {path}. Run prepare_dataset.py first.")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"Invalid feature_columns.json: {path}")
    return [str(item) for item in payload]


def load_label_map(base: str | Path, split_mode: str, dataset: str, pipeline: str, fold: Optional[int] = None) -> Dict[str, int]:
    path = mode_root(base, split_mode, dataset, fold) / pipeline / "label_map.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing label_map.json: {path}")
    return {str(k): int(v) for k, v in json.loads(path.read_text(encoding="utf-8")).items()}


def load_split(
    base: str | Path = DEFAULT_BASE,
    split_mode: str = "date",
    dataset: str = DEFAULT_DATASET,
    pipeline: str = "binary",
    split: str = "train",
    fold: Optional[int] = None,
    feature_set: str = "behavioral",
    sample_frac: Optional[float] = None,
    seed: int = 42,
    dtype: np.dtype = np.float32,
    exclude_posture_windows: bool = False,
    feature_cols: Optional[Sequence[str]] = None,
) -> LoadedSplit:
    folder = split_folder(base, split_mode, dataset, pipeline, split, fold)
    paths = list_parquets(folder)
    if not paths:
        raise FileNotFoundError(f"No parquet files in: {folder}. Run prepare_dataset.py first.")
    df = pd.concat([pd.read_parquet(path) for path in paths], ignore_index=True)

    if exclude_posture_windows:
        # Evaluation-time variant of --exclude_posture: keeps the dataset as
        # built but drops windows dominated by vulnerability-scanner output.
        df = df[df["posture_ratio"] < 0.5]
    if sample_frac is not None:
        if not 0.0 < sample_frac <= 1.0:
            raise ValueError("sample_frac must be in (0, 1]")
        df = df.sample(frac=sample_frac, random_state=seed)
    if df.empty:
        raise EmptySplitError(f"Loaded zero rows from {folder}")
    if "target" not in df.columns:
        raise ValueError(f"Missing target column in {folder}")

    if feature_cols is None:
        available = set(load_feature_columns(base, split_mode, dataset, fold))
        requested = resolve_feature_set(feature_set)
        unknown = [column for column in requested if column not in available]
        if unknown:
            raise ValueError(f"feature_set '{feature_set}' asks for columns not in this dataset: {unknown[:10]}")
        feature_cols = requested

    missing = [column for column in feature_cols if column not in df.columns]
    if missing:
        raise ValueError(f"Missing features in split: {missing[:10]}")

    X = df.loc[:, list(feature_cols)].to_numpy(dtype=dtype, copy=True)
    np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    y = df["target"].astype(str).to_numpy(copy=True)
    meta_cols = [c for c in ("window_start", "agent_id", "top_rule_id", "top_decoder", "posture_ratio", "alert_count") if c in df.columns]
    return LoadedSplit(X=X, y=y, feature_names=list(feature_cols), meta=df.loc[:, meta_cols].reset_index(drop=True))


def load_splits(
    base: str | Path = DEFAULT_BASE,
    split_mode: str = "date",
    dataset: str = DEFAULT_DATASET,
    pipeline: str = "binary",
    fold: Optional[int] = None,
    feature_set: str = "behavioral",
    sample_frac: Optional[float] = None,
    seed: int = 42,
    dtype: np.dtype = np.float32,
    exclude_posture_windows: bool = False,
    anomaly_train_policy: str = "quiet",
) -> tuple[LoadedSplit, LoadedSplit, LoadedSplit]:
    """Return (train, val, test). For pipeline='anomaly' the training split is
    chosen by `anomaly_train_policy` and val/test are the mixed evaluation
    sets."""
    train_split = anomaly_train_policy if pipeline == "anomaly" else "train"
    val_split, test_split = ("val", "test") if pipeline != "anomaly" else ("val", "test")

    kwargs = dict(
        base=base, split_mode=split_mode, dataset=dataset, pipeline=pipeline, fold=fold,
        feature_set=feature_set, sample_frac=sample_frac, seed=seed, dtype=dtype,
        exclude_posture_windows=exclude_posture_windows,
    )
    train = load_split(split=train_split, **kwargs)
    val = load_split(split=val_split, feature_cols=train.feature_names, **kwargs)
    test = load_split(split=test_split, feature_cols=train.feature_names, **kwargs)
    return train, val, test
