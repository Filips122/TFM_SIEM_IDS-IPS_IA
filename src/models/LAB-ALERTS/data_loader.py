#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

import numpy as np
import pandas as pd


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


def list_parquets(folder: Path) -> List[Path]:
    if not folder.exists():
        return []
    return sorted([path for path in folder.rglob("*.parquet") if path.is_file()])


def read_parquets(paths: List[Path]) -> pd.DataFrame:
    if not paths:
        return pd.DataFrame()
    return pd.concat([pd.read_parquet(path) for path in paths], ignore_index=True)


def mode_root(datasets_base: str | Path, split_mode: str, dataset: str, fold: Optional[int] = None) -> Path:
    root = resolve_from_root(datasets_base) / split_mode / dataset
    if split_mode == "groupkfold":
        if fold is None:
            raise ValueError("split_mode=groupkfold requires fold=<int>")
        return root / f"fold_{fold}"
    return root


def load_feature_columns(datasets_base: str | Path, split_mode: str, dataset: str, fold: Optional[int] = None) -> List[str]:
    root = mode_root(datasets_base, split_mode, dataset, fold)
    path = root / "feature_columns.json"
    if not path.exists() and split_mode == "groupkfold":
        path = resolve_from_root(datasets_base) / split_mode / dataset / "feature_columns.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing feature_columns.json: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        raise ValueError(f"Invalid feature_columns.json: {path}")
    return list(payload)


def split_folder(datasets_base: str | Path, split_mode: str, dataset: str, pipeline: str, split: str, fold: Optional[int] = None) -> Path:
    root = mode_root(datasets_base, split_mode, dataset, fold)
    if pipeline == "anomaly":
        subdir = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}[split]
        return root / "anomaly" / subdir
    return root / pipeline / split


def to_xy(df: pd.DataFrame, feature_cols: Sequence[str], dtype: np.dtype) -> LoadedSplit:
    if df.empty:
        raise EmptySplitError("Loaded zero rows")
    if "target" not in df.columns:
        raise ValueError("Missing target column")
    missing = [column for column in feature_cols if column not in df.columns]
    if missing:
        raise ValueError(f"Missing features in split: {missing[:10]}")
    X = df.loc[:, list(feature_cols)].to_numpy(dtype=dtype, copy=True)
    np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    y = df["target"].astype(str).to_numpy(copy=True)
    return LoadedSplit(X=X, y=y, feature_names=list(feature_cols))


def load_split(
    datasets_base: str | Path = "src/models/LAB-ALERTS/datasets",
    split_mode: str = "date",
    dataset: str = "LAB-ALERTS",
    pipeline: str = "binary",
    split: str = "train",
    fold: Optional[int] = None,
    sample_frac: Optional[float] = None,
    seed: int = 42,
    dtype: np.dtype = np.float32,
    feature_cols: Optional[Sequence[str]] = None,
) -> LoadedSplit:
    folder = split_folder(datasets_base, split_mode, dataset, pipeline, split, fold)
    paths = list_parquets(folder)
    if not paths:
        raise FileNotFoundError(f"No parquet files in: {folder}")
    df = read_parquets(paths)
    if sample_frac is not None:
        if not (0.0 < sample_frac <= 1.0):
            raise ValueError("sample_frac must be in (0, 1]")
        df = df.sample(frac=sample_frac, random_state=seed)
    if feature_cols is None:
        feature_cols = load_feature_columns(datasets_base, split_mode, dataset, fold)
    return to_xy(df, feature_cols, dtype)


def load_splits(
    datasets_base: str | Path = "src/models/LAB-ALERTS/datasets",
    split_mode: str = "date",
    dataset: str = "LAB-ALERTS",
    pipeline: str = "binary",
    fold: Optional[int] = None,
    sample_frac: Optional[float] = None,
    seed: int = 42,
    dtype: np.dtype = np.float32,
) -> tuple[LoadedSplit, LoadedSplit, LoadedSplit]:
    train = load_split(datasets_base, split_mode, dataset, pipeline, "train", fold, sample_frac, seed, dtype)
    val = load_split(datasets_base, split_mode, dataset, pipeline, "val", fold, sample_frac, seed, dtype, train.feature_names)
    test = load_split(datasets_base, split_mode, dataset, pipeline, "test", fold, sample_frac, seed, dtype, train.feature_names)
    return train, val, test