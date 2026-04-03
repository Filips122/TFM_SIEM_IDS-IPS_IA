#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple, Union

import numpy as np
import pandas as pd


def repo_root() -> Path:
    # <root>/src/models/NUSW-NB15/data_loader.py
    return Path(__file__).resolve().parents[3]


def resolve_from_root(p: Union[str, Path]) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


@dataclass
class LoadedSplit:
    X: np.ndarray
    y: np.ndarray
    feature_names: List[str]


def _list_parquets(folder: Path) -> List[Path]:
    if not folder.exists():
        return []
    return sorted([p for p in folder.rglob("*.parquet") if p.is_file()])


def _read_parquets(paths: List[Path], columns: Optional[Sequence[str]] = None) -> pd.DataFrame:
    if not paths:
        return pd.DataFrame()
    frames = [pd.read_parquet(p, columns=columns) for p in paths]
    return pd.concat(frames, ignore_index=True)


def _infer_numeric_feature_columns(df: pd.DataFrame, target_col: str = "target") -> List[str]:
    drop = {"target", "label_raw"}
    feats = []
    for c in df.columns:
        if c in drop or c == target_col:
            continue
        if pd.api.types.is_bool_dtype(df[c]) or pd.api.types.is_numeric_dtype(df[c]):
            feats.append(c)
    return feats


def _to_xy(
    df: pd.DataFrame,
    target_col: str = "target",
    dtype: np.dtype = np.float32,
    feature_cols: Optional[Sequence[str]] = None,
) -> LoadedSplit:
    if df.empty:
        return LoadedSplit(X=np.empty((0, 0), dtype=dtype), y=np.empty((0,), dtype=object), feature_names=[])

    if target_col not in df.columns:
        raise ValueError(f"Missing target column: {target_col}")

    if feature_cols is None:
        feature_cols = _infer_numeric_feature_columns(df, target_col=target_col)

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing features in split: {missing[:10]}")

    X = df.loc[:, list(feature_cols)].to_numpy(dtype=dtype, copy=True)
    np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    y = df[target_col].to_numpy(copy=True)
    return LoadedSplit(X=X, y=y, feature_names=list(feature_cols))


def get_split_folder(
    datasets_base: Union[str, Path],
    split_mode: str,
    dataset: str,
    pipeline: str,
    split: str,
    fold: Optional[int] = None,
) -> Path:
    base = resolve_from_root(datasets_base) / split_mode / dataset

    if split_mode == "groupkfold":
        if fold is None:
            raise ValueError("split_mode=groupkfold requires fold=<int>")
        if pipeline == "anomaly":
            sub = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}[split]
            return base / f"fold_{fold}" / "anomaly" / sub
        return base / f"fold_{fold}" / pipeline / split

    if pipeline == "anomaly":
        sub = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}[split]
        return base / "anomaly" / sub
    return base / pipeline / split


def load_split(
    datasets_base: Union[str, Path] = "src/models/NUSW-NB15/datasets",
    split_mode: str = "random",
    dataset: str = "NUSW-NB15",
    pipeline: str = "binary",
    split: str = "train",
    fold: Optional[int] = None,
    sample_frac: Optional[float] = None,
    seed: int = 42,
    dtype: np.dtype = np.float32,
    feature_cols: Optional[Sequence[str]] = None,
) -> LoadedSplit:
    folder = get_split_folder(datasets_base, split_mode, dataset, pipeline, split, fold)
    paths = _list_parquets(folder)
    if not paths:
        raise FileNotFoundError(f"No parquet files in: {folder}")

    df = _read_parquets(paths)
    if sample_frac is not None:
        if not (0.0 < sample_frac <= 1.0):
            raise ValueError("sample_frac must be in (0,1]")
        df = df.sample(frac=sample_frac, random_state=seed)

    return _to_xy(df, target_col="target", dtype=dtype, feature_cols=feature_cols)


def load_splits(
    datasets_base: Union[str, Path] = "src/models/NUSW-NB15/datasets",
    split_mode: str = "random",
    dataset: str = "NUSW-NB15",
    pipeline: str = "binary",
    fold: Optional[int] = None,
    sample_frac: Optional[float] = None,
    seed: int = 42,
    dtype: np.dtype = np.float32,
) -> Tuple[LoadedSplit, LoadedSplit, LoadedSplit]:
    tr = load_split(datasets_base, split_mode, dataset, pipeline, "train", fold, sample_frac, seed, dtype)
    feature_cols = tr.feature_names

    va = load_split(datasets_base, split_mode, dataset, pipeline, "val", fold, sample_frac, seed, dtype, feature_cols=feature_cols)
    te = load_split(datasets_base, split_mode, dataset, pipeline, "test", fold, sample_frac, seed, dtype, feature_cols=feature_cols)
    return tr, va, te
