#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple, Union

import numpy as np
import pandas as pd


def repo_root() -> Path:
    # <root>/src/models/CIC-IDS2017/sequence_loader.py
    return Path(__file__).resolve().parents[3]


def resolve_from_root(p: Union[str, Path]) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


def list_parquets(folder: Path) -> List[Path]:
    if not folder.exists():
        return []
    return sorted([p for p in folder.rglob("*.parquet") if p.is_file()])


def seq_split_folder(
    datasets_base: Union[str, Path],
    mode: str,          # day|random|groupkfold
    task: str,          # binary|multiclass|multiclass_grouped
    split: str,         # train|val|test
    fold: Optional[int] = None,
) -> Path:
    base = resolve_from_root(datasets_base) / "sequence" / mode / "TrafficLabelling" / task
    if mode == "groupkfold":
        if fold is None:
            raise ValueError("groupkfold requiere fold.")
        return base / f"fold_{fold}" / split
    return base / split


def parse_seq_columns(df: pd.DataFrame) -> Tuple[List[str], int, List[str]]:
    """
    Encuentra columnas feat__t-k y devuelve:
      - ordered_cols (oldest->newest, luego por feature)
      - window_size
      - feature_names (orden estable)
    """
    pat = re.compile(r"^(.*)__t-(\d+)$")
    feats = []
    times = set()
    for c in df.columns:
        m = pat.match(c)
        if m:
            feat = m.group(1)
            t = int(m.group(2))
            feats.append((feat, t, c))
            times.add(t)

    if not feats:
        raise ValueError("No se encontraron columnas __t-* en parquet secuencial.")

    window_size = max(times) + 1
    feature_names = sorted(list({f for f, _, _ in feats}))

    # Orden: oldest->newest => t-(W-1) ... t-0
    ordered_cols = []
    for t in range(window_size - 1, -1, -1):
        for f in feature_names:
            col = f"{f}__t-{t}"
            if col in df.columns:
                ordered_cols.append(col)

    return ordered_cols, window_size, feature_names


def load_sequence_split(
    datasets_base: Union[str, Path] = "src/models/CIC-IDS2017/datasets",
    mode: str = "day",
    task: str = "binary",
    split: str = "train",
    fold: Optional[int] = None,
    sample_frac: Optional[float] = None,
    seed: int = 42,
    dtype: np.dtype = np.float32,
) -> Tuple[np.ndarray, np.ndarray, int, int]:
    """
    Devuelve:
      X: (N, T, F)
      y: (N,) string labels
      T: window_size
      F: n_features
    """
    folder = seq_split_folder(datasets_base, mode, task, split, fold)
    paths = list_parquets(folder)
    if not paths:
        raise FileNotFoundError(f"No hay parquets en: {folder}")

    df = pd.concat([pd.read_parquet(p) for p in paths], ignore_index=True)

    if sample_frac is not None:
        df = df.sample(frac=sample_frac, random_state=seed)

    y = df["target"].to_numpy(copy=True)

    cols, T, feat_names = parse_seq_columns(df)
    Xflat = df[cols].to_numpy(dtype=dtype, copy=False)
    F = len(feat_names)
    X = Xflat.reshape(len(df), T, F)

    return X, y, T, F