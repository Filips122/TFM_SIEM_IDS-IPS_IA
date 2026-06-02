#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

import numpy as np
import pandas as pd

from global_schema import resolve_from_root


@dataclass
class GlobalSplit:
    features: np.ndarray
    target: np.ndarray
    dataset_id: np.ndarray
    dataset_name: np.ndarray
    feature_names: List[str]


def load_feature_columns(dataset_root: str | Path = "src/models/GLOBAL_TRANSFORMER/datasets/GLOBAL_BINARY_V1") -> List[str]:
    root = resolve_from_root(dataset_root)
    path = root / "feature_columns.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing feature_columns.json: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        raise ValueError(f"Invalid feature_columns.json: {path}")
    return list(payload)


def load_split(
    dataset_root: str | Path = "src/models/GLOBAL_TRANSFORMER/datasets/GLOBAL_BINARY_V1",
    split: str = "train",
    include_datasets: list[str] | None = None,
    exclude_datasets: list[str] | None = None,
) -> GlobalSplit:
    root = resolve_from_root(dataset_root)
    feature_names = load_feature_columns(root)
    path = root / split / f"global_{split}.parquet"
    if not path.exists():
        raise FileNotFoundError(f"Missing global split parquet: {path}")
    frame = pd.read_parquet(path)
    if include_datasets:
        frame = frame[frame["dataset_name"].isin(include_datasets)].copy()
    if exclude_datasets:
        frame = frame[~frame["dataset_name"].isin(exclude_datasets)].copy()
    if frame.empty:
        raise ValueError(f"Global split is empty after filtering: split={split}")
    features = frame.loc[:, feature_names].to_numpy(dtype=np.float32, copy=True)
    np.nan_to_num(features, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return GlobalSplit(
        features=features,
        target=frame["target_binary"].to_numpy(dtype=np.int64, copy=True),
        dataset_id=frame["dataset_id"].to_numpy(dtype=np.int64, copy=True),
        dataset_name=frame["dataset_name"].astype(str).to_numpy(copy=True),
        feature_names=feature_names,
    )


def load_splits(
    dataset_root: str | Path = "src/models/GLOBAL_TRANSFORMER/datasets/GLOBAL_BINARY_V1",
    include_datasets: list[str] | None = None,
    exclude_datasets: list[str] | None = None,
) -> tuple[GlobalSplit, GlobalSplit, GlobalSplit]:
    return (
        load_split(dataset_root, "train", include_datasets, exclude_datasets),
        load_split(dataset_root, "val", include_datasets, exclude_datasets),
        load_split(dataset_root, "test", include_datasets, exclude_datasets),
    )