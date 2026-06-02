#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence

import numpy as np


@dataclass(frozen=True)
class DatasetConfig:
    key: str
    model_dir: str
    datasets_base: str
    dataset: str
    split_mode: str
    pipeline: str = "binary"
    fold: int | None = None


DATASET_CONFIGS: Dict[str, DatasetConfig] = {
    "CIC-IDS2017": DatasetConfig(
        key="CIC-IDS2017",
        model_dir="src/models/CIC-IDS2017",
        datasets_base="src/models/CIC-IDS2017/datasets",
        dataset="MachineLearningCVE",
        split_mode="day",
    ),
    "UNSW-NB15": DatasetConfig(
        key="UNSW-NB15",
        model_dir="src/models/UNSW-NB15",
        datasets_base="src/models/UNSW-NB15/datasets",
        dataset="NUSW-NB15",
        split_mode="groupkfold",
        fold=0,
    ),
    "UGR16": DatasetConfig(
        key="UGR16",
        model_dir="src/models/UGR16",
        datasets_base="src/models/UGR16/datasets",
        dataset="UGR16_MARAPR_HYBRID",
        split_mode="date",
    ),
    "LAB-ALERTS": DatasetConfig(
        key="LAB-ALERTS",
        model_dir="src/models/LAB-ALERTS",
        datasets_base="src/models/LAB-ALERTS/datasets",
        dataset="LAB-ALERTS",
        split_mode="date",
    ),
    "COWRIE_FULL": DatasetConfig(
        key="COWRIE_FULL",
        model_dir="src/models/COWRIE_FULL",
        datasets_base="src/models/COWRIE_FULL/datasets",
        dataset="COWRIE_FULL",
        split_mode="date",
    ),
}


FEATURE_GROUP_PATTERNS: Mapping[str, Sequence[str]] = {
    "duration": (r"duration", r"\bdur\b", r"elapsed", r"time_delta"),
    "bytes": (r"byte", r"bytes", r"octet", r"payload", r"size"),
    "packets": (r"packet", r"pkts?", r"\bpkt\b"),
    "rates": (r"rate", r"per_sec", r"pps", r"bps"),
    "ports": (r"port", r"sport", r"dport"),
    "protocol": (r"proto", r"tcp", r"udp", r"icmp"),
    "flags": (r"flag", r"syn", r"ack", r"rst", r"fin", r"urg"),
    "dns": (r"dns", r"domain", r"nxdomain", r"query", r"qtype"),
    "http": (r"http", r"url", r"uri", r"method", r"status", r"user_agent"),
    "tls_ssl": (r"tls", r"ssl", r"sni", r"cert", r"ja3"),
    "auth": (r"auth", r"login", r"user", r"password", r"credential", r"failed"),
    "session": (r"session", r"command", r"shell", r"tty", r"input"),
    "counts": (r"count", r"cnt", r"num", r"number", r"total"),
    "unique": (r"unique", r"distinct", r"uniq"),
    "ratio": (r"ratio", r"percent", r"pct", r"frac"),
    "temporal": (r"hour", r"day", r"minute", r"second", r"window", r"rolling", r"lag"),
    "severity": (r"severity", r"priority", r"risk", r"score", r"alert"),
    "rarity": (r"rare", r"novel", r"first", r"seen", r"entropy"),
}


ROW_FEATURES = [
    "row_mean",
    "row_std",
    "row_min",
    "row_max",
    "row_abs_mean",
    "row_abs_max",
    "row_nonzero_ratio",
    "row_positive_ratio",
    "row_negative_ratio",
]

GROUP_STATS = ["mean", "abs_mean", "abs_max", "nonzero_ratio", "presence"]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_from_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root() / candidate).resolve()


def selected_dataset_configs(dataset_keys: Iterable[str]) -> List[DatasetConfig]:
    keys = [str(key) for key in dataset_keys]
    if not keys or "all" in {key.lower() for key in keys}:
        return list(DATASET_CONFIGS.values())
    missing = [key for key in keys if key not in DATASET_CONFIGS]
    if missing:
        raise ValueError(f"Unsupported dataset keys: {missing}")
    return [DATASET_CONFIGS[key] for key in keys]


def dataset_id_map(configs: Sequence[DatasetConfig]) -> Dict[str, int]:
    return {config.key: index for index, config in enumerate(configs)}


def global_feature_columns() -> List[str]:
    columns = list(ROW_FEATURES)
    for group_name in FEATURE_GROUP_PATTERNS:
        for stat_name in GROUP_STATS:
            columns.append(f"{group_name}_{stat_name}")
    return columns


def normalize_feature_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def group_indices(feature_names: Sequence[str]) -> Dict[str, List[int]]:
    normalized_names = [normalize_feature_name(name) for name in feature_names]
    output: Dict[str, List[int]] = {}
    for group_name, patterns in FEATURE_GROUP_PATTERNS.items():
        compiled = [re.compile(pattern) for pattern in patterns]
        matches: List[int] = []
        for feature_index, feature_name in enumerate(normalized_names):
            if any(pattern.search(feature_name) for pattern in compiled):
                matches.append(feature_index)
        output[group_name] = matches
    return output


def row_level_features(features_matrix: np.ndarray) -> np.ndarray:
    abs_matrix = np.abs(features_matrix)
    return np.column_stack(
        [
            np.mean(features_matrix, axis=1),
            np.std(features_matrix, axis=1),
            np.min(features_matrix, axis=1),
            np.max(features_matrix, axis=1),
            np.mean(abs_matrix, axis=1),
            np.max(abs_matrix, axis=1),
            np.mean(features_matrix != 0.0, axis=1),
            np.mean(features_matrix > 0.0, axis=1),
            np.mean(features_matrix < 0.0, axis=1),
        ]
    ).astype(np.float32, copy=False)


def grouped_features(features_matrix: np.ndarray, feature_names: Sequence[str]) -> np.ndarray:
    indices_by_group = group_indices(feature_names)
    group_blocks: List[np.ndarray] = []
    row_count = features_matrix.shape[0]
    for group_name in FEATURE_GROUP_PATTERNS:
        selected_indices = indices_by_group[group_name]
        if not selected_indices:
            group_blocks.append(np.zeros((row_count, len(GROUP_STATS)), dtype=np.float32))
            continue
        group_matrix = features_matrix[:, selected_indices]
        abs_group_matrix = np.abs(group_matrix)
        presence = np.ones(row_count, dtype=np.float32)
        group_blocks.append(
            np.column_stack(
                [
                    np.mean(group_matrix, axis=1),
                    np.mean(abs_group_matrix, axis=1),
                    np.max(abs_group_matrix, axis=1),
                    np.mean(group_matrix != 0.0, axis=1),
                    presence,
                ]
            ).astype(np.float32, copy=False)
        )
    return np.concatenate(group_blocks, axis=1).astype(np.float32, copy=False)


def transform_to_global_features(features_matrix: np.ndarray, feature_names: Sequence[str]) -> np.ndarray:
    if features_matrix.ndim != 2:
        raise ValueError("features_matrix must be two-dimensional")
    clean_matrix = features_matrix.astype(np.float32, copy=True)
    np.nan_to_num(clean_matrix, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    transformed = np.concatenate([row_level_features(clean_matrix), grouped_features(clean_matrix, feature_names)], axis=1)
    np.nan_to_num(transformed, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return transformed.astype(np.float32, copy=False)


def binary_target(raw_labels: Sequence[object]) -> np.ndarray:
    labels = np.asarray(raw_labels).astype(str)
    benign_mask = np.char.upper(labels) == "BENIGN"
    return np.where(benign_mask, 0, 1).astype(np.int64)