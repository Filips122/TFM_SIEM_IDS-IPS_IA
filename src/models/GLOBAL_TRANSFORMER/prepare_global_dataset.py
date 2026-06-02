#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import importlib
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Sequence

import numpy as np
import pandas as pd

from global_schema import (
    DatasetConfig,
    binary_target,
    dataset_id_map,
    global_feature_columns,
    resolve_from_root,
    selected_dataset_configs,
    transform_to_global_features,
)


SPLIT_NAMES = ["train", "val", "test"]


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_data_loader(config: DatasetConfig) -> Any:
    model_dir = resolve_from_root(config.model_dir)
    sys.path.insert(0, str(model_dir))
    if "data_loader" in sys.modules:
        del sys.modules["data_loader"]
    return importlib.import_module("data_loader")


def sample_split_rows(features_matrix: np.ndarray, labels: np.ndarray, max_rows: int | None, seed: int) -> tuple[np.ndarray, np.ndarray]:
    if max_rows is None or len(labels) <= max_rows:
        return features_matrix, labels
    rng = np.random.default_rng(seed)
    selected_indices = rng.choice(len(labels), size=max_rows, replace=False)
    return features_matrix[selected_indices], labels[selected_indices]


def proportional_caps(split_sizes: Sequence[int], max_rows: int | None) -> List[int | None]:
    if max_rows is None:
        return [None for _ in split_sizes]
    total_rows = int(sum(split_sizes))
    if total_rows <= max_rows:
        return [None for _ in split_sizes]
    raw_caps = [max(1, int(max_rows * (split_size / total_rows))) for split_size in split_sizes]
    while sum(raw_caps) > max_rows:
        largest_index = int(np.argmax(raw_caps))
        raw_caps[largest_index] -= 1
    return raw_caps


def split_to_frame(
    dataset_key: str,
    dataset_id: int,
    split_name: str,
    features_matrix: np.ndarray,
    labels: np.ndarray,
    feature_names: Sequence[str],
) -> pd.DataFrame:
    transformed = transform_to_global_features(features_matrix, feature_names)
    frame = pd.DataFrame(transformed, columns=global_feature_columns())
    frame.insert(0, "dataset_id", int(dataset_id))
    frame.insert(1, "dataset_name", dataset_key)
    frame.insert(2, "split", split_name)
    frame.insert(3, "target_binary", binary_target(labels))
    frame.insert(4, "target_raw", np.asarray(labels).astype(str))
    return frame


def prepare_dataset_config(
    config: DatasetConfig,
    dataset_id: int,
    sample_frac: float | None,
    max_rows_per_dataset: int | None,
    seed: int,
) -> Dict[str, pd.DataFrame]:
    data_loader = load_data_loader(config)
    loaded_splits = data_loader.load_splits(
        datasets_base=config.datasets_base,
        split_mode=config.split_mode,
        dataset=config.dataset,
        pipeline=config.pipeline,
        fold=config.fold,
        sample_frac=sample_frac,
        seed=seed,
    )
    split_sizes = [len(loaded_split.y) for loaded_split in loaded_splits]
    split_caps = proportional_caps(split_sizes, max_rows_per_dataset)
    frames: Dict[str, pd.DataFrame] = {}
    for split_index, split_name in enumerate(SPLIT_NAMES):
        loaded_split = loaded_splits[split_index]
        features_matrix, labels = sample_split_rows(
            loaded_split.X,
            loaded_split.y,
            split_caps[split_index],
            seed + dataset_id * 100 + split_index,
        )
        frames[split_name] = split_to_frame(config.key, dataset_id, split_name, features_matrix, labels, loaded_split.feature_names)
    return frames


def write_outputs(output_root: Path, frames_by_split: Dict[str, List[pd.DataFrame]], metadata: Dict[str, Any], overwrite: bool) -> None:
    if output_root.exists() and not overwrite:
        raise SystemExit(f"Output root already exists. Use --overwrite to replace files: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    for split_name, frames in frames_by_split.items():
        split_dir = output_root / split_name
        split_dir.mkdir(parents=True, exist_ok=True)
        combined = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
        combined.to_parquet(split_dir / f"global_{split_name}.parquet", index=False)
        metadata["splits"][split_name] = {
            "rows": int(len(combined)),
            "attack_rows": int(combined["target_binary"].sum()) if not combined.empty else 0,
            "datasets": combined.groupby("dataset_name").size().astype(int).to_dict() if not combined.empty else {},
        }
    write_json(output_root / "metadata.json", metadata)
    write_json(output_root / "feature_columns.json", global_feature_columns())
    write_json(output_root / "dataset_map.json", metadata["dataset_map"])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare GLOBAL_BINARY_V1 dataset for the Global Transformer experiment.")
    parser.add_argument("--datasets", nargs="+", default=["all"])
    parser.add_argument("--output_root", default="src/models/GLOBAL_TRANSFORMER/datasets/GLOBAL_BINARY_V1")
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--max_rows_per_dataset", type=int, default=200_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--dry_run", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configs = selected_dataset_configs(args.datasets)
    dataset_map = dataset_id_map(configs)
    output_root = resolve_from_root(args.output_root)
    metadata: Dict[str, Any] = {
        "name": "GLOBAL_BINARY_V1",
        "task": "binary_attack_detection",
        "sample_frac": args.sample_frac,
        "max_rows_per_dataset": args.max_rows_per_dataset,
        "seed": args.seed,
        "feature_columns": global_feature_columns(),
        "dataset_map": dataset_map,
        "dataset_configs": {config.key: asdict(config) for config in configs},
        "splits": {},
    }
    if args.dry_run:
        print(json.dumps(metadata, ensure_ascii=False, indent=2))
        return

    frames_by_split: Dict[str, List[pd.DataFrame]] = {split_name: [] for split_name in SPLIT_NAMES}
    for config in configs:
        print(f"[prepare] {config.key} split={config.split_mode} dataset={config.dataset} fold={config.fold}")
        frames = prepare_dataset_config(
            config=config,
            dataset_id=dataset_map[config.key],
            sample_frac=args.sample_frac,
            max_rows_per_dataset=args.max_rows_per_dataset,
            seed=args.seed,
        )
        for split_name in SPLIT_NAMES:
            frames_by_split[split_name].append(frames[split_name])
            print(f"  {split_name}: {len(frames[split_name]):,} rows")

    write_outputs(output_root, frames_by_split, metadata, overwrite=args.overwrite)
    print("Saved:", output_root)


if __name__ == "__main__":
    main()