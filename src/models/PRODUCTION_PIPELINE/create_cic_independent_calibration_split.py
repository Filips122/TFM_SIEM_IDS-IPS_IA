#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import numpy as np
import pandas as pd


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_from_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root() / candidate).resolve()


def list_parquets(folder: Path) -> List[Path]:
    return sorted([path for path in folder.glob("*.parquet") if path.is_file()])


def scenario_key(path: Path) -> str:
    return path.name.split("__part", 1)[0]


def label_counts(path: Path) -> Dict[str, int]:
    target = pd.read_parquet(path, columns=["target"])["target"].astype(str)
    counts = target.value_counts().to_dict()
    return {str(key): int(value) for key, value in counts.items()}


def add_counts(left: Dict[str, int], right: Dict[str, int]) -> Dict[str, int]:
    out = dict(left)
    for key, value in right.items():
        out[key] = out.get(key, 0) + int(value)
    return out


def reset_dir(path: Path, overwrite: bool) -> None:
    if path.exists():
        if not overwrite:
            raise FileExistsError(f"Output folder exists: {path}. Use --overwrite.")
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def link_or_copy(src: Path, dst: Path, mode: str) -> str:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if mode == "hardlink":
        try:
            os.link(src, dst)
            return "hardlink"
        except OSError:
            shutil.copy2(src, dst)
            return "copy_fallback"
    shutil.copy2(src, dst)
    return "copy"


def split_test_files(paths: List[Path], calibration_ratio: float, seed: int) -> Tuple[List[Path], List[Path]]:
    rng = np.random.default_rng(seed)
    by_scenario: Dict[str, List[Path]] = {}
    for path in paths:
        by_scenario.setdefault(scenario_key(path), []).append(path)

    calibration: List[Path] = []
    holdout: List[Path] = []
    for _, scenario_paths in sorted(by_scenario.items()):
        scenario_paths = sorted(scenario_paths)
        indexes = np.arange(len(scenario_paths))
        rng.shuffle(indexes)
        n_calibration = int(round(len(scenario_paths) * calibration_ratio))
        if len(scenario_paths) > 1:
            n_calibration = max(1, min(n_calibration, len(scenario_paths) - 1))
        selected = set(indexes[:n_calibration].tolist())
        for index, path in enumerate(scenario_paths):
            if index in selected:
                calibration.append(path)
            else:
                holdout.append(path)
    return sorted(calibration), sorted(holdout)


def materialize_files(paths: Iterable[Path], output_dir: Path, mode: str) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    files: List[Dict[str, Any]] = []
    for src in paths:
        dst = output_dir / src.name
        operation = link_or_copy(src, dst, mode)
        current_counts = label_counts(src)
        counts = add_counts(counts, current_counts)
        files.append(
            {
                "source": str(src),
                "stored_as": str(dst),
                "operation": operation,
                "scenario": scenario_key(src),
                "counts": current_counts,
            }
        )
    return {"counts": counts, "files": files}


def copy_json_if_exists(src: Path, dst: Path) -> None:
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create an independent CIC sequence calibration/test split from existing day split parquets.")
    parser.add_argument("--source_mode", default="day")
    parser.add_argument("--target_mode", default="day_independent_calibration")
    parser.add_argument("--datasets_base", default="src/models/CIC-IDS2017/datasets")
    parser.add_argument("--task", default="binary")
    parser.add_argument("--calibration_ratio", type=float, default=0.30)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--file_mode", choices=["hardlink", "copy"], default="hardlink")
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not (0.0 < args.calibration_ratio < 1.0):
        raise ValueError("--calibration_ratio must be in (0, 1)")

    base = resolve_from_root(args.datasets_base) / "sequence"
    source_root = base / args.source_mode / "TrafficLabelling" / args.task
    target_root = base / args.target_mode / "TrafficLabelling" / args.task
    reset_dir(target_root, args.overwrite)

    source_train = list_parquets(source_root / "train")
    source_val = list_parquets(source_root / "val")
    source_test = list_parquets(source_root / "test")
    if not source_train or not source_val or not source_test:
        raise FileNotFoundError(f"Missing source split parquets under {source_root}")

    calibration_files, holdout_files = split_test_files(source_test, args.calibration_ratio, args.seed)
    manifest = {
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_mode": args.source_mode,
        "target_mode": args.target_mode,
        "task": args.task,
        "calibration_ratio": args.calibration_ratio,
        "seed": args.seed,
        "file_mode": args.file_mode,
        "splits": {
            "train": materialize_files(source_train, target_root / "train", args.file_mode),
            "val": materialize_files(source_val, target_root / "val", args.file_mode),
            "calibration": materialize_files(calibration_files, target_root / "calibration", args.file_mode),
            "test": materialize_files(holdout_files, target_root / "test", args.file_mode),
        },
        "notes": [
            "Calibration and test are disjoint whole parquet shards from the original Friday test split.",
            "Train and val are linked/copied from the original day split so future retraining can keep calibration independent.",
        ],
    }
    stats = {split: payload["counts"] for split, payload in manifest["splits"].items()}
    (target_root / "split_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (target_root / "sequence_stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    copy_json_if_exists(source_root / "sequence_meta.json", target_root / "sequence_meta.json")
    print("Saved:", target_root)
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()