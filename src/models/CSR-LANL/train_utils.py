#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import random
import time
from pathlib import Path
from typing import Any, Dict, Optional

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
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json_optional(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def dataset_profile_path(datasets_base: str | Path, split_mode: str, dataset: str, fold: Optional[int] = None) -> Path:
    base = resolve_from_root(datasets_base) / split_mode / dataset
    if split_mode == "groupkfold" and fold is not None:
        return base / f"fold_{fold}" / "dataset_profile.json"
    return base / "dataset_profile.json"


def dataset_profile_reference(datasets_base: str | Path, split_mode: str, dataset: str, fold: Optional[int] = None) -> Dict[str, Any]:
    path = dataset_profile_path(datasets_base, split_mode, dataset, fold)
    profile = read_json_optional(path)
    if profile is None:
        return {"status": "missing", "path": str(path), "fold": fold}
    config = profile.get("config", {}) if isinstance(profile, dict) else {}
    return {
        "status": "ok",
        "path": str(path),
        "dataset": profile.get("dataset"),
        "sampling_profile": profile.get("sampling_profile"),
        "split_mode": config.get("split_mode"),
        "source_set": config.get("source_set"),
        "window_seconds": config.get("window_seconds"),
        "redteam_window_hours": config.get("redteam_window_hours"),
        "config_fingerprint": profile.get("config_fingerprint"),
        "fold": fold,
    }


def save_dataset_profile_ref(root: Path, datasets_base: str | Path, split_mode: str, dataset: str, fold: Optional[int] = None) -> Dict[str, Any]:
    ref = dataset_profile_reference(datasets_base, split_mode, dataset, fold)
    save_json(root / "dataset_profile_ref.json", ref)
    return ref


def save_run_metadata(root: Path, model_name: str, split_mode: str, run_id: str, dataset: str = "CSR-LANL") -> None:
    save_json(
        root / "run_metadata.json",
        {
            "dataset": dataset,
            "model_name": model_name,
            "split_mode": split_mode,
            "run_id": run_id,
            "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "artifact_root": str(root),
        },
    )


def artifacts_root(model_name: str, split_mode: str, run_id: Optional[str] = None) -> Path:
    run_id = run_id or now_run_id()
    root = resolve_from_root(f"src/models/CSR-LANL/artifacts/{model_name}/{split_mode}/{run_id}")
    ensure_dir(root)
    save_run_metadata(root, model_name, split_mode, run_id)
    return root


def fit_label_encoder(y_train: np.ndarray) -> LabelEncoder:
    encoder = LabelEncoder()
    encoder.fit(y_train.astype(str))
    classes = list(map(str, encoder.classes_))
    if len(classes) == 2 and "BENIGN" in classes and "ATTACK" in classes:
        encoder.classes_ = np.array(["BENIGN", "ATTACK"], dtype=encoder.classes_.dtype)
    return encoder


def save_label_encoder(path: Path, encoder: LabelEncoder) -> Dict[str, int]:
    mapping = {str(label): int(index) for index, label in enumerate(encoder.classes_)}
    save_json(path / "label_map.json", mapping)
    return mapping


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)