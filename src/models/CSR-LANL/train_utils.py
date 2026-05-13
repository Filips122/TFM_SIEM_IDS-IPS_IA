#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import random
import time
from pathlib import Path
from typing import Dict, Optional

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


def artifacts_root(model_name: str, split_mode: str, run_id: Optional[str] = None) -> Path:
    run_id = run_id or now_run_id()
    root = resolve_from_root(f"src/models/CSR-LANL/artifacts/{model_name}/{split_mode}/{run_id}")
    ensure_dir(root)
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