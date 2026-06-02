#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ModelSpec:
    model_id: str
    domain: str
    dataset_key: str
    model_type: str
    artifact_dir: str
    threshold: float = 0.5
    version: str = "unknown"
    status: str = "candidate"
    pipeline: str = "binary"
    split_mode: Optional[str] = None
    fold: Optional[int] = None
    calibrator_path: Optional[str] = None
    policy_path: Optional[str] = None
    metrics_path: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def resolved_artifact_dir(self, repo_root: Path) -> Path:
        path = Path(self.artifact_dir).expanduser()
        return path.resolve() if path.is_absolute() else (repo_root / path).resolve()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ThresholdPolicy:
    threshold: float
    objective: str
    precision: float
    recall: float
    f1: float
    accuracy: float
    alert_rate: float
    false_positive_rate: float
    true_positive_rate: float
    tp: int
    fp: int
    tn: int
    fn: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DetectionDecision:
    model_id: str
    domain: str
    dataset_key: str
    prediction: str
    probability_attack: float
    threshold: float
    risk_score: int
    severity: str
    explanation: str
    entity_id: Optional[str] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)