#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

try:
    from .schemas import ModelSpec
except ImportError:  # pragma: no cover - direct script/local import fallback
    from schemas import ModelSpec


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_from_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root() / candidate).resolve()


class ModelRegistry:
    def __init__(self, specs: Iterable[ModelSpec]) -> None:
        self._specs: Dict[str, ModelSpec] = {spec.model_id: spec for spec in specs}

    @classmethod
    def from_json(cls, path: str | Path) -> "ModelRegistry":
        registry_path = resolve_from_root(path)
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
        models = payload.get("models", payload)
        if not isinstance(models, list):
            raise ValueError("Registry JSON must contain a list or a {'models': [...]} object")
        return cls(ModelSpec(**item) for item in models)

    def get(self, model_id: str) -> ModelSpec:
        try:
            return self._specs[model_id]
        except KeyError as exc:
            raise KeyError(f"Unknown model_id: {model_id}") from exc

    def find_by_domain(self, domain: str, status: Optional[str] = None) -> List[ModelSpec]:
        out = [spec for spec in self._specs.values() if spec.domain == domain]
        if status is not None:
            out = [spec for spec in out if spec.status == status]
        return sorted(out, key=lambda item: item.model_id)

    def find_by_dataset(self, dataset_key: str, status: Optional[str] = None) -> List[ModelSpec]:
        out = [spec for spec in self._specs.values() if spec.dataset_key == dataset_key]
        if status is not None:
            out = [spec for spec in out if spec.status == status]
        return sorted(out, key=lambda item: item.model_id)

    def to_dict(self) -> Dict[str, List[dict]]:
        return {"models": [spec.to_dict() for spec in sorted(self._specs.values(), key=lambda item: item.model_id)]}


def write_registry(path: str | Path, specs: Iterable[ModelSpec]) -> None:
    registry_path = resolve_from_root(path)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry = ModelRegistry(specs)
    registry_path.write_text(json.dumps(registry.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")