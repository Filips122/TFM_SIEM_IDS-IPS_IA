#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from .model_registry import ModelRegistry, resolve_from_root
    from .risk_scoring import risk_score, severity_from_score
except ImportError:  # pragma: no cover - direct script fallback
    from model_registry import ModelRegistry, resolve_from_root
    from risk_scoring import risk_score, severity_from_score


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_json(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    payload = json.loads(resolve_from_root(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return payload


def build_siem_event(
    model_spec: Any,
    probability_attack: float,
    threshold: Optional[float] = None,
    entity_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    ids_severity: float = 0.0,
    asset_criticality: float = 0.0,
    correlation_score: float = 0.0,
    source_event: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    selected_threshold = float(model_spec.threshold if threshold is None else threshold)
    predicted_attack = probability_attack >= selected_threshold
    score = risk_score(
        probability_attack=probability_attack,
        ids_severity=ids_severity,
        asset_criticality=asset_criticality,
        correlation_score=correlation_score,
    )
    event: Dict[str, Any] = {
        "@timestamp": timestamp or now_utc(),
        "event": {
            "kind": "alert" if predicted_attack else "event",
            "category": ["intrusion_detection"],
            "type": ["info" if not predicted_attack else "indicator"],
            "module": "production_ml_pipeline",
            "dataset": model_spec.dataset_key,
        },
        "ml": {
            "model_id": model_spec.model_id,
            "model_version": model_spec.version,
            "model_type": model_spec.model_type,
            "domain": model_spec.domain,
            "policy_path": getattr(model_spec, "policy_path", None),
            "score": float(probability_attack),
            "threshold": selected_threshold,
            "prediction": "attack" if predicted_attack else "benign",
            "risk_score": score,
            "severity": severity_from_score(score),
        },
        "rule": {
            "name": f"ML detection - {model_spec.domain}",
            "category": "machine_learning",
            "description": "Production pipeline model decision exported for SIEM correlation.",
        },
        "labels": {
            "production_status": model_spec.status,
            "pipeline": model_spec.pipeline,
            "split_mode": str(model_spec.split_mode),
        },
    }
    if entity_id:
        event["related"] = {"hosts": [entity_id]}
        event["entity"] = {"id": entity_id}
    if source_event:
        event["source_event"] = source_event
    return event


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export a production model decision as SIEM-friendly JSON.")
    parser.add_argument("--registry", default="src/models/PRODUCTION_PIPELINE/active_model_registry.json")
    parser.add_argument("--model_id", required=True)
    parser.add_argument("--probability_attack", type=float, required=True)
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--entity_id", default=None)
    parser.add_argument("--timestamp", default=None)
    parser.add_argument("--ids_severity", type=float, default=0.0)
    parser.add_argument("--asset_criticality", type=float, default=0.0)
    parser.add_argument("--correlation_score", type=float, default=0.0)
    parser.add_argument("--source_event_json", default=None)
    parser.add_argument("--output", default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    registry = ModelRegistry.from_json(args.registry)
    model_spec = registry.get(args.model_id)
    event = build_siem_event(
        model_spec=model_spec,
        probability_attack=args.probability_attack,
        threshold=args.threshold,
        entity_id=args.entity_id,
        timestamp=args.timestamp,
        ids_severity=args.ids_severity,
        asset_criticality=args.asset_criticality,
        correlation_score=args.correlation_score,
        source_event=load_json(args.source_event_json),
    )
    payload = json.dumps(event, ensure_ascii=False, indent=2)
    if args.output:
        path = resolve_from_root(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload + "\n", encoding="utf-8")
        print("Saved:", path)
    else:
        print(payload)


if __name__ == "__main__":
    main()