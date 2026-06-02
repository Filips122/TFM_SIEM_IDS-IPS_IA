#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .model_registry import resolve_from_root
except ImportError:  # pragma: no cover - direct script fallback
    from model_registry import resolve_from_root


def repo_relative(path: Path) -> str:
    root = resolve_from_root(".")
    try:
        return str(path.resolve().relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path.resolve())


def read_json(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return payload


def test_metrics(manifest: Dict[str, Any]) -> Dict[str, Any]:
    metrics = manifest.get("production_metrics", {})
    test = metrics.get("test", {}) if isinstance(metrics, dict) else {}
    return test if isinstance(test, dict) else {}


def numeric(value: Any, default: float = -1.0) -> float:
    return float(value) if isinstance(value, (int, float)) else default


def group_key(manifest: Dict[str, Any]) -> Tuple[str, str, str]:
    spec = manifest.get("model_spec", {})
    return (str(spec.get("domain")), str(spec.get("dataset_key")), str(spec.get("pipeline")))


def candidate_score(manifest: Dict[str, Any]) -> Tuple[float, float, float, float, int, int]:
    spec = manifest.get("model_spec", {})
    test = test_metrics(manifest)
    warnings = manifest.get("warnings", [])
    model_type = str(spec.get("model_type", ""))
    is_calibrated = 1 if "calibrated" in model_type else 0

    primary = numeric(test.get("f1"), numeric(test.get("macro_f1"), numeric(test.get("roc_auc"))))
    recall = numeric(test.get("recall"), numeric(test.get("macro_recall")))
    precision = numeric(test.get("precision"), 0.0)
    accuracy = numeric(test.get("accuracy"), 0.0)
    warning_count = len(warnings) if isinstance(warnings, list) else 0
    return (primary, recall, precision, accuracy, -warning_count, -is_calibrated)


def active_spec_from_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    spec = dict(manifest.get("model_spec", {}))
    archive_dir = Path(str(manifest.get("archive_dir")))
    spec["artifact_dir"] = repo_relative(archive_dir)
    spec["metrics_path"] = repo_relative(archive_dir / "manifest.json")
    notes = list(spec.get("notes") or [])
    notes.append("Selected from PRODUCTION_PIPELINE model_store by build_active_registry.py.")
    spec["notes"] = notes
    return spec


def load_active_policies(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        return {}
    payload = read_json(path)
    policies = payload.get("policies", [])
    if not isinstance(policies, list):
        raise ValueError(f"Policy registry must contain a policies list: {path}")
    active: Dict[str, Dict[str, Any]] = {}
    for entry in policies:
        if not isinstance(entry, dict) or not entry.get("active", True):
            continue
        model_id = str(entry.get("model_id", ""))
        policy_path = entry.get("policy_path")
        if not model_id or not policy_path:
            raise ValueError(f"Active policy entry requires model_id and policy_path: {entry}")
        policy_payload = read_json(resolve_from_root(str(policy_path)))
        active[model_id] = {"entry": entry, "payload": policy_payload}
    return active


def apply_active_policy(spec: Dict[str, Any], policy_info: Optional[Dict[str, Any]]) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    if policy_info is None:
        return spec, None
    out = dict(spec)
    entry = policy_info["entry"]
    payload = policy_info["payload"]
    policy_path = str(entry["policy_path"])
    out["threshold"] = float(payload["threshold"])
    out["policy_path"] = policy_path
    if entry.get("status_override"):
        out["status"] = str(entry["status_override"])
    notes = list(out.get("notes") or [])
    notes.append(f"Active policy: {payload.get('policy_id')} ({policy_path}).")
    for note in entry.get("notes", []):
        notes.append(str(note))
    out["notes"] = notes
    return out, payload


def write_markdown(path: Path, selections: List[Dict[str, Any]]) -> None:
    lines = ["# Active Production Model Registry", "", "Generated from archived model_store manifests.", ""]
    columns = ["domain", "dataset_key", "pipeline", "model_id", "version", "status", "threshold", "precision", "recall", "f1", "macro_f1", "roc_auc", "policy_path", "warning_count"]
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("| " + " | ".join(["---"] * len(columns)) + " |")
    for item in selections:
        spec = item["spec"]
        test = item.get("policy_metrics") or item["test"]
        warnings = item["manifest"].get("warnings", [])
        row = {
            "domain": spec.get("domain"),
            "dataset_key": spec.get("dataset_key"),
            "pipeline": spec.get("pipeline"),
            "model_id": spec.get("model_id"),
            "version": spec.get("version"),
            "status": spec.get("status"),
            "threshold": spec.get("threshold"),
            "precision": test.get("precision"),
            "recall": test.get("recall"),
            "f1": test.get("f1"),
            "macro_f1": test.get("macro_f1"),
            "roc_auc": test.get("roc_auc"),
            "policy_path": spec.get("policy_path"),
            "warning_count": len(warnings) if isinstance(warnings, list) else 0,
        }
        lines.append("| " + " | ".join(format_value(row.get(column)) for column in columns) + " |")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def format_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build active production registry from archived model_store manifests.")
    parser.add_argument("--model_store", default="src/models/PRODUCTION_PIPELINE/model_store")
    parser.add_argument("--policy_registry", default="src/models/PRODUCTION_PIPELINE/policy_registry.active.json")
    parser.add_argument("--output", default="src/models/PRODUCTION_PIPELINE/active_model_registry.json")
    parser.add_argument("--summary", default="src/models/PRODUCTION_PIPELINE/active_model_registry.md")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    model_store = resolve_from_root(args.model_store)
    active_policies = load_active_policies(resolve_from_root(args.policy_registry))
    manifests = [read_json(path) for path in sorted(model_store.glob("*/*/manifest.json"))]
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for manifest in manifests:
        grouped.setdefault(group_key(manifest), []).append(manifest)

    selections: List[Dict[str, Any]] = []
    for key, candidates in sorted(grouped.items()):
        selected = max(candidates, key=candidate_score)
        spec = active_spec_from_manifest(selected)
        spec, policy_payload = apply_active_policy(spec, active_policies.get(str(spec.get("model_id"))))
        policy_metrics = policy_payload.get("holdout_test_metrics") if policy_payload else None
        selections.append({"key": key, "manifest": selected, "spec": spec, "test": test_metrics(selected), "policy_metrics": policy_metrics})

    output = resolve_from_root(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"models": [item["spec"] for item in selections]}, ensure_ascii=False, indent=2), encoding="utf-8")
    write_markdown(resolve_from_root(args.summary), selections)
    print("Saved:", output)
    print("Saved:", resolve_from_root(args.summary))


if __name__ == "__main__":
    main()