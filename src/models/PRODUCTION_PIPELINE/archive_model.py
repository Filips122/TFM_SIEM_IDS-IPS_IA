#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from .model_registry import ModelRegistry, resolve_from_root
    from .schemas import ModelSpec
except ImportError:  # pragma: no cover - direct script fallback
    from model_registry import ModelRegistry, resolve_from_root
    from schemas import ModelSpec


MODEL_FILENAMES = ["model.joblib", "best_model.pt", "model.pt", "standardizer.npz", "calibrator.joblib", "x_mean.npy", "x_std.npy"]
METADATA_FILENAMES = [
    "label_map.json",
    "hgb_config.json",
    "isoforest_config.json",
    "run_metadata.json",
    "results.json",
    "calibration_config.json",
    "calibration_summary.json",
    "history.json",
    "history.csv",
    "unseen_classes_warning.json",
    "early_stopping_warning.json",
]
METRIC_FILENAMES = ["metrics_train.json", "metrics_val.json", "metrics_test.json", "summary.json"]
THRESHOLD_DIRS = ["production_thresholds"]


def json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_ready(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_file(src: Path, dst: Path) -> Dict[str, Any]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return {
        "source": str(src),
        "stored_as": str(dst),
        "bytes": int(dst.stat().st_size),
        "sha256": file_sha256(dst),
    }


def copy_optional_files(source_dir: Path, archive_dir: Path, filenames: Iterable[str], subdir: str) -> List[Dict[str, Any]]:
    copied: List[Dict[str, Any]] = []
    for filename in filenames:
        src = source_dir / filename
        if src.exists() and src.is_file():
            copied.append(copy_file(src, archive_dir / subdir / filename))
    return copied


def copy_optional_dirs(source_dir: Path, archive_dir: Path, dirnames: Iterable[str], subdir: str) -> List[Dict[str, Any]]:
    copied: List[Dict[str, Any]] = []
    for dirname in dirnames:
        src = source_dir / dirname
        if not src.exists() or not src.is_dir():
            continue
        dst = archive_dir / subdir / dirname
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        files = [path for path in dst.rglob("*") if path.is_file()]
        copied.append(
            {
                "source": str(src),
                "stored_as": str(dst),
                "file_count": len(files),
                "bytes": int(sum(path.stat().st_size for path in files)),
            }
        )
    return copied


def read_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else None


def extract_threshold_summary(archive_dir: Path) -> Dict[str, Any]:
    summary_path = archive_dir / "thresholds" / "production_thresholds" / "threshold_summary.json"
    payload = read_json_if_exists(summary_path)
    if not payload:
        return {}

    selected = payload.get("selected_thresholds_on_test", {})
    best_f1 = selected.get("best_f1") if isinstance(selected, dict) else None
    oracle = payload.get("oracle_on_test", {})
    oracle_best = oracle.get("best_f1") if isinstance(oracle, dict) else None
    return {
        "source": str(summary_path),
        "policy": "best_f1_selected_on_val_applied_to_test",
        "test": best_f1 or {},
        "oracle_test_best_f1": oracle_best or {},
        "warnings": payload.get("warnings", []),
        "val_rows": payload.get("val_rows"),
        "val_attack_rows": payload.get("val_attack_rows"),
        "test_rows": payload.get("test_rows"),
        "test_attack_rows": payload.get("test_attack_rows"),
    }


def extract_static_metrics(archive_dir: Path) -> Dict[str, Any]:
    metrics_path = archive_dir / "metrics" / "metrics_test.json"
    payload = read_json_if_exists(metrics_path)
    if payload:
        return {"source": str(metrics_path), "test": payload}

    results_path = archive_dir / "metadata" / "results.json"
    results = read_json_if_exists(results_path)
    if results and isinstance(results.get("test"), dict):
        return {"source": str(results_path), "test": results["test"]}
    return {}


def archive_one(spec: ModelSpec, output_root: Path, overwrite: bool) -> Dict[str, Any]:
    source_dir = spec.resolved_artifact_dir(resolve_from_root("."))
    archive_dir = output_root / spec.model_id / spec.version
    warnings: List[str] = []
    if archive_dir.exists():
        if not overwrite:
            raise FileExistsError(f"Archive already exists: {archive_dir}. Use --overwrite to replace it.")
        shutil.rmtree(archive_dir)
    archive_dir.mkdir(parents=True, exist_ok=True)

    if not source_dir.exists():
        warnings.append(f"source_artifact_dir does not exist: {source_dir}")

    copied_model_files = copy_optional_files(source_dir, archive_dir, MODEL_FILENAMES, "model") if source_dir.exists() else []
    copied_metadata = copy_optional_files(source_dir, archive_dir, METADATA_FILENAMES, "metadata") if source_dir.exists() else []
    copied_metrics = copy_optional_files(source_dir, archive_dir, METRIC_FILENAMES, "metrics") if source_dir.exists() else []
    copied_thresholds = copy_optional_dirs(source_dir, archive_dir, THRESHOLD_DIRS, "thresholds") if source_dir.exists() else []

    if not copied_model_files:
        warnings.append("no model artifact copied; expected one of model.joblib, best_model.pt, model.pt")

    threshold_metrics = extract_threshold_summary(archive_dir)
    static_metrics = extract_static_metrics(archive_dir)
    production_metrics = threshold_metrics or static_metrics
    warnings.extend(threshold_metrics.get("warnings", []))

    manifest = {
        "model_spec": spec.to_dict(),
        "archived_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_artifact_dir": str(source_dir),
        "archive_dir": str(archive_dir),
        "copied_files": {
            "model": copied_model_files,
            "metadata": copied_metadata,
            "metrics": copied_metrics,
            "thresholds": copied_thresholds,
        },
        "production_metrics": production_metrics,
        "warnings": warnings,
    }
    write_json(archive_dir / "manifest.json", manifest)
    return manifest


def build_archive_index(output_root: Path) -> Dict[str, Any]:
    manifests: List[Dict[str, Any]] = []
    for manifest_path in sorted(output_root.glob("*/*/manifest.json")):
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifests.append(payload)
    return {
        "indexed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "count": len(manifests),
        "models": manifests,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Archive production candidate models and evaluation outputs into PRODUCTION_PIPELINE/model_store.")
    parser.add_argument("--registry", default="src/models/PRODUCTION_PIPELINE/model_registry.example.json")
    parser.add_argument("--model_id", action="append", default=None, help="Archive only selected model_id. Can be repeated.")
    parser.add_argument("--output_root", default="src/models/PRODUCTION_PIPELINE/model_store")
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    registry = ModelRegistry.from_json(args.registry)
    specs = [registry.get(model_id) for model_id in args.model_id] if args.model_id else [ModelSpec(**item) for item in registry.to_dict()["models"]]
    output_root = resolve_from_root(args.output_root)
    for spec in specs:
        manifest = archive_one(spec, output_root, overwrite=args.overwrite)
        print(f"Archived {spec.model_id} -> {manifest['archive_dir']}")
    write_json(output_root / "archive_index.json", build_archive_index(output_root))
    print("Index:", output_root / "archive_index.json")


if __name__ == "__main__":
    main()