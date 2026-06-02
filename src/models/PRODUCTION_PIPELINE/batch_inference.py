#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import joblib
import numpy as np

try:
    from .model_registry import ModelRegistry, resolve_from_root
    from .siem_export import build_siem_event
    from .threshold_optimizer import (
        DATASET_CONFIGS,
        align_proba,
        attack_scores,
        binary_targets,
        class_names_from_label_map,
        load_dataset_module,
        metrics_at_threshold,
        split_warnings,
        write_json,
    )
except ImportError:  # pragma: no cover - direct script fallback
    from model_registry import ModelRegistry, resolve_from_root
    from siem_export import build_siem_event
    from threshold_optimizer import (
        DATASET_CONFIGS,
        align_proba,
        attack_scores,
        binary_targets,
        class_names_from_label_map,
        load_dataset_module,
        metrics_at_threshold,
        split_warnings,
        write_json,
    )


def now_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.gmtime())


def log(message: str) -> None:
    print(f"[batch-inference] {message}", flush=True)


def first_existing(base: Path, candidates: Iterable[str]) -> Optional[Path]:
    for candidate in candidates:
        path = base / candidate
        if path.exists():
            return path
    return None


def load_label_map(path: Path) -> Dict[str, int]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {str(label): int(index) for label, index in payload.items()}


def find_model_files(spec: Any) -> Tuple[Path, Path, Optional[Path]]:
    artifact_dir = spec.resolved_artifact_dir(resolve_from_root("."))
    model_path = first_existing(artifact_dir, ["model/model.joblib", "model.joblib"])
    label_map_path = first_existing(artifact_dir, ["metadata/label_map.json", "label_map.json"])
    calibrator_path = first_existing(artifact_dir, ["model/calibrator.joblib", "calibrator.joblib"])
    if calibrator_path is None and spec.calibrator_path:
        external = resolve_from_root(spec.calibrator_path)
        calibrator_path = external if external.exists() else None
    if model_path is None:
        raise FileNotFoundError(f"Missing model.joblib under {artifact_dir}")
    if label_map_path is None:
        raise FileNotFoundError(f"Missing label_map.json under {artifact_dir}")
    return model_path, label_map_path, calibrator_path


def load_dataset_split(spec: Any, split: str, sample_frac: Optional[float], max_rows_per_split: Optional[int], seed: int) -> Any:
    if spec.dataset_key not in DATASET_CONFIGS:
        raise ValueError(f"Unsupported dataset_key for batch inference: {spec.dataset_key}")
    if "hgb" not in spec.model_type:
        raise ValueError(f"batch_inference.py currently supports HGB/sklearn artifacts, got {spec.model_type}")
    if spec.pipeline.startswith("sequence") or spec.pipeline.startswith("anomaly"):
        raise ValueError(f"Pipeline {spec.pipeline} requires a dedicated adapter")

    config = DATASET_CONFIGS[spec.dataset_key]
    data_loader = load_dataset_module(resolve_from_root(config["model_dir"]))
    load_split_func = data_loader.load_split
    extra_kwargs: Dict[str, Any] = {}
    if max_rows_per_split is not None and hasattr(data_loader, "load_split_bounded"):
        load_split_func = data_loader.load_split_bounded
        extra_kwargs["max_rows"] = max_rows_per_split

    loaded = load_split_func(
        datasets_base=config["datasets_base"],
        split_mode=spec.split_mode or config["default_split"],
        dataset=config["dataset"],
        pipeline=spec.pipeline,
        split=split,
        fold=spec.fold,
        sample_frac=sample_frac,
        seed=seed,
        **extra_kwargs,
    )
    if max_rows_per_split is not None and not hasattr(data_loader, "load_split_bounded") and len(loaded.y) > max_rows_per_split:
        indexes = np.random.default_rng(seed).choice(len(loaded.y), size=max_rows_per_split, replace=False)
        indexes.sort()
        loaded.X = loaded.X[indexes]
        loaded.y = loaded.y[indexes]
    return loaded


def transform_calibrator(calibrator: Any, scores: np.ndarray) -> np.ndarray:
    if hasattr(calibrator, "predict_proba"):
        calibrated = calibrator.predict_proba(scores.reshape(-1, 1))[:, 1]
    elif hasattr(calibrator, "predict"):
        calibrated = calibrator.predict(scores.astype(float))
    else:
        raise TypeError(f"Unsupported calibrator type: {type(calibrator)!r}")
    return np.clip(np.asarray(calibrated, dtype=float), 0.0, 1.0)


def score_model(
    model: Any,
    split: Any,
    class_names: List[str],
    benign_label: str,
    positive_label: str,
    calibrator: Optional[Any],
) -> Tuple[np.ndarray, np.ndarray]:
    proba = align_proba(model, model.predict_proba(split.X.astype(np.float32)), len(class_names))
    raw_scores = attack_scores(proba, class_names, benign_label, positive_label)
    scores = transform_calibrator(calibrator, raw_scores) if calibrator is not None else raw_scores
    y_true = binary_targets(split.y, benign_label)
    return y_true, scores


def default_outputs(model_id: str, split: str, run_id: str) -> Tuple[Path, Path]:
    base = resolve_from_root("src/models/PRODUCTION_PIPELINE/inference_runs") / model_id / run_id
    return base / f"{split}_events.jsonl", base / f"{split}_summary.json"


def write_events_jsonl(
    path: Path,
    spec: Any,
    scores: np.ndarray,
    y_true: np.ndarray,
    threshold: float,
    split: str,
    include_benign: bool,
    max_events: Optional[int],
    ids_severity: float,
    asset_criticality: float,
    correlation_score: float,
) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with path.open("w", encoding="utf-8") as handle:
        for row_index, score in enumerate(scores):
            predicted_attack = float(score) >= threshold
            if not include_benign and not predicted_attack:
                continue
            if max_events is not None and written >= max_events:
                break
            event = build_siem_event(
                model_spec=spec,
                probability_attack=float(score),
                threshold=threshold,
                entity_id=f"{spec.dataset_key}:{split}:{row_index}",
                ids_severity=ids_severity,
                asset_criticality=asset_criticality,
                correlation_score=correlation_score,
                source_event={
                    "split": split,
                    "row_index": int(row_index),
                    "y_true_binary": int(y_true[row_index]),
                },
            )
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            written += 1
    return written


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run batch inference for active HGB/sklearn production models and export SIEM JSONL.")
    parser.add_argument("--registry", default="src/models/PRODUCTION_PIPELINE/active_model_registry.json")
    parser.add_argument("--model_id", required=True)
    parser.add_argument("--split", choices=["train", "val", "test"], default="test")
    parser.add_argument("--output_jsonl", default=None)
    parser.add_argument("--summary_output", default=None)
    parser.add_argument("--run_id", default=None)
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--benign_label", default="BENIGN")
    parser.add_argument("--positive_label", default="__non_benign__")
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--max_rows_per_split", type=int, default=None)
    parser.add_argument("--max_events", type=int, default=1000)
    parser.add_argument("--include_benign", action="store_true")
    parser.add_argument("--ids_severity", type=float, default=0.0)
    parser.add_argument("--asset_criticality", type=float, default=0.0)
    parser.add_argument("--correlation_score", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    registry = ModelRegistry.from_json(args.registry)
    spec = registry.get(args.model_id)
    threshold = float(spec.threshold if args.threshold is None else args.threshold)
    run_id = args.run_id or now_id()
    output_jsonl, summary_output = default_outputs(spec.model_id, args.split, run_id)
    if args.output_jsonl:
        output_jsonl = resolve_from_root(args.output_jsonl)
    if args.summary_output:
        summary_output = resolve_from_root(args.summary_output)

    model_path, label_map_path, calibrator_path = find_model_files(spec)
    log(f"loading model {model_path}")
    model = joblib.load(model_path)
    calibrator = joblib.load(calibrator_path) if calibrator_path is not None else None
    if calibrator_path is not None:
        log(f"using calibrator {calibrator_path}")

    label_map = load_label_map(label_map_path)
    class_names = class_names_from_label_map(label_map)
    log(f"loading {spec.dataset_key} split={args.split}")
    split = load_dataset_split(spec, args.split, args.sample_frac, args.max_rows_per_split, args.seed)
    y_true, scores = score_model(model, split, class_names, args.benign_label, args.positive_label, calibrator)
    metrics = metrics_at_threshold(y_true, scores, threshold)
    warnings = split_warnings(args.split, y_true, args.benign_label, class_names)
    written = write_events_jsonl(
        path=output_jsonl,
        spec=spec,
        scores=scores,
        y_true=y_true,
        threshold=threshold,
        split=args.split,
        include_benign=args.include_benign,
        max_events=args.max_events,
        ids_severity=args.ids_severity,
        asset_criticality=args.asset_criticality,
        correlation_score=args.correlation_score,
    )
    summary = {
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_id": spec.model_id,
        "dataset_key": spec.dataset_key,
        "domain": spec.domain,
        "split": args.split,
        "run_id": run_id,
        "rows_scored": int(len(y_true)),
        "events_written": int(written),
        "events_path": str(output_jsonl),
        "threshold": threshold,
        "score_type": "calibrated_probability" if calibrator is not None else "raw_probability",
        "class_names": class_names,
        "metrics": metrics,
        "warnings": warnings,
    }
    write_json(summary_output, summary)
    log(f"events written={written} path={output_jsonl}")
    log(f"summary saved={summary_output}")


if __name__ == "__main__":
    main()