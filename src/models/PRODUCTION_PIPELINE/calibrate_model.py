#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

try:
    from .model_registry import ModelRegistry, resolve_from_root
    from .threshold_optimizer import (
        DATASET_CONFIGS,
        attack_scores,
        class_names_from_label_map,
        load_dataset_module,
        load_label_map,
        log,
        metrics_at_threshold,
        pick_alert_budget,
        pick_best,
        pick_precision_target,
        pick_recall_target,
        score_split,
        split_warnings,
        sweep_thresholds,
        write_csv,
        write_json,
    )
except ImportError:  # pragma: no cover - direct script fallback
    from model_registry import ModelRegistry, resolve_from_root
    from threshold_optimizer import (
        DATASET_CONFIGS,
        attack_scores,
        class_names_from_label_map,
        load_dataset_module,
        load_label_map,
        log,
        metrics_at_threshold,
        pick_alert_budget,
        pick_best,
        pick_precision_target,
        pick_recall_target,
        score_split,
        split_warnings,
        sweep_thresholds,
        write_csv,
        write_json,
    )


def expected_calibration_error(y_true: np.ndarray, scores: np.ndarray, bins: int = 15) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = len(y_true)
    if total == 0:
        return 0.0
    ece = 0.0
    for left, right in zip(edges[:-1], edges[1:]):
        if right == 1.0:
            mask = (scores >= left) & (scores <= right)
        else:
            mask = (scores >= left) & (scores < right)
        count = int(mask.sum())
        if count == 0:
            continue
        confidence = float(scores[mask].mean())
        accuracy = float(y_true[mask].mean())
        ece += (count / total) * abs(confidence - accuracy)
    return float(ece)


def repo_relative(path: Path) -> str:
    root = resolve_from_root(".")
    try:
        return str(path.resolve().relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path.resolve())


def fit_calibrator(method: str, scores: np.ndarray, y_true: np.ndarray) -> Any:
    if method == "isotonic":
        calibrator = IsotonicRegression(out_of_bounds="clip")
        calibrator.fit(scores.astype(float), y_true.astype(int))
        return calibrator
    if method == "sigmoid":
        calibrator = LogisticRegression(max_iter=1000, solver="lbfgs")
        calibrator.fit(scores.reshape(-1, 1), y_true.astype(int))
        return calibrator
    raise ValueError(f"Unsupported calibration method: {method}")


def transform_calibrator(method: str, calibrator: Any, scores: np.ndarray) -> np.ndarray:
    if method == "isotonic":
        return np.asarray(calibrator.predict(scores.astype(float)), dtype=float)
    if method == "sigmoid":
        return np.asarray(calibrator.predict_proba(scores.reshape(-1, 1))[:, 1], dtype=float)
    raise ValueError(f"Unsupported calibration method: {method}")


def load_split_pair(spec: Any, sample_frac: Optional[float], max_rows_per_split: Optional[int], seed: int) -> Tuple[Any, Any, Dict[str, Any]]:
    config = DATASET_CONFIGS[spec.dataset_key]
    run_config = {
        "model_dir": config["model_dir"],
        "datasets_base": config["datasets_base"],
        "dataset": config["dataset"],
        "split_mode": spec.split_mode or config["default_split"],
        "pipeline": spec.pipeline,
        "fold": spec.fold,
        "sample_frac": sample_frac,
        "seed": seed,
    }
    data_loader = load_dataset_module(resolve_from_root(run_config["model_dir"]))
    load_split_func = data_loader.load_split
    extra_kwargs: Dict[str, Any] = {}
    if max_rows_per_split is not None and hasattr(data_loader, "load_split_bounded"):
        load_split_func = data_loader.load_split_bounded
        extra_kwargs["max_rows"] = max_rows_per_split

    val = load_split_func(
        datasets_base=run_config["datasets_base"],
        split_mode=run_config["split_mode"],
        dataset=run_config["dataset"],
        pipeline=run_config["pipeline"],
        split="val",
        fold=run_config["fold"],
        sample_frac=run_config["sample_frac"],
        seed=run_config["seed"],
        **extra_kwargs,
    )
    test = load_split_func(
        datasets_base=run_config["datasets_base"],
        split_mode=run_config["split_mode"],
        dataset=run_config["dataset"],
        pipeline=run_config["pipeline"],
        split="test",
        fold=run_config["fold"],
        sample_frac=run_config["sample_frac"],
        seed=run_config["seed"],
        feature_cols=val.feature_names,
        **extra_kwargs,
    )
    return val, test, run_config


def score_raw(model: Any, split: Any, class_names: List[str], benign_label: str, positive_label: str) -> Tuple[np.ndarray, np.ndarray]:
    return score_split(model, split, class_names, benign_label, positive_label)


def write_threshold_outputs(
    output_dir: Path,
    y_val: np.ndarray,
    val_scores: np.ndarray,
    y_test: np.ndarray,
    test_scores: np.ndarray,
    thresholds: np.ndarray,
    min_precision: float,
    min_recall: float,
    max_alert_rate: Optional[float],
    warnings: List[str],
    extra_summary: Dict[str, Any],
) -> Dict[str, Any]:
    val_rows = sweep_thresholds(y_val, val_scores, thresholds)
    test_rows = sweep_thresholds(y_test, test_scores, thresholds)
    selected = {
        "best_f1": pick_best(val_rows),
        f"precision_at_least_{min_precision:.2f}": pick_precision_target(val_rows, min_precision),
        f"recall_at_least_{min_recall:.2f}": pick_recall_target(val_rows, min_recall),
        "alert_budget": pick_alert_budget(val_rows, max_alert_rate),
    }
    selected_test = {
        name: metrics_at_threshold(y_test, test_scores, policy["threshold"]) if policy else None
        for name, policy in selected.items()
    }
    oracle_on_test = {
        "best_f1": pick_best(test_rows),
        f"precision_at_least_{min_precision:.2f}": pick_precision_target(test_rows, min_precision),
        f"recall_at_least_{min_recall:.2f}": pick_recall_target(test_rows, min_recall),
        "alert_budget": pick_alert_budget(test_rows, max_alert_rate),
    }
    columns = [
        "threshold",
        "precision",
        "recall",
        "f1",
        "accuracy",
        "alert_rate",
        "false_positive_rate",
        "true_positive_rate",
        "tp",
        "fp",
        "tn",
        "fn",
    ]
    threshold_dir = output_dir / "production_thresholds"
    write_csv(threshold_dir / "threshold_sweep_val.csv", val_rows, columns)
    write_csv(threshold_dir / "threshold_sweep_test.csv", test_rows, columns)
    summary = {
        **extra_summary,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "val_rows": int(len(y_val)),
        "val_attack_rows": int(y_val.sum()),
        "test_rows": int(len(y_test)),
        "test_attack_rows": int(y_test.sum()),
        "warnings": warnings,
        "selected_on_val": selected,
        "selected_thresholds_on_test": selected_test,
        "oracle_on_test": oracle_on_test,
    }
    write_json(threshold_dir / "threshold_summary.json", summary)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create calibrated production candidates from archived registry model specs.")
    parser.add_argument("--registry", default="src/models/PRODUCTION_PIPELINE/model_registry.example.json")
    parser.add_argument("--model_id", required=True)
    parser.add_argument("--method", choices=["isotonic", "sigmoid"], default="isotonic")
    parser.add_argument("--output_root", default="src/models/PRODUCTION_PIPELINE/calibration_runs")
    parser.add_argument("--run_id", default=None)
    parser.add_argument("--benign_label", default="BENIGN")
    parser.add_argument("--positive_label", default="__non_benign__")
    parser.add_argument("--threshold_min", type=float, default=0.01)
    parser.add_argument("--threshold_max", type=float, default=0.99)
    parser.add_argument("--threshold_steps", type=int, default=199)
    parser.add_argument("--min_precision", type=float, default=0.90)
    parser.add_argument("--min_recall", type=float, default=0.90)
    parser.add_argument("--max_alert_rate", type=float, default=None)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--max_rows_per_split", type=int, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    registry = ModelRegistry.from_json(args.registry)
    spec = registry.get(args.model_id)
    if "hgb" not in spec.model_type:
        raise SystemExit(f"Calibration script currently supports HGB/sklearn predict_proba models, got {spec.model_type}")

    source_dir = spec.resolved_artifact_dir(resolve_from_root("."))
    model_path = source_dir / "model.joblib"
    if not model_path.exists():
        raise FileNotFoundError(f"Missing model.joblib: {model_path}")

    label_map = load_label_map(source_dir)
    class_names = class_names_from_label_map(label_map)
    run_id = args.run_id or f"{time.strftime('%Y%m%d_%H%M%S')}_{args.method}"
    output_dir = resolve_from_root(args.output_root) / spec.model_id / run_id
    if output_dir.exists():
        if not args.overwrite:
            raise FileExistsError(f"Calibration output exists: {output_dir}. Use --overwrite.")
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    log(f"loading source model {model_path}")
    model = joblib.load(model_path)
    log("loading validation/test splits")
    val, test, run_config = load_split_pair(spec, args.sample_frac, args.max_rows_per_split, args.seed)
    log(f"val rows={len(val.y)} test rows={len(test.y)} features={len(val.feature_names)}")
    y_val, raw_val_scores = score_raw(model, val, class_names, args.benign_label, args.positive_label)
    y_test, raw_test_scores = score_raw(model, test, class_names, args.benign_label, args.positive_label)
    warnings = split_warnings("val", y_val, args.benign_label, class_names) + split_warnings("test", y_test, args.benign_label, class_names)
    for warning in warnings:
        log(f"warning: {warning}")

    log(f"fitting {args.method} calibrator")
    calibrator = fit_calibrator(args.method, raw_val_scores, y_val)
    cal_val_scores = np.clip(transform_calibrator(args.method, calibrator, raw_val_scores), 0.0, 1.0)
    cal_test_scores = np.clip(transform_calibrator(args.method, calibrator, raw_test_scores), 0.0, 1.0)

    shutil.copy2(model_path, output_dir / "model.joblib")
    shutil.copy2(source_dir / "label_map.json", output_dir / "label_map.json")
    joblib.dump(calibrator, output_dir / "calibrator.joblib")
    for optional_name in ["hgb_config.json", "run_metadata.json"]:
        optional_path = source_dir / optional_name
        if optional_path.exists():
            shutil.copy2(optional_path, output_dir / optional_name)

    thresholds = np.linspace(args.threshold_min, args.threshold_max, args.threshold_steps)
    calibration_summary = {
        "model_id": spec.model_id,
        "source_artifact_dir": str(source_dir),
        "calibrated_artifact_dir": str(output_dir),
        "method": args.method,
        "run_config": run_config,
        "class_names": class_names,
        "raw_val_ece": expected_calibration_error(y_val, raw_val_scores),
        "calibrated_val_ece": expected_calibration_error(y_val, cal_val_scores),
        "raw_test_ece": expected_calibration_error(y_test, raw_test_scores),
        "calibrated_test_ece": expected_calibration_error(y_test, cal_test_scores),
    }
    write_json(output_dir / "calibration_config.json", vars(args))
    write_json(output_dir / "calibration_summary.json", calibration_summary)
    threshold_summary = write_threshold_outputs(
        output_dir=output_dir,
        y_val=y_val,
        val_scores=cal_val_scores,
        y_test=y_test,
        test_scores=cal_test_scores,
        thresholds=thresholds,
        min_precision=args.min_precision,
        min_recall=args.min_recall,
        max_alert_rate=args.max_alert_rate,
        warnings=warnings,
        extra_summary={**calibration_summary, "score_type": "calibrated_probability"},
    )
    write_json(
        output_dir / "run_metadata.json",
        {
            "model_name": f"{spec.model_id}_{args.method}_calibrated",
            "split_mode": spec.split_mode,
            "run_id": run_id,
            "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_model_id": spec.model_id,
            "source_artifact_dir": str(source_dir),
        },
    )
    best = threshold_summary.get("selected_thresholds_on_test", {}).get("best_f1", {})
    calibrated_model_id = f"{spec.model_id}_{args.method}_calibrated_{run_id}"
    registry_entry = {
        "model_id": calibrated_model_id,
        "domain": spec.domain,
        "dataset_key": spec.dataset_key,
        "model_type": f"{spec.model_type}_calibrated_{args.method}",
        "artifact_dir": repo_relative(output_dir),
        "threshold": float(best.get("threshold", spec.threshold)) if isinstance(best, dict) else spec.threshold,
        "version": run_id,
        "status": "calibrated_candidate",
        "pipeline": spec.pipeline,
        "split_mode": spec.split_mode,
        "fold": spec.fold,
        "calibrator_path": repo_relative(output_dir / "calibrator.joblib"),
        "metrics_path": repo_relative(output_dir / "production_thresholds" / "threshold_summary.json"),
        "notes": [
            f"Calibrated from {spec.model_id} using {args.method}.",
            f"Raw test ECE={calibration_summary['raw_test_ece']:.6f}; calibrated test ECE={calibration_summary['calibrated_test_ece']:.6f}.",
        ],
    }
    write_json(output_dir / "model_registry_entry.json", registry_entry)
    write_json(output_dir / "model_registry.json", {"models": [registry_entry]})
    log(f"saved calibrated candidate: {output_dir}")
    if best:
        log(f"test best-F1 policy: threshold={best.get('threshold')} precision={best.get('precision')} recall={best.get('recall')} f1={best.get('f1')}")


if __name__ == "__main__":
    main()