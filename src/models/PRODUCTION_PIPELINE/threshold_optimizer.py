#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import importlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score


DATASET_CONFIGS: Dict[str, Dict[str, str]] = {
    "CIC-IDS2017": {
        "model_dir": "src/models/CIC-IDS2017",
        "datasets_base": "src/models/CIC-IDS2017/datasets",
        "dataset": "MachineLearningCVE",
        "default_split": "day",
    },
    "UNSW-NB15": {
        "model_dir": "src/models/UNSW-NB15",
        "datasets_base": "src/models/UNSW-NB15/datasets",
        "dataset": "NUSW-NB15",
        "default_split": "groupkfold",
    },
    "UGR16": {
        "model_dir": "src/models/UGR16",
        "datasets_base": "src/models/UGR16/datasets",
        "dataset": "UGR16_MARAPR_HYBRID",
        "default_split": "date",
    },
    "LAB-ALERTS": {
        "model_dir": "src/models/LAB-ALERTS",
        "datasets_base": "src/models/LAB-ALERTS/datasets",
        "dataset": "LAB-ALERTS",
        "default_split": "date",
    },
    "COWRIE_FULL": {
        "model_dir": "src/models/COWRIE_FULL",
        "datasets_base": "src/models/COWRIE_FULL/datasets",
        "dataset": "COWRIE_FULL",
        "default_split": "date",
    },
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_from_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root() / candidate).resolve()


def json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    if isinstance(value, np.ndarray):
        return json_ready(value.tolist())
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.floating):
        out = float(value)
        return out if np.isfinite(out) else None
    if isinstance(value, float):
        return value if np.isfinite(value) else None
    return value


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_ready(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(path: Path, rows: Iterable[Dict[str, Any]], columns: List[str]) -> None:
    import csv

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column) for column in columns})


def log(message: str) -> None:
    print(f"[threshold-optimizer] {message}", flush=True)


def load_dataset_module(model_dir: Path) -> Any:
    sys.path.insert(0, str(model_dir))
    if "data_loader" in sys.modules:
        del sys.modules["data_loader"]
    return importlib.import_module("data_loader")


def load_artifact_config(artifact_dir: Path) -> Dict[str, Any]:
    for name in ["hgb_config.json", "run_metadata.json"]:
        path = artifact_dir / name
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    return {}


def load_label_map(artifact_dir: Path) -> Dict[str, int]:
    path = artifact_dir / "label_map.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing label_map.json in {artifact_dir}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {str(label): int(index) for label, index in payload.items()}


def infer_run_config(args: argparse.Namespace, artifact_config: Dict[str, Any]) -> Dict[str, Any]:
    dataset_config = DATASET_CONFIGS[args.dataset_key]
    run_params = artifact_config.get("params", {})
    if "run_config" in artifact_config:
        run_params = artifact_config["run_config"]

    return {
        "model_dir": args.model_dir or dataset_config["model_dir"],
        "datasets_base": args.datasets_base or run_params.get("datasets_base") or dataset_config["datasets_base"],
        "dataset": args.dataset or run_params.get("dataset") or dataset_config["dataset"],
        "split_mode": args.split_mode or run_params.get("split_mode") or dataset_config["default_split"],
        "pipeline": args.pipeline or run_params.get("pipeline") or "binary",
        "fold": args.fold if args.fold is not None else run_params.get("fold"),
        "sample_frac": args.sample_frac,
        "seed": args.seed,
    }


def class_names_from_label_map(label_map: Dict[str, int]) -> List[str]:
    return [label for label, _ in sorted(label_map.items(), key=lambda item: item[1])]


def binary_targets(labels: np.ndarray, benign_label: str) -> np.ndarray:
    return (labels.astype(str) != benign_label).astype(int)


def attack_scores(proba: np.ndarray, class_names: List[str], benign_label: str, positive_label: str) -> np.ndarray:
    if positive_label != "__non_benign__":
        if positive_label not in class_names:
            raise ValueError(f"positive_label={positive_label} not present in classes: {class_names}")
        return proba[:, class_names.index(positive_label)]

    attack_indexes = [index for index, label in enumerate(class_names) if label != benign_label]
    if not attack_indexes:
        raise ValueError(f"No non-benign classes found in classes: {class_names}")
    return proba[:, attack_indexes].sum(axis=1)


def align_proba(model: Any, proba: np.ndarray, n_classes: int) -> np.ndarray:
    model_classes = np.asarray(getattr(model, "classes_", np.arange(proba.shape[1])), dtype=int)
    if proba.shape[1] == n_classes and np.array_equal(model_classes, np.arange(n_classes)):
        return proba

    aligned = np.zeros((proba.shape[0], n_classes), dtype=proba.dtype)
    for proba_index, class_index in enumerate(model_classes):
        if 0 <= int(class_index) < n_classes:
            aligned[:, int(class_index)] = proba[:, proba_index]
    return aligned


def score_split(model: Any, split: Any, class_names: List[str], benign_label: str, positive_label: str) -> Tuple[np.ndarray, np.ndarray]:
    if not hasattr(model, "predict_proba"):
        raise TypeError("threshold_optimizer currently expects a classifier with predict_proba")
    proba = align_proba(model, model.predict_proba(split.X.astype(np.float32)), len(class_names))
    scores = attack_scores(proba, class_names, benign_label, positive_label)
    y_true = binary_targets(split.y, benign_label)
    return y_true, scores


def metrics_at_threshold(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> Dict[str, Any]:
    y_pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "threshold": float(threshold),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "alert_rate": float(y_pred.mean()) if len(y_pred) else 0.0,
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "true_positive_rate": float(tp / (tp + fn)) if (tp + fn) else 0.0,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }


def sweep_thresholds(y_true: np.ndarray, scores: np.ndarray, thresholds: np.ndarray) -> List[Dict[str, Any]]:
    y_true = y_true.astype(int, copy=False)
    scores = scores.astype(float, copy=False)
    order = np.argsort(scores)
    scores_sorted = scores[order]
    y_sorted = y_true[order]

    total = int(len(y_true))
    total_pos = int(y_true.sum())
    total_neg = total - total_pos
    cumulative_pos = np.cumsum(y_sorted, dtype=np.int64)
    cumulative_neg = np.cumsum(1 - y_sorted, dtype=np.int64)

    rows: List[Dict[str, Any]] = []
    for threshold in thresholds:
        index = int(np.searchsorted(scores_sorted, threshold, side="left"))
        pos_below = int(cumulative_pos[index - 1]) if index > 0 else 0
        neg_below = int(cumulative_neg[index - 1]) if index > 0 else 0
        tp = total_pos - pos_below
        fp = total_neg - neg_below
        fn = pos_below
        tn = neg_below

        predicted_pos = tp + fp
        precision = float(tp / predicted_pos) if predicted_pos else 0.0
        recall = float(tp / total_pos) if total_pos else 0.0
        f1 = float((2.0 * precision * recall) / (precision + recall)) if (precision + recall) else 0.0
        rows.append(
            {
                "threshold": float(threshold),
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "accuracy": float((tp + tn) / total) if total else 0.0,
                "alert_rate": float(predicted_pos / total) if total else 0.0,
                "false_positive_rate": float(fp / total_neg) if total_neg else 0.0,
                "true_positive_rate": recall,
                "tp": int(tp),
                "fp": int(fp),
                "tn": int(tn),
                "fn": int(fn),
            }
        )
    return rows


def pick_best(rows: List[Dict[str, Any]], key: str = "f1") -> Dict[str, Any]:
    return max(rows, key=lambda row: (row[key], row["recall"], row["precision"], -row["threshold"]))


def pick_precision_target(rows: List[Dict[str, Any]], min_precision: float) -> Optional[Dict[str, Any]]:
    candidates = [row for row in rows if row["precision"] >= min_precision]
    if not candidates:
        return None
    return max(candidates, key=lambda row: (row["recall"], row["f1"], -row["alert_rate"]))


def pick_recall_target(rows: List[Dict[str, Any]], min_recall: float) -> Optional[Dict[str, Any]]:
    candidates = [row for row in rows if row["recall"] >= min_recall]
    if not candidates:
        return None
    return max(candidates, key=lambda row: (row["precision"], row["f1"], -row["alert_rate"]))


def pick_alert_budget(rows: List[Dict[str, Any]], max_alert_rate: Optional[float]) -> Optional[Dict[str, Any]]:
    if max_alert_rate is None:
        return None
    candidates = [row for row in rows if row["alert_rate"] <= max_alert_rate]
    if not candidates:
        return None
    return pick_best(candidates)


def split_warnings(split_name: str, y_true: np.ndarray, benign_label: str, class_names: List[str]) -> List[str]:
    warnings: List[str] = []
    if benign_label not in class_names:
        warnings.append(f"{split_name}: benign_label={benign_label} is absent from label_map/classes; binary non-benign metrics may be trivial")
    positives = int(y_true.sum())
    negatives = int(len(y_true) - positives)
    if positives == 0:
        warnings.append(f"{split_name}: no positive rows after binary mapping")
    if negatives == 0:
        warnings.append(f"{split_name}: no negative rows after binary mapping")
    return warnings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Optimize binary attack thresholds for production candidate models.")
    parser.add_argument("--artifact_dir", required=True, help="Directory containing model.joblib, label_map.json and hgb_config.json")
    parser.add_argument("--dataset_key", required=True, choices=sorted(DATASET_CONFIGS))
    parser.add_argument("--output_dir", default=None)
    parser.add_argument("--model_dir", default=None)
    parser.add_argument("--datasets_base", default=None)
    parser.add_argument("--dataset", default=None)
    parser.add_argument("--split_mode", default=None)
    parser.add_argument("--pipeline", default=None)
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--max_rows_per_split", type=int, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--benign_label", default="BENIGN")
    parser.add_argument("--positive_label", default="__non_benign__")
    parser.add_argument("--threshold_min", type=float, default=0.01)
    parser.add_argument("--threshold_max", type=float, default=0.99)
    parser.add_argument("--threshold_steps", type=int, default=99)
    parser.add_argument("--min_precision", type=float, default=0.90)
    parser.add_argument("--min_recall", type=float, default=0.90)
    parser.add_argument("--max_alert_rate", type=float, default=None)
    parser.add_argument("--dry_run", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    artifact_dir = resolve_from_root(args.artifact_dir)
    artifact_config = load_artifact_config(artifact_dir)
    run_config = infer_run_config(args, artifact_config)
    output_dir = resolve_from_root(args.output_dir) if args.output_dir else artifact_dir / "production_thresholds"

    model_path = artifact_dir / "model.joblib"
    if not model_path.exists() and not args.dry_run:
        raise FileNotFoundError(f"Missing model.joblib in {artifact_dir}")

    label_map = load_label_map(artifact_dir) if not args.dry_run else {args.benign_label: 0, "ATTACK": 1}
    class_names = class_names_from_label_map(label_map)

    if args.dry_run:
        payload = {
            "artifact_dir": str(artifact_dir),
            "output_dir": str(output_dir),
            "run_config": run_config,
            "class_names": class_names,
            "thresholds": [args.threshold_min, args.threshold_max, args.threshold_steps],
        }
        print(json.dumps(json_ready(payload), ensure_ascii=False, indent=2))
        return

    model_dir = resolve_from_root(run_config["model_dir"])
    log(f"loading data_loader from {model_dir}")
    data_loader = load_dataset_module(model_dir)
    log(f"loading model from {model_path}")
    model = joblib.load(model_path)

    load_split_func = data_loader.load_split
    load_split_kwargs: Dict[str, Any] = {}
    if args.max_rows_per_split is not None and hasattr(data_loader, "load_split_bounded"):
        load_split_func = data_loader.load_split_bounded
        load_split_kwargs["max_rows"] = args.max_rows_per_split

    log("loading validation split")
    val = load_split_func(
        datasets_base=run_config["datasets_base"],
        split_mode=run_config["split_mode"],
        dataset=run_config["dataset"],
        pipeline=run_config["pipeline"],
        split="val",
        fold=run_config["fold"],
        sample_frac=run_config["sample_frac"],
        seed=run_config["seed"],
        **load_split_kwargs,
    )
    log(f"validation rows={len(val.y)} features={len(val.feature_names)}")
    log("loading test split")
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
        **load_split_kwargs,
    )
    log(f"test rows={len(test.y)} features={len(test.feature_names)}")

    log("scoring validation split")
    y_val, val_scores = score_split(model, val, class_names, args.benign_label, args.positive_label)
    log("scoring test split")
    y_test, test_scores = score_split(model, test, class_names, args.benign_label, args.positive_label)
    warnings = split_warnings("val", y_val, args.benign_label, class_names) + split_warnings("test", y_test, args.benign_label, class_names)
    for warning in warnings:
        log(f"warning: {warning}")
    thresholds = np.linspace(args.threshold_min, args.threshold_max, args.threshold_steps)
    log(f"sweeping {len(thresholds)} thresholds")
    val_rows = sweep_thresholds(y_val, val_scores, thresholds)
    test_rows = sweep_thresholds(y_test, test_scores, thresholds)

    best_f1 = pick_best(val_rows)
    precision_target = pick_precision_target(val_rows, args.min_precision)
    recall_target = pick_recall_target(val_rows, args.min_recall)
    alert_budget = pick_alert_budget(val_rows, args.max_alert_rate)

    selected = {
        "best_f1": best_f1,
        f"precision_at_least_{args.min_precision:.2f}": precision_target,
        f"recall_at_least_{args.min_recall:.2f}": recall_target,
        "alert_budget": alert_budget,
    }
    selected_test = {
        name: metrics_at_threshold(y_test, test_scores, policy["threshold"]) if policy else None
        for name, policy in selected.items()
    }
    oracle_on_test = {
        "best_f1": pick_best(test_rows),
        f"precision_at_least_{args.min_precision:.2f}": pick_precision_target(test_rows, args.min_precision),
        f"recall_at_least_{args.min_recall:.2f}": pick_recall_target(test_rows, args.min_recall),
        "alert_budget": pick_alert_budget(test_rows, args.max_alert_rate),
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
    write_csv(output_dir / "threshold_sweep_val.csv", val_rows, columns)
    write_csv(output_dir / "threshold_sweep_test.csv", test_rows, columns)
    write_json(
        output_dir / "threshold_summary.json",
        {
            "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "artifact_dir": str(artifact_dir),
            "run_config": run_config,
            "class_names": class_names,
            "benign_label": args.benign_label,
            "positive_label": args.positive_label,
            "val_rows": int(len(y_val)),
            "val_attack_rows": int(y_val.sum()),
            "test_rows": int(len(y_test)),
            "test_attack_rows": int(y_test.sum()),
            "warnings": warnings,
            "selected_on_val": selected,
            "selected_thresholds_on_test": selected_test,
            "oracle_on_test": oracle_on_test,
        },
    )
    print("Saved:", output_dir)


if __name__ == "__main__":
    main()