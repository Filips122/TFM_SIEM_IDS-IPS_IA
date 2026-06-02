#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import importlib
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


DATASET_CONFIGS: Dict[str, Dict[str, str]] = {
    "CIC-IDS2017": {
        "model_dir": "src/models/CIC-IDS2017",
        "datasets_base": "src/models/CIC-IDS2017/datasets",
        "dataset": "TrafficLabelling",
        "default_split": "day",
        "artifact_prefix": "CIC_IDS2017",
    },
    "UNSW-NB15": {
        "model_dir": "src/models/UNSW-NB15",
        "datasets_base": "src/models/UNSW-NB15/datasets",
        "dataset": "NUSW-NB15",
        "default_split": "groupkfold",
        "artifact_prefix": "UNSW_NB15",
    },
    "UGR16": {
        "model_dir": "src/models/UGR16",
        "datasets_base": "src/models/UGR16/datasets",
        "dataset": "UGR16_MARAPR_HYBRID",
        "default_split": "date",
        "artifact_prefix": "UGR16",
    },
    "LAB-ALERTS": {
        "model_dir": "src/models/LAB-ALERTS",
        "datasets_base": "src/models/LAB-ALERTS/datasets",
        "dataset": "LAB-ALERTS",
        "default_split": "date",
        "artifact_prefix": "LAB_ALERTS",
    },
    "COWRIE_FULL": {
        "model_dir": "src/models/COWRIE_FULL",
        "datasets_base": "src/models/COWRIE_FULL/datasets",
        "dataset": "COWRIE_FULL",
        "default_split": "date",
        "artifact_prefix": "COWRIE_FULL",
    },
    "CSR-LANL": {
        "model_dir": "src/models/CSR-LANL",
        "datasets_base": "src/models/CSR-LANL/datasets_redteam_identity_v3",
        "dataset": "CSR-LANL",
        "default_split": "redteam_stratified_groupkfold",
        "artifact_prefix": "CSR_LANL",
    },
}

GROUP_SPLITS = {"groupkfold", "redteam_stratified_groupkfold"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_from_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root() / candidate).resolve()


def json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(v) for v in value]
    if isinstance(value, np.ndarray):
        return json_ready(value.tolist())
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        out = float(value)
        return out if np.isfinite(out) else None
    if isinstance(value, float):
        return value if np.isfinite(value) else None
    return value


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_ready(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def now_run_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.localtime())


def load_dataset_modules(model_dir: Path) -> Dict[str, Any]:
    sys.path.insert(0, str(model_dir))
    modules = {}
    for module_name in ["data_loader", "metrics", "reporting"]:
        if module_name in sys.modules:
            del sys.modules[module_name]
        modules[module_name] = importlib.import_module(module_name)
    return modules


def artifact_root(model_dir: Path, model_name: str, split_mode: str, run_id: str, run_config: Dict[str, Any]) -> Path:
    root = model_dir / "artifacts" / model_name / split_mode / run_id
    root.mkdir(parents=True, exist_ok=True)
    write_json(
        root / "run_metadata.json",
        {
            "model": model_name,
            "split_mode": split_mode,
            "run_id": run_id,
            "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "run_config": run_config,
        },
    )
    return root


def parse_numeric_or_auto(value: str) -> str | int | float:
    text = str(value).strip().lower()
    if text == "auto":
        return "auto"
    if "." in text:
        return float(text)
    return int(text)


def parse_contamination(value: str) -> str | float:
    text = str(value).strip().lower()
    if text == "auto":
        return "auto"
    return float(text)


def save_anomaly_plot(reporting: Any, root: Path, split_name: str, y_true: np.ndarray, scores: np.ndarray, positive_label: str) -> None:
    if not hasattr(reporting, "save_anomaly_plots"):
        return
    try:
        reporting.save_anomaly_plots(root, split_name, y_true, scores, positive_label=positive_label)
    except Exception as exc:
        write_json(root / f"anomaly_plot_warning_{split_name}.json", {"warning": str(exc)})


def anomaly_metrics(metrics_module: Any, y_true: np.ndarray, scores: np.ndarray, positive_label: str) -> Dict[str, float]:
    report = metrics_module.evaluate_anomaly_scores(y_true, scores, positive_label=positive_label)
    return {
        "roc_auc": report.roc_auc,
        "pr_auc": report.pr_auc,
        "best_f1": report.best_f1,
        "best_threshold": report.best_threshold,
    }


def run_one(args: argparse.Namespace, modules: Dict[str, Any], fold: Optional[int], out_dir: Path) -> Dict[str, Any]:
    data_loader = modules["data_loader"]
    metrics_module = modules["metrics"]
    reporting = modules["reporting"]

    train, val, test = data_loader.load_splits(
        datasets_base=args.datasets_base,
        split_mode=args.split_mode,
        dataset=args.dataset,
        pipeline=args.pipeline,
        fold=fold,
        sample_frac=args.sample_frac,
        seed=args.seed,
    )

    model = IsolationForest(
        n_estimators=args.n_estimators,
        max_samples=parse_numeric_or_auto(args.max_samples),
        contamination=parse_contamination(args.contamination),
        max_features=args.max_features,
        bootstrap=args.bootstrap,
        random_state=args.seed,
        n_jobs=args.n_jobs,
    )
    model.fit(train.X.astype(np.float32))
    val_scores = -model.score_samples(val.X.astype(np.float32))
    test_scores = -model.score_samples(test.X.astype(np.float32))

    val_metrics = anomaly_metrics(metrics_module, val.y, val_scores, args.positive_label)
    test_metrics = anomaly_metrics(metrics_module, test.y, test_scores, args.positive_label)
    save_anomaly_plot(reporting, out_dir, "val", val.y, val_scores, args.positive_label)
    save_anomaly_plot(reporting, out_dir, "test", test.y, test_scores, args.positive_label)

    joblib.dump(model, out_dir / "model.joblib")
    write_json(out_dir / "metrics_val.json", val_metrics)
    write_json(out_dir / "metrics_test.json", test_metrics)
    write_json(out_dir / "label_map.json", {"BENIGN": 0, args.positive_label: 1})
    write_json(
        out_dir / "isoforest_config.json",
        {
            "dataset_key": args.dataset_key,
            "dataset": args.dataset,
            "datasets_base": str(resolve_from_root(args.datasets_base)),
            "pipeline": args.pipeline,
            "split_mode": args.split_mode,
            "fold": fold,
            "feature_count": len(train.feature_names),
            "params": vars(args),
        },
    )
    return {"val": val_metrics, "test": test_metrics}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generic tunable IsolationForest trainer for thesis datasets.")
    parser.add_argument("--dataset_key", required=True, choices=sorted(DATASET_CONFIGS))
    parser.add_argument("--datasets_base", default=None)
    parser.add_argument("--dataset", default=None)
    parser.add_argument("--split_mode", default=None)
    parser.add_argument("--pipeline", default="anomaly", choices=["anomaly"])
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--n_folds", type=int, default=5)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--run_id", default=None)
    parser.add_argument("--model_name", default=None)
    parser.add_argument("--positive_label", default="ATTACK")

    parser.add_argument("--n_estimators", type=int, default=500)
    parser.add_argument("--max_samples", default="auto")
    parser.add_argument("--contamination", default="auto")
    parser.add_argument("--max_features", type=float, default=1.0)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--n_jobs", type=int, default=1)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = dict(DATASET_CONFIGS[args.dataset_key])
    args.datasets_base = args.datasets_base or config["datasets_base"]
    args.dataset = args.dataset or config["dataset"]
    args.split_mode = args.split_mode or config["default_split"]

    model_dir = resolve_from_root(config["model_dir"])
    modules = load_dataset_modules(model_dir)
    run_id = args.run_id or now_run_id()
    model_name = args.model_name or f"tunable_{config['artifact_prefix']}_isoforest"
    root = artifact_root(model_dir, model_name, args.split_mode, run_id, vars(args))

    if args.split_mode not in GROUP_SPLITS:
        try:
            out = run_one(args, modules, None, root)
        except (FileNotFoundError, ValueError) as exc:
            raise SystemExit(f"Training failed for {args.dataset_key}: {exc}")
        write_json(root / "results.json", out)
        print("Saved:", root)
        return

    if not args.all_folds and args.fold is None:
        args.fold = 0
    folds = range(args.n_folds) if args.all_folds else [args.fold]
    summary = {}
    for fold in folds:
        fold_dir = root / f"fold_{int(fold)}"
        fold_dir.mkdir(parents=True, exist_ok=True)
        try:
            out = run_one(args, modules, int(fold), fold_dir)
        except (FileNotFoundError, ValueError) as exc:
            summary[f"fold_{int(fold)}"] = {"skipped": True, "reason": str(exc)}
            continue
        write_json(fold_dir / "results.json", out)
        summary[f"fold_{int(fold)}"] = out
    write_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()