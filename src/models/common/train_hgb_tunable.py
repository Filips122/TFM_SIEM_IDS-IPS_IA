#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import importlib
import inspect
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight


DATASET_CONFIGS: Dict[str, Dict[str, str]] = {
    "CIC-IDS2017": {
        "model_dir": "src/models/CIC-IDS2017",
        "datasets_base": "src/models/CIC-IDS2017/datasets",
        "dataset": "MachineLearningCVE",
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
    if isinstance(value, (np.str_, np.bytes_)):
        return str(value)
    return value


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_ready(payload), ensure_ascii=False, indent=2), encoding="utf-8")


def now_run_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.localtime())


def load_dataset_modules(model_dir: Path) -> Dict[str, Any]:
    sys.path.insert(0, str(model_dir))
    modules = {}
    for module_name in ["data_loader", "reporting"]:
        if module_name in sys.modules:
            del sys.modules[module_name]
        modules[module_name] = importlib.import_module(module_name)
    return modules


def save_metrics(reporting: Any, root: Path, split_name: str, y_true: np.ndarray, proba: np.ndarray, class_names: np.ndarray, make_plots: bool) -> Dict[str, Any]:
    func = reporting.save_metrics_and_plots
    kwargs = {}
    if "make_roc_and_calibration" in inspect.signature(func).parameters:
        kwargs["make_roc_and_calibration"] = make_plots
    return func(root, split_name, y_true, proba, class_names, **kwargs)


def save_label_map(root: Path, encoder: LabelEncoder) -> None:
    mapping = {str(label): int(index) for index, label in enumerate(encoder.classes_)}
    write_json(root / "label_map.json", mapping)


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


def hgb_max_depth(value: int) -> Optional[int]:
    return None if value <= 0 else int(value)


def hgb_max_leaf_nodes(value: int) -> Optional[int]:
    return None if value <= 0 else int(value)


def fit_split_encoder(train_y: np.ndarray, val_y: np.ndarray, test_y: np.ndarray) -> LabelEncoder:
    encoder = LabelEncoder()
    labels = np.concatenate([train_y.astype(str), val_y.astype(str), test_y.astype(str)])
    encoder.fit(labels)
    return encoder


def split_label_counts(encoder: LabelEncoder, values: np.ndarray) -> Dict[str, int]:
    encoded = encoder.transform(values.astype(str))
    counts = np.bincount(encoded, minlength=len(encoder.classes_))
    return {str(label): int(counts[index]) for index, label in enumerate(encoder.classes_)}


def align_proba_to_encoder(model: HistGradientBoostingClassifier, proba: np.ndarray, encoder: LabelEncoder) -> np.ndarray:
    n_classes = len(encoder.classes_)
    model_classes = np.asarray(getattr(model, "classes_", np.arange(proba.shape[1])), dtype=int)
    if proba.shape[1] == n_classes and np.array_equal(model_classes, np.arange(n_classes)):
        return proba

    aligned = np.zeros((proba.shape[0], n_classes), dtype=proba.dtype)
    for proba_index, class_index in enumerate(model_classes):
        if 0 <= int(class_index) < n_classes:
            aligned[:, int(class_index)] = proba[:, proba_index]
    return aligned


def run_one(args: argparse.Namespace, modules: Dict[str, Any], config: Dict[str, str], fold: Optional[int], out_dir: Path) -> Dict[str, Any]:
    data_loader = modules["data_loader"]
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

    encoder = fit_split_encoder(train.y, val.y, test.y)
    train_classes = np.unique(train.y.astype(str))
    if len(train_classes) < 2:
        raise ValueError(f"HGB requires at least two train classes, got {list(train_classes)}")

    missing_train_classes = sorted(set(encoder.classes_.astype(str)) - set(train_classes.astype(str)))
    if missing_train_classes:
        write_json(
            out_dir / "unseen_classes_warning.json",
            {
                "warning": "Some labels appear only in val/test and are absent from train. Metrics keep those labels and assign zero probability to classes the model cannot learn.",
                "missing_train_classes": missing_train_classes,
                "train_counts": split_label_counts(encoder, train.y),
                "val_counts": split_label_counts(encoder, val.y),
                "test_counts": split_label_counts(encoder, test.y),
            },
        )

    y_train = encoder.transform(train.y.astype(str))
    y_val = encoder.transform(val.y.astype(str))
    y_test = encoder.transform(test.y.astype(str))

    X_train = train.X.astype(np.float32)
    X_val = val.X.astype(np.float32)
    X_test = test.X.astype(np.float32)

    train_observed_counts = np.bincount(y_train)
    early_stopping = (not args.no_early_stopping) and bool(np.all(train_observed_counts >= 2))
    if (not args.no_early_stopping) and not early_stopping:
        write_json(
            out_dir / "early_stopping_warning.json",
            {
                "warning": "Early stopping disabled because at least one class has fewer than two train examples.",
                "train_counts": split_label_counts(encoder, train.y),
            },
        )

    model = HistGradientBoostingClassifier(
        max_iter=args.max_iter,
        learning_rate=args.learning_rate,
        max_depth=hgb_max_depth(args.max_depth),
        max_leaf_nodes=hgb_max_leaf_nodes(args.max_leaf_nodes),
        min_samples_leaf=args.min_samples_leaf,
        l2_regularization=args.l2_regularization,
        early_stopping=early_stopping,
        validation_fraction=args.validation_fraction,
        n_iter_no_change=args.n_iter_no_change,
        tol=args.tol,
        random_state=args.seed,
    )
    sample_weight = compute_sample_weight(class_weight="balanced", y=y_train) if args.class_weight == "balanced" else None
    model.fit(X_train, y_train, sample_weight=sample_weight)

    if hasattr(reporting, "save_staged_classification_history"):
        try:
            reporting.save_staged_classification_history(out_dir, model, X_train, y_train, X_val, y_val, encoder.classes_)
        except Exception as exc:
            write_json(out_dir / "history_warning.json", {"warning": str(exc)})

    proba_train = align_proba_to_encoder(model, model.predict_proba(X_train), encoder)
    proba_val = align_proba_to_encoder(model, model.predict_proba(X_val), encoder)
    proba_test = align_proba_to_encoder(model, model.predict_proba(X_test), encoder)

    metrics_train = save_metrics(reporting, out_dir, "train", y_train, proba_train, encoder.classes_, make_plots=False)
    metrics_val = save_metrics(reporting, out_dir, "val", y_val, proba_val, encoder.classes_, make_plots=False)
    metrics_test = save_metrics(reporting, out_dir, "test", y_test, proba_test, encoder.classes_, make_plots=True)

    if hasattr(reporting, "plot_corr_matrix") and not args.skip_corr:
        try:
            reporting.plot_corr_matrix(X_train, out_dir / "plots" / "corr_matrix.png")
        except Exception as exc:
            write_json(out_dir / "corr_warning.json", {"warning": str(exc)})

    joblib.dump(model, out_dir / "model.joblib")
    save_label_map(out_dir, encoder)
    write_json(
        out_dir / "hgb_config.json",
        {
            "dataset_key": args.dataset_key,
            "dataset": args.dataset,
            "datasets_base": str(resolve_from_root(args.datasets_base)),
            "pipeline": args.pipeline,
            "split_mode": args.split_mode,
            "fold": fold,
            "feature_count": len(train.feature_names),
            "classes": list(encoder.classes_),
            "params": vars(args),
        },
    )
    return {
        "best_iter": int(getattr(model, "n_iter_", args.max_iter)),
        "train": metrics_train,
        "val": metrics_val,
        "test": metrics_test,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generic tunable HistGradientBoosting trainer for thesis datasets.")
    parser.add_argument("--dataset_key", required=True, choices=sorted(DATASET_CONFIGS))
    parser.add_argument("--datasets_base", default=None)
    parser.add_argument("--dataset", default=None)
    parser.add_argument("--split_mode", default=None)
    parser.add_argument("--pipeline", default="binary", choices=["binary", "multiclass"])
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--n_folds", type=int, default=5)
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--run_id", default=None)
    parser.add_argument("--model_name", default=None)

    parser.add_argument("--max_iter", type=int, default=500)
    parser.add_argument("--learning_rate", type=float, default=0.05)
    parser.add_argument("--max_depth", type=int, default=3, help="Use <=0 for None")
    parser.add_argument("--max_leaf_nodes", type=int, default=31, help="Use <=0 for None")
    parser.add_argument("--min_samples_leaf", type=int, default=50)
    parser.add_argument("--l2_regularization", type=float, default=0.1)
    parser.add_argument("--validation_fraction", type=float, default=0.15)
    parser.add_argument("--n_iter_no_change", type=int, default=12)
    parser.add_argument("--tol", type=float, default=1e-4)
    parser.add_argument("--class_weight", default="none", choices=["none", "balanced"])
    parser.add_argument("--no_early_stopping", action="store_true")
    parser.add_argument("--skip_corr", action="store_true")
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
    model_name = args.model_name or f"tunable_{config['artifact_prefix']}_{args.pipeline}_hgb"
    root = artifact_root(model_dir, model_name, args.split_mode, run_id, vars(args))

    if args.split_mode not in GROUP_SPLITS:
        try:
            out = run_one(args, modules, config, None, root)
        except (FileNotFoundError, ValueError) as exc:
            raise SystemExit(f"Training failed for {args.dataset_key}: {exc}")
        write_json(root / "results.json", {"best_iter": out["best_iter"], "train": out["train"], "val": out["val"], "test": out["test"]})
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
            out = run_one(args, modules, config, int(fold), fold_dir)
        except (FileNotFoundError, ValueError) as exc:
            summary[f"fold_{int(fold)}"] = {"skipped": True, "reason": str(exc)}
            continue
        write_json(fold_dir / "results.json", {"best_iter": out["best_iter"], "train": out["train"], "val": out["val"], "test": out["test"]})
        summary[f"fold_{int(fold)}"] = {"best_iter": out["best_iter"], "val": out["val"], "test": out["test"]}
    write_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()