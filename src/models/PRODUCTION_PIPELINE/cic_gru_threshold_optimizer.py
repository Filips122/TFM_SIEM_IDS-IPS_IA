#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import torch

try:
    from .cic_gru_inference import (
        find_files,
        infer_gru_architecture,
        limit_rows,
        load_cic_modules,
        predict_proba,
        standardize_sequences,
    )
    from .model_registry import ModelRegistry, resolve_from_root
    from .threshold_optimizer import (
        attack_scores,
        binary_targets,
        class_names_from_label_map,
        metrics_at_threshold,
        pick_alert_budget,
        pick_best,
        pick_precision_target,
        pick_recall_target,
        sweep_thresholds,
        write_csv,
        write_json,
    )
except ImportError:  # pragma: no cover - direct script fallback
    from cic_gru_inference import (
        find_files,
        infer_gru_architecture,
        limit_rows,
        load_cic_modules,
        predict_proba,
        standardize_sequences,
    )
    from model_registry import ModelRegistry, resolve_from_root
    from threshold_optimizer import (
        attack_scores,
        binary_targets,
        class_names_from_label_map,
        metrics_at_threshold,
        pick_alert_budget,
        pick_best,
        pick_precision_target,
        pick_recall_target,
        sweep_thresholds,
        write_csv,
        write_json,
    )


def now_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.gmtime())


def log(message: str) -> None:
    print(f"[cic-gru-threshold] {message}", flush=True)


def load_label_map(path: Path) -> Dict[str, int]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {str(label): int(index) for label, index in payload.items()}


def build_model(models_torch: Any, state_dict: Dict[str, torch.Tensor], n_features: int, n_classes: int, device: torch.device) -> torch.nn.Module:
    arch = infer_gru_architecture(state_dict)
    model = models_torch.GRUClassifier(
        n_features=n_features,
        n_classes=n_classes,
        hidden=arch["hidden"],
        n_layers=arch["n_layers"],
        dropout=0.0,
        bidirectional=arch["bidirectional"],
    ).to(device)
    model.load_state_dict(state_dict)
    return model


def score_sequence_split(
    sequence_loader: Any,
    model: torch.nn.Module,
    mean: np.ndarray,
    std: np.ndarray,
    class_names: List[str],
    split_mode: str,
    split: str,
    max_rows: Optional[int],
    seed: int,
    device: torch.device,
    batch_size: int,
    benign_label: str,
    positive_label: str,
) -> Tuple[np.ndarray, np.ndarray, int, int]:
    X, labels, window_size, n_features = sequence_loader.load_sequence_split(mode=split_mode, task="binary", split=split)
    X, labels = limit_rows(X, labels, max_rows, seed)
    X = standardize_sequences(X, mean, std)
    proba = predict_proba(model, X, device, batch_size)
    scores = attack_scores(proba, class_names, benign_label, positive_label)
    y_true = binary_targets(labels, benign_label)
    return y_true, scores, int(window_size), int(n_features)


def allocation_counts(total_by_file: List[int], target_total: int) -> List[int]:
    total_available = int(sum(total_by_file))
    if target_total <= 0 or total_available == 0:
        return [0 for _ in total_by_file]
    target = min(int(target_total), total_available)
    raw = np.asarray(total_by_file, dtype=float) * (target / total_available)
    counts = np.floor(raw).astype(int)
    remainder = target - int(counts.sum())
    if remainder > 0:
        fractional_order = np.argsort(raw - counts)[::-1]
        for index in fractional_order[:remainder]:
            counts[index] += 1
    return [int(min(count, total_by_file[index])) for index, count in enumerate(counts)]


def sample_rows(df: pd.DataFrame, mask: np.ndarray, n_rows: int, rng: np.random.Generator) -> pd.DataFrame:
    if n_rows <= 0:
        return df.iloc[0:0].copy()
    positions = np.flatnonzero(mask)
    if len(positions) == 0:
        return df.iloc[0:0].copy()
    take = min(n_rows, len(positions))
    chosen = rng.choice(positions, size=take, replace=False)
    chosen.sort()
    return df.iloc[chosen].copy()


def load_sequence_stratified_sample(
    sequence_loader: Any,
    split_mode: str,
    splits: List[str],
    benign_label: str,
    attack_rows: int,
    benign_rows: int,
    seed: int,
    dtype: np.dtype = np.float32,
) -> Tuple[np.ndarray, np.ndarray, int, int, Dict[str, Any]]:
    rng = np.random.default_rng(seed)
    file_infos: List[Dict[str, Any]] = []
    for split in splits:
        folder = sequence_loader.seq_split_folder("src/models/CIC-IDS2017/datasets", split_mode, "binary", split)
        for path in sequence_loader.list_parquets(folder):
            target = pd.read_parquet(path, columns=["target"])["target"].astype(str).to_numpy()
            attack_count = int((target != benign_label).sum())
            benign_count = int((target == benign_label).sum())
            file_infos.append({"split": split, "path": path, "attack_count": attack_count, "benign_count": benign_count})

    attack_alloc = allocation_counts([item["attack_count"] for item in file_infos], attack_rows)
    benign_alloc = allocation_counts([item["benign_count"] for item in file_infos], benign_rows)

    chunks: List[pd.DataFrame] = []
    for item, n_attack, n_benign in zip(file_infos, attack_alloc, benign_alloc):
        if n_attack <= 0 and n_benign <= 0:
            continue
        df = pd.read_parquet(item["path"])
        target = df["target"].astype(str).to_numpy()
        sampled = pd.concat(
            [
                sample_rows(df, target != benign_label, n_attack, rng),
                sample_rows(df, target == benign_label, n_benign, rng),
            ],
            ignore_index=True,
        )
        if not sampled.empty:
            sampled["_source_split"] = item["split"]
            chunks.append(sampled)

    if not chunks:
        raise ValueError("No rows sampled for representative CIC calibration set")

    sample_df = pd.concat(chunks, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    y = sample_df["target"].astype(str).to_numpy(copy=True)
    cols, window_size, feature_names = sequence_loader.parse_seq_columns(sample_df)
    Xflat = sample_df[cols].to_numpy(dtype=dtype, copy=True)
    np.nan_to_num(Xflat, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    n_features = len(feature_names)
    X = Xflat.reshape(len(sample_df), window_size, n_features)
    metadata = {
        "selection_splits": splits,
        "requested_attack_rows": int(attack_rows),
        "requested_benign_rows": int(benign_rows),
        "sampled_attack_rows": int((y != benign_label).sum()),
        "sampled_benign_rows": int((y == benign_label).sum()),
        "sampled_rows": int(len(y)),
        "source_split_counts": {str(key): int(value) for key, value in sample_df["_source_split"].value_counts().to_dict().items()},
    }
    return X, y, int(window_size), int(n_features), metadata


def load_selection_split(
    sequence_loader: Any,
    split_mode: str,
    selection_source: str,
    selection_split: str,
    benign_label: str,
    calibration_attack_rows: int,
    calibration_benign_rows: int,
    max_rows: Optional[int],
    seed: int,
) -> Tuple[np.ndarray, np.ndarray, int, int, Dict[str, Any]]:
    if selection_source in {"val", "split"}:
        split_name = "val" if selection_source == "val" else selection_split
        X, labels, window_size, n_features = sequence_loader.load_sequence_split(mode=split_mode, task="binary", split=split_name)
        X, labels = limit_rows(X, labels, max_rows, seed)
        metadata = {
            "selection_source": selection_source,
            "selection_splits": [split_name],
            "selection_split_mode": split_mode,
            "sampled_rows": int(len(labels)),
            "sampled_attack_rows": int((labels.astype(str) != benign_label).sum()),
            "sampled_benign_rows": int((labels.astype(str) == benign_label).sum()),
        }
        return X, labels, int(window_size), int(n_features), metadata

    splits = ["train"] if selection_source == "train_stratified" else ["train", "val"]
    X, labels, window_size, n_features, metadata = load_sequence_stratified_sample(
        sequence_loader=sequence_loader,
        split_mode=split_mode,
        splits=splits,
        benign_label=benign_label,
        attack_rows=calibration_attack_rows,
        benign_rows=calibration_benign_rows,
        seed=seed,
    )
    metadata["selection_source"] = selection_source
    return X, labels, window_size, n_features, metadata


def parse_float_list(value: str) -> List[float]:
    return [float(item.strip()) for item in value.split(",") if item.strip()]


def threshold_for_alert_rate(scores: np.ndarray, target_rate: float) -> Optional[float]:
    if len(scores) == 0 or target_rate <= 0.0:
        return None
    if target_rate >= 1.0:
        return float(np.min(scores))
    return float(np.quantile(scores.astype(float), 1.0 - target_rate, method="higher"))


def threshold_for_benign_fpr(y_true: np.ndarray, scores: np.ndarray, target_fpr: float) -> Optional[float]:
    benign_scores = scores[y_true.astype(int) == 0]
    if len(benign_scores) == 0 or target_fpr <= 0.0:
        return None
    if target_fpr >= 1.0:
        return float(np.min(benign_scores))
    return float(np.quantile(benign_scores.astype(float), 1.0 - target_fpr, method="higher"))


def policy_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: Optional[float], policy: str, target: float) -> Optional[Dict[str, Any]]:
    if threshold is None:
        return None
    row = metrics_at_threshold(y_true, scores, threshold)
    row["policy"] = policy
    row["target"] = float(target)
    return row


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Optimize CIC GRU sequence threshold on validation and evaluate on test.")
    parser.add_argument("--registry", default="src/models/PRODUCTION_PIPELINE/active_model_registry.json")
    parser.add_argument("--model_id", default="gru_cic_day_20260520_145849")
    parser.add_argument("--output_dir", default=None)
    parser.add_argument("--run_id", default=None)
    parser.add_argument("--selection_source", choices=["val", "split", "train_stratified", "train_val_stratified"], default="val")
    parser.add_argument("--selection_split", default="calibration")
    parser.add_argument("--selection_split_mode", default=None)
    parser.add_argument("--test_split", default="test")
    parser.add_argument("--test_split_mode", default=None)
    parser.add_argument("--calibration_attack_rows", type=int, default=50000)
    parser.add_argument("--calibration_benign_rows", type=int, default=50000)
    parser.add_argument("--threshold_min", type=float, default=0.0)
    parser.add_argument("--threshold_max", type=float, default=0.99)
    parser.add_argument("--threshold_steps", type=int, default=199)
    parser.add_argument("--min_precision", type=float, default=0.90)
    parser.add_argument("--min_recall", type=float, default=0.90)
    parser.add_argument("--max_alert_rate", type=float, default=None)
    parser.add_argument("--alert_rate_targets", default="0.01,0.05,0.10")
    parser.add_argument("--benign_fpr_targets", default="0.001,0.005,0.01,0.05")
    parser.add_argument("--max_rows", type=int, default=None)
    parser.add_argument("--min_val_positive_rows", type=int, default=50)
    parser.add_argument("--batch_size", type=int, default=2048)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--benign_label", default="BENIGN")
    parser.add_argument("--positive_label", default="__non_benign__")
    parser.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    registry = ModelRegistry.from_json(args.registry)
    spec = registry.get(args.model_id)
    if spec.dataset_key != "CIC-IDS2017" or "gru" not in spec.model_type:
        raise SystemExit(f"Expected CIC GRU model spec, got dataset={spec.dataset_key} model_type={spec.model_type}")

    run_id = args.run_id or now_id()
    output_dir = resolve_from_root(args.output_dir) if args.output_dir else resolve_from_root("src/models/PRODUCTION_PIPELINE/threshold_runs") / spec.model_id / run_id
    files = find_files(spec)
    models_torch, sequence_loader = load_cic_modules()
    device = torch.device("cuda" if args.device == "auto" and torch.cuda.is_available() else (args.device if args.device != "auto" else "cpu"))
    state_dict = torch.load(files["checkpoint"], map_location=device)
    label_map = load_label_map(files["label_map"])
    class_names = class_names_from_label_map(label_map)
    mean = np.load(files["x_mean"])
    std = np.load(files["x_std"])

    selection_split_mode = args.selection_split_mode or spec.split_mode or "day"
    test_split_mode = args.test_split_mode or spec.split_mode or "day"
    log(f"loading selection source={args.selection_source} mode={selection_split_mode}")
    X_val, y_val_labels, window_size, n_features, selection_metadata = load_selection_split(
        sequence_loader=sequence_loader,
        split_mode=selection_split_mode,
        selection_source=args.selection_source,
        selection_split=args.selection_split,
        benign_label=args.benign_label,
        calibration_attack_rows=args.calibration_attack_rows,
        calibration_benign_rows=args.calibration_benign_rows,
        max_rows=args.max_rows,
        seed=args.seed,
    )
    model = build_model(models_torch, state_dict, n_features, len(class_names), device)
    X_val = standardize_sequences(X_val, mean, std)
    val_scores = attack_scores(predict_proba(model, X_val, device, args.batch_size), class_names, args.benign_label, args.positive_label)
    y_val = binary_targets(y_val_labels, args.benign_label)

    log("scoring test split")
    y_test, test_scores, _, _ = score_sequence_split(
        sequence_loader=sequence_loader,
        model=model,
        mean=mean,
        std=std,
        class_names=class_names,
        split_mode=test_split_mode,
        split=args.test_split,
        max_rows=args.max_rows,
        seed=args.seed,
        device=device,
        batch_size=args.batch_size,
        benign_label=args.benign_label,
        positive_label=args.positive_label,
    )

    thresholds = np.linspace(args.threshold_min, args.threshold_max, args.threshold_steps)
    val_rows = sweep_thresholds(y_val, val_scores, thresholds)
    test_rows = sweep_thresholds(y_test, test_scores, thresholds)
    alert_rate_targets = parse_float_list(args.alert_rate_targets)
    benign_fpr_targets = parse_float_list(args.benign_fpr_targets)
    selected = {
        "best_f1": pick_best(val_rows),
        f"precision_at_least_{args.min_precision:.2f}": pick_precision_target(val_rows, args.min_precision),
        f"recall_at_least_{args.min_recall:.2f}": pick_recall_target(val_rows, args.min_recall),
        "alert_budget": pick_alert_budget(val_rows, args.max_alert_rate),
    }
    for target in alert_rate_targets:
        threshold = threshold_for_alert_rate(val_scores, target)
        selected[f"alert_rate_{target:g}"] = policy_metrics(y_val, val_scores, threshold, "alert_rate", target)
    for target in benign_fpr_targets:
        threshold = threshold_for_benign_fpr(y_val, val_scores, target)
        selected[f"benign_fpr_{target:g}"] = policy_metrics(y_val, val_scores, threshold, "benign_fpr", target)
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
    warnings: List[str] = []
    if int(y_val.sum()) < args.min_val_positive_rows:
        warnings.append(
            f"validation split has only {int(y_val.sum())} positive rows; F1/recall threshold selection may be unstable; prefer benign_fpr or alert_rate policies"
        )
    if args.selection_source in {"train_stratified", "train_val_stratified"}:
        warnings.append(
            f"selection_source={args.selection_source} includes training rows; treat threshold as development calibration and confirm with a future independent calibration split"
        )
    if selected["best_f1"]["f1"] == 0.0:
        warnings.append("best validation F1 is 0.0; do not promote this threshold without a better validation policy")

    summary = {
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_id": spec.model_id,
        "dataset_key": spec.dataset_key,
        "domain": spec.domain,
        "run_id": run_id,
        "rows_val": int(len(y_val)),
        "rows_test": int(len(y_test)),
        "val_attack_rows": int(y_val.sum()),
        "test_attack_rows": int(y_test.sum()),
        "window_size": int(window_size),
        "n_features": int(n_features),
        "test_split": args.test_split,
        "test_split_mode": test_split_mode,
        "class_names": class_names,
        "selection_metadata": selection_metadata,
        "selected_on_val": selected,
        "selected_thresholds_on_test": selected_test,
        "oracle_on_test": oracle_on_test,
        "warnings": warnings,
        "notes": ["Use selected_on_val policies for production-style decisions; oracle_on_test is diagnostic only."],
    }
    write_json(output_dir / "threshold_summary.json", summary)
    log(f"summary saved={output_dir / 'threshold_summary.json'}")


if __name__ == "__main__":
    main()