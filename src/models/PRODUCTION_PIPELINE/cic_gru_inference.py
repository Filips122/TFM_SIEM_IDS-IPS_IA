#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import importlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import numpy as np
import torch

try:
    from .model_registry import ModelRegistry, resolve_from_root
    from .siem_export import build_siem_event
    from .threshold_optimizer import attack_scores, binary_targets, class_names_from_label_map, metrics_at_threshold, write_json
except ImportError:  # pragma: no cover - direct script fallback
    from model_registry import ModelRegistry, resolve_from_root
    from siem_export import build_siem_event
    from threshold_optimizer import attack_scores, binary_targets, class_names_from_label_map, metrics_at_threshold, write_json


def now_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.gmtime())


def log(message: str) -> None:
    print(f"[cic-gru-inference] {message}", flush=True)


def load_cic_modules() -> Tuple[Any, Any]:
    model_dir = resolve_from_root("src/models/CIC-IDS2017")
    sys.path.insert(0, str(model_dir))
    for module_name in ["models_torch", "sequence_loader"]:
        if module_name in sys.modules:
            del sys.modules[module_name]
    return importlib.import_module("models_torch"), importlib.import_module("sequence_loader")


def first_existing(base: Path, candidates: Iterable[str]) -> Optional[Path]:
    for candidate in candidates:
        path = base / candidate
        if path.exists():
            return path
    return None


def find_files(spec: Any) -> Dict[str, Path]:
    artifact_dir = spec.resolved_artifact_dir(resolve_from_root("."))
    paths = {
        "checkpoint": first_existing(artifact_dir, ["model/best_model.pt", "best_model.pt"]),
        "x_mean": first_existing(artifact_dir, ["model/x_mean.npy", "x_mean.npy"]),
        "x_std": first_existing(artifact_dir, ["model/x_std.npy", "x_std.npy"]),
        "label_map": first_existing(artifact_dir, ["metadata/label_map.json", "label_map.json"]),
        "results": first_existing(artifact_dir, ["metadata/results.json", "results.json"]),
    }
    missing = [name for name, path in paths.items() if path is None and name != "results"]
    if missing:
        raise FileNotFoundError(f"Missing GRU artifact files under {artifact_dir}: {missing}")
    return {name: path for name, path in paths.items() if path is not None}


def read_json(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return payload


def infer_gru_architecture(state_dict: Dict[str, torch.Tensor]) -> Dict[str, Any]:
    weight_hh = state_dict["gru.weight_hh_l0"]
    hidden = int(weight_hh.shape[1])
    layer_ids = set()
    pattern = re.compile(r"^gru\.weight_ih_l(\d+)(?:_reverse)?$")
    bidirectional = False
    for key in state_dict:
        match = pattern.match(key)
        if match:
            layer_ids.add(int(match.group(1)))
            if key.endswith("_reverse"):
                bidirectional = True
    return {"hidden": hidden, "n_layers": max(layer_ids) + 1 if layer_ids else 1, "bidirectional": bidirectional}


def load_label_map(path: Path) -> Dict[str, int]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {str(label): int(index) for label, index in payload.items()}


def load_policy_threshold(path: str) -> float:
    payload = json.loads(resolve_from_root(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "threshold" not in payload:
        raise ValueError(f"Policy JSON must contain a threshold field: {path}")
    return float(payload["threshold"])


def standardize_sequences(X: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    n_rows, window_size, n_features = X.shape
    flat = np.array(X.reshape(n_rows, window_size * n_features), dtype=np.float32, copy=True)
    np.nan_to_num(flat, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    safe_std = np.where(std < 1e-8, 1.0, std)
    flat = (flat - mean) / safe_std
    np.nan_to_num(flat, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    return flat.reshape(n_rows, window_size, n_features).astype(np.float32, copy=False)


def limit_rows(X: np.ndarray, y: np.ndarray, max_rows: Optional[int], seed: int) -> Tuple[np.ndarray, np.ndarray]:
    if max_rows is None or len(y) <= max_rows:
        return X, y
    indexes = np.random.default_rng(seed).choice(len(y), size=max_rows, replace=False)
    indexes.sort()
    return X[indexes], y[indexes]


def predict_proba(model: torch.nn.Module, X: np.ndarray, device: torch.device, batch_size: int) -> np.ndarray:
    model.eval()
    probabilities: List[np.ndarray] = []
    with torch.no_grad():
        for start in range(0, len(X), batch_size):
            xb = torch.from_numpy(X[start : start + batch_size]).to(device)
            logits = model(xb)
            probs = torch.softmax(logits, dim=1).detach().cpu().numpy()
            probabilities.append(probs)
    return np.concatenate(probabilities, axis=0) if probabilities else np.empty((0, 0), dtype=np.float32)


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
                entity_id=f"{spec.dataset_key}:{split}:sequence:{row_index}",
                source_event={"split": split, "row_index": int(row_index), "y_true_binary": int(y_true[row_index])},
            )
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            written += 1
    return written


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run CIC-IDS2017 GRU sequence inference and export SIEM JSONL.")
    parser.add_argument("--registry", default="src/models/PRODUCTION_PIPELINE/active_model_registry.json")
    parser.add_argument("--model_id", default="gru_cic_day_20260520_145849")
    parser.add_argument("--split", choices=["train", "val", "test"], default="test")
    parser.add_argument("--split_mode", default=None)
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--policy_json", default=None)
    parser.add_argument("--output_jsonl", default=None)
    parser.add_argument("--summary_output", default=None)
    parser.add_argument("--run_id", default=None)
    parser.add_argument("--max_rows", type=int, default=None)
    parser.add_argument("--max_events", type=int, default=1000)
    parser.add_argument("--include_benign", action="store_true")
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

    policy_json = args.policy_json or spec.policy_path
    threshold = float(
        args.threshold
        if args.threshold is not None
        else load_policy_threshold(policy_json)
        if policy_json
        else spec.threshold
    )
    run_id = args.run_id or now_id()
    output_jsonl, summary_output = default_outputs(spec.model_id, args.split, run_id)
    if args.output_jsonl:
        output_jsonl = resolve_from_root(args.output_jsonl)
    if args.summary_output:
        summary_output = resolve_from_root(args.summary_output)

    files = find_files(spec)
    models_torch, sequence_loader = load_cic_modules()
    device = torch.device("cuda" if args.device == "auto" and torch.cuda.is_available() else (args.device if args.device != "auto" else "cpu"))
    log(f"loading checkpoint {files['checkpoint']} on {device}")
    state_dict = torch.load(files["checkpoint"], map_location=device)
    label_map = load_label_map(files["label_map"])
    class_names = class_names_from_label_map(label_map)
    results = read_json(files["results"]) if "results" in files else {}

    split_mode = args.split_mode or spec.split_mode or "day"
    log(f"loading CIC sequence mode={split_mode} split={args.split}")
    X, y_labels, window_size, n_features = sequence_loader.load_sequence_split(mode=split_mode, task="binary", split=args.split)
    X, y_labels = limit_rows(X, y_labels, args.max_rows, args.seed)
    mean = np.load(files["x_mean"])
    std = np.load(files["x_std"])
    X = standardize_sequences(X, mean, std)

    arch = infer_gru_architecture(state_dict)
    model = models_torch.GRUClassifier(
        n_features=n_features,
        n_classes=len(class_names),
        hidden=arch["hidden"],
        n_layers=arch["n_layers"],
        dropout=0.0,
        bidirectional=arch["bidirectional"],
    ).to(device)
    model.load_state_dict(state_dict)
    proba = predict_proba(model, X, device, args.batch_size)
    scores = attack_scores(proba, class_names, args.benign_label, args.positive_label)
    y_true = binary_targets(y_labels, args.benign_label)
    metrics = metrics_at_threshold(y_true, scores, threshold)
    written = write_events_jsonl(output_jsonl, spec, scores, y_true, threshold, args.split, args.include_benign, args.max_events)
    summary = {
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_id": spec.model_id,
        "dataset_key": spec.dataset_key,
        "domain": spec.domain,
        "split": args.split,
        "split_mode": split_mode,
        "run_id": run_id,
        "rows_scored": int(len(y_true)),
        "events_written": int(written),
        "events_path": str(output_jsonl),
        "threshold": threshold,
        "policy_json": policy_json,
        "class_names": class_names,
        "window_size": int(window_size),
        "n_features": int(n_features),
        "artifact_results": {"T": results.get("T"), "F": results.get("F"), "test": results.get("test")},
        "architecture": arch,
        "metrics": metrics,
        "notes": [
            "Threshold loaded from policy_json/policy_path." if policy_json else "Threshold loaded from active registry or CLI override."
        ],
    }
    write_json(summary_output, summary)
    log(f"events written={written} path={output_jsonl}")
    log(f"summary saved={summary_output}")


if __name__ == "__main__":
    main()