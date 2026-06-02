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
import pandas as pd

try:
    from .model_registry import ModelRegistry, resolve_from_root
    from .siem_export import build_siem_event
    from .threshold_optimizer import write_json
except ImportError:  # pragma: no cover - direct script fallback
    from model_registry import ModelRegistry, resolve_from_root
    from siem_export import build_siem_event
    from threshold_optimizer import write_json


def now_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.gmtime())


def log(message: str) -> None:
    print(f"[csr-entity-day] {message}", flush=True)


def load_csr_loader() -> Any:
    model_dir = resolve_from_root("src/models/CSR-LANL")
    sys.path.insert(0, str(model_dir))
    if "data_loader" in sys.modules:
        del sys.modules["data_loader"]
    return importlib.import_module("data_loader")


def first_existing(base: Path, candidates: Iterable[str]) -> Optional[Path]:
    for candidate in candidates:
        path = base / candidate
        if path.exists():
            return path
    return None


def find_model_path(spec: Any) -> Path:
    artifact_dir = spec.resolved_artifact_dir(resolve_from_root("."))
    path = first_existing(artifact_dir, ["model/model.joblib", "model.joblib"])
    if path is None:
        raise FileNotFoundError(f"Missing model.joblib under {artifact_dir}")
    return path


def infer_datasets_base(spec: Any, model: Any) -> str:
    expected_features = int(getattr(model, "n_features_in_", -1))
    candidates = sorted(resolve_from_root("src/models/CSR-LANL").glob("datasets*/redteam_stratified_groupkfold/CSR-LANL/fold_0/feature_columns.json"))
    matches: List[Path] = []
    for path in candidates:
        columns = json.loads(path.read_text(encoding="utf-8"))
        if len(columns) == expected_features:
            matches.append(path)
    if not matches:
        raise FileNotFoundError(f"Could not infer CSR datasets_base for n_features_in_={expected_features}")
    selected = matches[0].parents[3]
    try:
        return str(selected.relative_to(resolve_from_root("."))).replace("\\", "/")
    except ValueError:
        return str(selected)


def load_split_frame(
    data_loader: Any,
    datasets_base: str,
    split_mode: str,
    fold: Optional[int],
    split: str,
    sample_frac: Optional[float],
    seed: int,
) -> Any:
    return data_loader.load_split_frame(
        datasets_base=datasets_base,
        split_mode=split_mode,
        dataset="CSR-LANL",
        pipeline="anomaly",
        split=split,
        fold=fold,
        sample_frac=sample_frac,
        seed=seed,
    )


def limit_rows(loaded: Any, max_rows: Optional[int], seed: int) -> Any:
    if max_rows is None or len(loaded.y) <= max_rows:
        return loaded
    indexes = np.random.default_rng(seed).choice(len(loaded.y), size=max_rows, replace=False)
    indexes.sort()
    loaded.X = loaded.X[indexes]
    loaded.y = loaded.y[indexes]
    loaded.meta = loaded.meta.iloc[indexes].reset_index(drop=True)
    loaded.frame = loaded.frame.iloc[indexes].reset_index(drop=True)
    return loaded


def normalize_scores(scores: np.ndarray) -> np.ndarray:
    if len(scores) == 0:
        return scores.astype(float)
    order = np.argsort(scores)
    ranks = np.empty(len(scores), dtype=float)
    ranks[order] = np.arange(1, len(scores) + 1, dtype=float)
    return ranks / float(len(scores))


def entity_day_frame(meta: pd.DataFrame, scores: np.ndarray, normalized_scores: np.ndarray, y_true: np.ndarray) -> pd.DataFrame:
    frame = meta.copy()
    frame["raw_score"] = scores.astype(float)
    frame["normalized_score"] = normalized_scores.astype(float)
    frame["y_true_binary"] = y_true.astype(int)
    if "entity" not in frame.columns:
        frame["entity"] = "unknown"
    if "window_start" in frame.columns:
        day_values = pd.to_datetime(frame["window_start"], errors="coerce").dt.strftime("%Y-%m-%d")
        frame["day"] = day_values.fillna("unknown")
    else:
        frame["day"] = "unknown"

    agg_spec: Dict[str, Tuple[str, str]] = {
        "raw_score": ("raw_score", "max"),
        "normalized_score": ("normalized_score", "max"),
        "mean_normalized_score": ("normalized_score", "mean"),
        "windows": ("y_true_binary", "size"),
        "attack_windows": ("y_true_binary", "sum"),
    }
    for optional in ["redteam_exact", "redteam_near"]:
        if optional in frame.columns:
            agg_spec[optional] = (optional, "sum")

    grouped = frame.groupby(["entity", "day"], dropna=False).agg(**agg_spec).reset_index()
    grouped["has_attack"] = (grouped["attack_windows"] > 0).astype(int)
    grouped = grouped.sort_values(["normalized_score", "raw_score"], ascending=[False, False]).reset_index(drop=True)
    grouped["global_rank"] = np.arange(1, len(grouped) + 1)
    grouped["daily_rank"] = grouped.groupby("day")["normalized_score"].rank(method="first", ascending=False).astype(int)
    return grouped


def topk_metrics(entity_days: pd.DataFrame, topk_values: List[int]) -> Dict[str, Any]:
    total_attack_windows = int(entity_days["attack_windows"].sum())
    total_attack_entity_days = int(entity_days["has_attack"].sum())
    first_attack = entity_days.loc[entity_days["has_attack"] > 0, "global_rank"]
    metrics: Dict[str, Any] = {
        "entity_days": int(len(entity_days)),
        "attack_windows": total_attack_windows,
        "attack_entity_days": total_attack_entity_days,
        "first_attack_rank": int(first_attack.iloc[0]) if not first_attack.empty else None,
    }
    for topk in topk_values:
        selected = entity_days.head(topk)
        metrics[f"top_{topk}"] = {
            "selected_entity_days": int(len(selected)),
            "covered_attack_windows": int(selected["attack_windows"].sum()),
            "covered_attack_entity_days": int(selected["has_attack"].sum()),
            "attack_window_recall": float(selected["attack_windows"].sum() / total_attack_windows) if total_attack_windows else 0.0,
            "attack_entity_day_recall": float(selected["has_attack"].sum() / total_attack_entity_days) if total_attack_entity_days else 0.0,
        }
    return metrics


def daily_budget_metrics(entity_days: pd.DataFrame, budgets: List[int]) -> Dict[str, Any]:
    total_attack_windows = int(entity_days["attack_windows"].sum())
    total_attack_entity_days = int(entity_days["has_attack"].sum())
    out: Dict[str, Any] = {}
    for budget in budgets:
        selected = entity_days[entity_days["daily_rank"] <= budget]
        out[f"daily_budget_{budget}"] = {
            "selected_entity_days": int(len(selected)),
            "covered_attack_windows": int(selected["attack_windows"].sum()),
            "covered_attack_entity_days": int(selected["has_attack"].sum()),
            "attack_window_recall": float(selected["attack_windows"].sum() / total_attack_windows) if total_attack_windows else 0.0,
            "attack_entity_day_recall": float(selected["has_attack"].sum() / total_attack_entity_days) if total_attack_entity_days else 0.0,
        }
    return out


def default_outputs(model_id: str, split: str, run_id: str) -> Tuple[Path, Path, Path]:
    base = resolve_from_root("src/models/PRODUCTION_PIPELINE/inference_runs") / model_id / run_id
    return base / f"{split}_entity_days.csv", base / f"{split}_events.jsonl", base / f"{split}_summary.json"


def write_siem_events(path: Path, spec: Any, selected: pd.DataFrame, threshold: float, max_events: Optional[int]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with path.open("w", encoding="utf-8") as handle:
        for _, row in selected.iterrows():
            if max_events is not None and written >= max_events:
                break
            score = float(row["normalized_score"])
            event = build_siem_event(
                model_spec=spec,
                probability_attack=score,
                threshold=threshold,
                entity_id=str(row["entity"]),
                source_event={
                    "entity": str(row["entity"]),
                    "day": str(row["day"]),
                    "global_rank": int(row["global_rank"]),
                    "daily_rank": int(row["daily_rank"]),
                    "windows": int(row["windows"]),
                    "attack_windows": int(row["attack_windows"]),
                    "raw_score": float(row["raw_score"]),
                },
            )
            event["event"]["dataset"] = "CSR-LANL.entity_day"
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            written += 1
    return written


def parse_int_list(value: str) -> List[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate CSR-LANL IsolationForest as entity-day SOC triage.")
    parser.add_argument("--registry", default="src/models/PRODUCTION_PIPELINE/active_model_registry.json")
    parser.add_argument("--model_id", default="isoforest_csr_entity_day_20260531_002323_fold0")
    parser.add_argument("--datasets_base", default=None)
    parser.add_argument("--split", choices=["train", "val", "test"], default="test")
    parser.add_argument("--sample_frac", type=float, default=None)
    parser.add_argument("--max_rows", type=int, default=None)
    parser.add_argument("--topk", default="10,25,50,100,500")
    parser.add_argument("--daily_budgets", default="10,25,50")
    parser.add_argument("--event_policy", choices=["topk", "daily_budget"], default="daily_budget")
    parser.add_argument("--event_topk", type=int, default=100)
    parser.add_argument("--event_daily_budget", type=int, default=25)
    parser.add_argument("--max_events", type=int, default=1000)
    parser.add_argument("--run_id", default=None)
    parser.add_argument("--entity_days_csv", default=None)
    parser.add_argument("--output_jsonl", default=None)
    parser.add_argument("--summary_output", default=None)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    registry = ModelRegistry.from_json(args.registry)
    spec = registry.get(args.model_id)
    if spec.dataset_key != "CSR-LANL" or "isoforest" not in spec.model_type:
        raise SystemExit(f"Expected CSR IsolationForest spec, got dataset={spec.dataset_key} model_type={spec.model_type}")

    run_id = args.run_id or now_id()
    entity_days_csv, output_jsonl, summary_output = default_outputs(spec.model_id, args.split, run_id)
    if args.entity_days_csv:
        entity_days_csv = resolve_from_root(args.entity_days_csv)
    if args.output_jsonl:
        output_jsonl = resolve_from_root(args.output_jsonl)
    if args.summary_output:
        summary_output = resolve_from_root(args.summary_output)

    model_path = find_model_path(spec)
    log(f"loading model {model_path}")
    model = joblib.load(model_path)
    datasets_base = args.datasets_base or infer_datasets_base(spec, model)
    log(f"using datasets_base={datasets_base}")

    data_loader = load_csr_loader()
    loaded = load_split_frame(data_loader, datasets_base, spec.split_mode or "redteam_stratified_groupkfold", spec.fold, args.split, args.sample_frac, args.seed)
    loaded = limit_rows(loaded, args.max_rows, args.seed)
    scores = -model.score_samples(loaded.X.astype(np.float32))
    normalized_scores = normalize_scores(scores)
    y_true = (loaded.y.astype(str) != "BENIGN").astype(int)
    entity_days = entity_day_frame(loaded.meta, scores, normalized_scores, y_true)
    entity_days_csv.parent.mkdir(parents=True, exist_ok=True)
    entity_days.to_csv(entity_days_csv, index=False)

    topk_values = parse_int_list(args.topk)
    daily_budgets = parse_int_list(args.daily_budgets)
    metrics = {"topk": topk_metrics(entity_days, topk_values), "daily_budget": daily_budget_metrics(entity_days, daily_budgets)}

    if args.event_policy == "topk":
        selected = entity_days.head(args.event_topk)
    else:
        selected = entity_days[entity_days["daily_rank"] <= args.event_daily_budget]
    event_threshold = float(selected["normalized_score"].min()) if len(selected) else 1.0
    written = write_siem_events(output_jsonl, spec, selected, event_threshold, args.max_events)

    summary = {
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_id": spec.model_id,
        "dataset_key": spec.dataset_key,
        "domain": spec.domain,
        "split": args.split,
        "run_id": run_id,
        "datasets_base": datasets_base,
        "rows_scored": int(len(loaded.y)),
        "entity_days": int(len(entity_days)),
        "events_written": int(written),
        "entity_days_csv": str(entity_days_csv),
        "events_path": str(output_jsonl),
        "event_policy": args.event_policy,
        "event_threshold": event_threshold,
        "metrics": metrics,
        "notes": ["CSR-LANL is evaluated as SOC triage over entity-days; row-level F1 is intentionally not used as the main metric."],
    }
    write_json(summary_output, summary)
    log(f"entity days saved={entity_days_csv}")
    log(f"events written={written} path={output_jsonl}")
    log(f"summary saved={summary_output}")


if __name__ == "__main__":
    main()