#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any, List, Optional

try:
    from .model_registry import ModelRegistry, resolve_from_root
except ImportError:  # pragma: no cover - direct script fallback
    from model_registry import ModelRegistry, resolve_from_root


def script_path(name: str) -> Path:
    return resolve_from_root("src/models/PRODUCTION_PIPELINE") / name


def add_optional_int(command: List[str], flag: str, value: Optional[int]) -> None:
    if value is not None:
        command.extend([flag, str(value)])


def add_optional_str(command: List[str], flag: str, value: Optional[str]) -> None:
    if value:
        command.extend([flag, value])


def hgb_command(spec: Any, args: argparse.Namespace) -> List[str]:
    if spec.dataset_key == "COWRIE_FULL":
        raise SystemExit("COWRIE_FULL is a multiclass taxonomy model; no binary batch inference is routed by default.")
    command = [
        sys.executable,
        str(script_path("batch_inference.py")),
        "--registry",
        args.registry,
        "--model_id",
        spec.model_id,
        "--split",
        args.split,
        "--run_id",
        args.run_id,
        "--max_events",
        str(args.max_events),
    ]
    add_optional_int(command, "--max_rows_per_split", args.max_rows)
    return command


def cic_command(spec: Any, args: argparse.Namespace) -> List[str]:
    command = [
        sys.executable,
        str(script_path("cic_gru_inference.py")),
        "--registry",
        args.registry,
        "--model_id",
        spec.model_id,
        "--split",
        args.split,
        "--run_id",
        args.run_id,
        "--max_events",
        str(args.max_events),
        "--device",
        args.device,
    ]
    add_optional_str(command, "--split_mode", args.split_mode)
    add_optional_int(command, "--max_rows", args.max_rows)
    return command


def csr_command(spec: Any, args: argparse.Namespace) -> List[str]:
    command = [
        sys.executable,
        str(script_path("csr_entity_day_evaluator.py")),
        "--registry",
        args.registry,
        "--model_id",
        spec.model_id,
        "--split",
        args.split,
        "--run_id",
        args.run_id,
        "--event_policy",
        args.event_policy,
        "--event_daily_budget",
        str(args.event_daily_budget),
        "--max_events",
        str(args.max_events),
    ]
    add_optional_int(command, "--max_rows", args.max_rows)
    return command


def build_command(spec: Any, args: argparse.Namespace) -> List[str]:
    if spec.domain == "network_sequence" or spec.pipeline.startswith("sequence"):
        return cic_command(spec, args)
    if spec.domain == "entity_day_triage" or spec.pipeline.startswith("anomaly"):
        return csr_command(spec, args)
    if "hgb" in spec.model_type:
        return hgb_command(spec, args)
    raise SystemExit(f"No active inference adapter is registered for model_type={spec.model_type} domain={spec.domain}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Route active production inference to the correct domain adapter.")
    parser.add_argument("--registry", default="src/models/PRODUCTION_PIPELINE/active_model_registry.json")
    parser.add_argument("--model_id", required=True)
    parser.add_argument("--split", choices=["train", "val", "calibration", "test"], default="test")
    parser.add_argument("--split_mode", default=None, help="Optional CIC sequence split_mode override for evaluation datasets.")
    parser.add_argument("--run_id", default="router_active_inference")
    parser.add_argument("--max_rows", type=int, default=None)
    parser.add_argument("--max_events", type=int, default=1000)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--event_policy", choices=["topk", "daily_budget"], default="daily_budget")
    parser.add_argument("--event_daily_budget", type=int, default=25)
    parser.add_argument("--dry_run", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    registry = ModelRegistry.from_json(args.registry)
    spec = registry.get(args.model_id)
    command = build_command(spec, args)
    print("[run-active-inference] " + " ".join(command), flush=True)
    if args.dry_run:
        return
    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()