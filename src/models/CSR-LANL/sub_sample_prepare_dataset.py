#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import sys

from prepare_dataset import main as prepare_main


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare a bounded CSR-LANL subsample dataset."
    )
    parser.add_argument("--in_dir", default="out/CSR-LANL")
    parser.add_argument("--out_dir", default="src/models/CSR-LANL/datasets_subsample")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--source_set", default="auth", choices=["auth", "auth_flow", "auth_flow_dns", "all"])
    parser.add_argument("--split_mode", nargs="+", default=["random"], help="date, random, groupkfold, all")
    parser.add_argument("--window_seconds", type=int, default=60)
    parser.add_argument("--max_rows", type=int, default=200_000)
    parser.add_argument("--strategy", choices=["first_redteam", "head"], default="first_redteam")
    parser.add_argument("--time_window_hours", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--progress_every_chunks", type=int, default=20)
    parser.add_argument("--progress_every_rows", type=int, default=5_000_000)
    parser.add_argument("--no_progress", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    prepare_argv = [
        "prepare_dataset.py",
        "--in_dir", args.in_dir,
        "--out_dir", args.out_dir,
        "--dataset", args.dataset,
        "--source_set", args.source_set,
        "--split_mode",
        *args.split_mode,
        "--window_seconds", str(args.window_seconds),
        "--max_rows_per_source", str(args.max_rows),
        "--seed", str(args.seed),
        "--progress_every_chunks", str(args.progress_every_chunks),
        "--progress_every_rows", str(args.progress_every_rows),
    ]

    if args.strategy == "first_redteam":
        prepare_argv.extend(["--time_window_hours", str(args.time_window_hours)])

    if args.no_progress:
        prepare_argv.append("--no_progress")

    sys.argv = prepare_argv
    prepare_main()


if __name__ == "__main__":
    main()