#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import sys

from prepare_dataset import main as prepare_main


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare a red-team-centered CSR-LANL dataset.")
    parser.add_argument("--in_dir", default="out/CSR-LANL")
    parser.add_argument("--out_dir", default="src/models/CSR-LANL/datasets_redteam")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--source_set", default="auth_flow", choices=["auth", "auth_flow", "auth_flow_dns", "all"])
    parser.add_argument("--split_mode", nargs="+", default=["date", "redteam_stratified_groupkfold"], help="date, random, groupkfold, redteam_stratified_groupkfold, all")
    parser.add_argument("--window_seconds", type=int, default=60)
    parser.add_argument("--redteam_window_hours", type=float, default=1.0, help="Hours before and after each red-team event to keep")
    parser.add_argument("--redteam_window_limit", type=int, default=0, help="0 keeps all red-team events")
    parser.add_argument("--redteam_exclusion_windows", type=int, default=2)
    parser.add_argument("--min_redteam_matches", type=int, default=1)
    parser.add_argument("--max_rows_per_source", type=int, default=0, help="0 disables row caps; caps may drop later red-team windows")
    parser.add_argument("--chunk_size", type=int, default=250_000)
    parser.add_argument("--train_ratio", type=float, default=0.70)
    parser.add_argument("--val_ratio", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n_folds", type=int, default=5)
    parser.add_argument("--fold", type=int, default=0)
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--min_multiclass_windows", type=int, default=3)
    parser.add_argument("--progress_every_chunks", type=int, default=4)
    parser.add_argument("--progress_every_rows", type=int, default=1_000_000)
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
        "--redteam_window_hours", str(args.redteam_window_hours),
        "--redteam_window_limit", str(args.redteam_window_limit),
        "--redteam_exclusion_windows", str(args.redteam_exclusion_windows),
        "--min_redteam_matches", str(args.min_redteam_matches),
        "--chunk_size", str(args.chunk_size),
        "--train_ratio", str(args.train_ratio),
        "--val_ratio", str(args.val_ratio),
        "--seed", str(args.seed),
        "--n_folds", str(args.n_folds),
        "--fold", str(args.fold),
        "--min_multiclass_windows", str(args.min_multiclass_windows),
        "--progress_every_chunks", str(args.progress_every_chunks),
        "--progress_every_rows", str(args.progress_every_rows),
    ]
    if args.max_rows_per_source > 0:
        prepare_argv.extend(["--max_rows_per_source", str(args.max_rows_per_source)])
    if args.all_folds:
        prepare_argv.append("--all_folds")
    if args.no_progress:
        prepare_argv.append("--no_progress")

    sys.argv = prepare_argv
    prepare_main()


if __name__ == "__main__":
    main()