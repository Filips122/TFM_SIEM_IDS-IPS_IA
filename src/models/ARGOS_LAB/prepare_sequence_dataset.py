#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build per-agent window sequences for the recurrent model.

Each sample is the last `--seq_len` consecutive windows of one agent, and the
label is the label of the final window. Sequences never cross an agent
boundary, and they are cut from the already-split parquet files, so the
train/val/test separation of prepare_dataset.py is preserved exactly.

Why sequences are worth building here: the weak labeller looked at one alert at
a time. How an agent's activity *evolved* over the preceding quarter of an hour
is information no labelling rule had, so a model that needs the sequence to
succeed cannot be shortcutting to the label.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd

from data_loader import list_parquets, mode_root, resolve_from_root, split_folder
from feature_spec import resolve_feature_set

SPLITS = ("train", "val", "test")


def build_sequences(df: pd.DataFrame, feature_cols: List[str], seq_len: int, stride: int, max_gap_minutes: float):
    """Slice each agent's ordered windows into fixed-length sequences.

    A sequence is dropped when it spans a gap larger than `max_gap_minutes`,
    otherwise a quiet agent's windows from different days would be stitched
    into a single fake 'sequence'.
    """
    X_parts, y_parts, meta_parts = [], [], []
    max_gap = pd.Timedelta(minutes=max_gap_minutes)

    for agent_id, group in df.groupby("agent_id", sort=True):
        group = group.sort_values("window_start")
        if len(group) < seq_len:
            continue
        features = group[feature_cols].to_numpy(dtype=np.float32)
        targets = group["target"].astype(str).to_numpy()
        times = pd.to_datetime(group["window_start"]).to_numpy()

        for end in range(seq_len - 1, len(group), stride):
            start = end - seq_len + 1
            span = pd.Timestamp(times[end]) - pd.Timestamp(times[start])
            if span > max_gap:
                continue
            X_parts.append(features[start : end + 1])
            y_parts.append(targets[end])
            meta_parts.append({"agent_id": str(agent_id), "window_start": pd.Timestamp(times[end])})

    if not X_parts:
        raise SystemExit("No sequences produced. Try a shorter --seq_len or a larger --max_gap_minutes.")
    return np.stack(X_parts), np.array(y_parts), pd.DataFrame(meta_parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build per-agent window sequences for ARGOS-LAB")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    parser.add_argument("--dataset", default="ARGOS-LAB")
    parser.add_argument("--pipeline", default="binary", choices=["binary", "multiclass", "taxonomy"])
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--feature_set", default="behavioral", choices=["full", "nosignature", "behavioral"])
    parser.add_argument("--seq_len", type=int, default=12, help="windows per sequence (1 min each)")
    parser.add_argument("--stride", type=int, default=1)
    parser.add_argument("--max_gap_minutes", type=float, default=60.0)
    parser.add_argument("--out_dir", default=None, help="defaults to <dataset root>/sequences")
    args = parser.parse_args()

    if args.split_mode == "random":
        raise SystemExit(
            "A random split shuffles windows, so consecutive sequences would leak across "
            "train/test. Use --split_mode date or groupkfold."
        )

    feature_cols = resolve_feature_set(args.feature_set)
    root = mode_root("src/models/ARGOS_LAB/datasets", args.split_mode, args.dataset, args.fold)
    out_root = Path(args.out_dir) if args.out_dir else root / "sequences" / f"{args.pipeline}__{args.feature_set}__L{args.seq_len}"
    out_root = resolve_from_root(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    print("== prepare_sequence_dataset (ARGOS-LAB) ==")
    print(f"Dataset    : {args.dataset}  pipeline={args.pipeline}  split_mode={args.split_mode}")
    print(f"Sequence   : len={args.seq_len} stride={args.stride} features={len(feature_cols)} ({args.feature_set})")
    print(f"Output     : {out_root}\n")

    summary: Dict[str, Dict] = {}
    for split in SPLITS:
        folder = split_folder("src/models/ARGOS_LAB/datasets", args.split_mode, args.dataset, args.pipeline, split, args.fold)
        paths = list_parquets(folder)
        if not paths:
            raise SystemExit(f"No parquet files in {folder}. Run prepare_dataset.py first.")
        df = pd.concat([pd.read_parquet(path) for path in paths], ignore_index=True)

        X, y, meta = build_sequences(df, feature_cols, args.seq_len, args.stride, args.max_gap_minutes)
        np.save(out_root / f"X_{split}.npy", X)
        np.save(out_root / f"y_{split}.npy", y)
        meta.to_parquet(out_root / f"meta_{split}.parquet", index=False)

        counts = {str(k): int(v) for k, v in pd.Series(y).value_counts().items()}
        summary[split] = {"sequences": int(len(X)), "shape": list(X.shape), "windows_in": int(len(df)), "label_counts": counts}
        print(f"  {split:<6} windows={len(df):>7,} -> sequences={len(X):>7,}  shape={X.shape}  {counts}")

    (out_root / "sequence_spec.json").write_text(
        json.dumps(
            {
                "dataset": args.dataset,
                "pipeline": args.pipeline,
                "split_mode": args.split_mode,
                "fold": args.fold,
                "feature_set": args.feature_set,
                "feature_columns": feature_cols,
                "seq_len": args.seq_len,
                "stride": args.stride,
                "max_gap_minutes": args.max_gap_minutes,
                "splits": summary,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nSaved: {out_root}")


if __name__ == "__main__":
    main()
