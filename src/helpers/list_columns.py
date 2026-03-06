#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Set

import pandas as pd


def clean_colname(c: str) -> str:
    c = c.replace("\ufeff", "")
    c = " ".join(c.split())
    return c.strip()


def list_csv_files(folder: Path) -> List[Path]:
    return sorted([p for p in folder.rglob("*.csv") if p.is_file()])


def collect_columns(csv_paths: List[Path], head_rows: int = 5) -> Set[str]:
    cols: Set[str] = set()
    for p in csv_paths:
        df = pd.read_csv(
            p,
            nrows=head_rows,
            low_memory=False,
            encoding="utf-8",
            encoding_errors="replace",
            on_bad_lines="skip",
        )
        cols.update(clean_colname(c) for c in df.columns)
    return cols


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--base_dir",
        type=str,
        default="C:/Users/xfeli/Desktop/TFM/modelos",
        help="Ruta base del repo (donde está la carpeta src/)",
    )
    ap.add_argument(
        "--ml_rel",
        type=str,
        default="src/datasets/CIC-IDS2017/MachineLearningCVE",
        help="Ruta relativa desde base_dir",
    )
    ap.add_argument(
        "--tl_rel",
        type=str,
        default="src/datasets/CIC-IDS2017/TrafficLabelling",
        help="Ruta relativa desde base_dir",
    )
    args = ap.parse_args()

    base = Path(args.base_dir).expanduser().resolve()
    ml_dir = (base / args.ml_rel).resolve()
    tl_dir = (base / args.tl_rel).resolve()

    ml_csvs = list_csv_files(ml_dir)
    tl_csvs = list_csv_files(tl_dir)

    if not ml_csvs:
        raise SystemExit(f"No se encontraron CSV en: {ml_dir}")
    if not tl_csvs:
        raise SystemExit(f"No se encontraron CSV en: {tl_dir}")

    ml_cols = collect_columns(ml_csvs)
    tl_cols = collect_columns(tl_csvs)

    both = sorted(ml_cols & tl_cols)
    only_ml = sorted(ml_cols - tl_cols)
    only_tl = sorted(tl_cols - ml_cols)

    print("== COLUMN LIST ==")
    print(f"Base dir: {base}")
    print(f"MachineLearningCVE: {ml_dir}  (CSVs: {len(ml_csvs)})")
    print(f"TrafficLabelling : {tl_dir}  (CSVs: {len(tl_csvs)})\n")

    print(f"Columns in BOTH ({len(both)}):")
    for c in both:
        print(" -", c)

    print(f"\nColumns ONLY in MachineLearningCVE ({len(only_ml)}):")
    for c in only_ml:
        print(" -", c)

    print(f"\nColumns ONLY in TrafficLabelling ({len(only_tl)}):")
    for c in only_tl:
        print(" -", c)


if __name__ == "__main__":
    main()