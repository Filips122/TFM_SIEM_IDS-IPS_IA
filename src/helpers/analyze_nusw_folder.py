#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd


def repo_root() -> Path:
    # <root>/src/helpers/analyze_nusw_folder.py
    return Path(__file__).resolve().parents[2]


def resolve_from_root(p: str | Path) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


DEFAULT_ROOT = Path("out/NUSW-NB15")
DEFAULT_OUT = Path("out/NUSW-NB15_analysis")
EXCLUDED_META_PATTERNS = ("features", "list_events", "train_test_network")


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def human_mb(size: int) -> str:
    return f"{size / (1024 * 1024):.2f} MB"


def sniff_delimiter(path: Path, default: str = ",") -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            sample = f.read(8192)
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except Exception:
        return default


def normalize_colname(c: str) -> str:
    c = c.replace("\ufeff", "")
    c = " ".join(c.split())
    return c.strip().lower()


def normalize_attack_cat(v: object) -> str:
    s = str(v or "").strip()
    if s == "" or s.lower() in {"nan", "none", "null"}:
        return "Unknown"
    if s.lower() == "normal":
        return "Normal"
    return s


def list_csvs(root: Path, data_only: bool) -> List[Path]:
    csvs = sorted([p for p in root.glob("*.csv") if p.is_file()])
    if not data_only:
        return csvs
    out = []
    for p in csvs:
        n = p.name.lower()
        if any(k in n for k in EXCLUDED_META_PATTERNS):
            continue
        out.append(p)
    return out


def detect_train_test_files(csvs: List[Path]) -> tuple[Optional[Path], Optional[Path]]:
    train = None
    test = None
    for p in csvs:
        n = p.name.lower()
        if "training-set" in n:
            train = p
        elif "testing-set" in n:
            test = p
    return train, test


@dataclass
class FileQuickSummary:
    file: str
    size_bytes: int
    size_human: str
    delimiter: str
    rows_sampled: int
    n_cols: int
    columns_raw: List[str]
    columns_norm: List[str]
    sample_dtypes: Dict[str, str]
    has_label: bool
    has_attack_cat: bool
    has_proto: bool
    has_service: bool
    has_state: bool


@dataclass
class FileDeepSummary:
    file: str
    rows: int
    missing_by_col: Dict[str, int]
    nonfinite_by_col: Dict[str, int]
    label_counts_binary: Dict[str, int]
    attack_cat_counts: Dict[str, int]
    duplicate_rows_estimate: int


def quick_analyze_csv(path: Path, head_rows: int) -> FileQuickSummary:
    delim = sniff_delimiter(path)
    df = pd.read_csv(
        path,
        sep=delim,
        nrows=head_rows,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace",
        on_bad_lines="skip",
    )

    cols_raw = list(df.columns)
    cols_norm = [normalize_colname(c) for c in cols_raw]
    norm_set = set(cols_norm)
    stat = path.stat()

    return FileQuickSummary(
        file=path.name,
        size_bytes=stat.st_size,
        size_human=human_mb(stat.st_size),
        delimiter=delim,
        rows_sampled=len(df),
        n_cols=len(cols_raw),
        columns_raw=cols_raw,
        columns_norm=cols_norm,
        sample_dtypes={c: str(df[c].dtype) for c in cols_raw},
        has_label=("label" in norm_set),
        has_attack_cat=("attack_cat" in norm_set),
        has_proto=("proto" in norm_set),
        has_service=("service" in norm_set),
        has_state=("state" in norm_set),
    )


def deep_analyze_csv(path: Path, delimiter: str, chunksize: int = 250_000, sample_for_dups: int = 50_000) -> FileDeepSummary:
    reader = pd.read_csv(
        path,
        sep=delimiter,
        chunksize=chunksize,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace",
        on_bad_lines="skip",
    )

    total_rows = 0
    missing_by_col: Dict[str, int] = {}
    nonfinite_by_col: Dict[str, int] = {}
    label_counts_binary: Dict[str, int] = {"BENIGN": 0, "ATTACK": 0}
    attack_cat_counts: Dict[str, int] = {}
    sample_frames: List[pd.DataFrame] = []

    for chunk in reader:
        if chunk.empty:
            continue

        total_rows += len(chunk)
        chunk.columns = [normalize_colname(c) for c in chunk.columns]

        for c in chunk.columns:
            missing_by_col[c] = missing_by_col.get(c, 0) + int(chunk[c].isna().sum())

            if pd.api.types.is_numeric_dtype(chunk[c]):
                arr = chunk[c].to_numpy(copy=False)
                not_finite = int(np.sum(~np.isfinite(arr)))
                nans = int(np.sum(np.isnan(arr)))
                nonfinite_by_col[c] = nonfinite_by_col.get(c, 0) + max(0, not_finite - nans)
            elif chunk[c].dtype == object:
                s = chunk[c].astype(str).str.lower()
                bad = int(s.isin(["inf", "+inf", "-inf", "infinity", "+infinity", "-infinity"]).sum())
                nonfinite_by_col[c] = nonfinite_by_col.get(c, 0) + bad

        # Binary labels
        if "label" in chunk.columns:
            lab = pd.to_numeric(chunk["label"], errors="coerce")
            benign = int((lab == 0).sum())
            attack = int((lab == 1).sum())
            label_counts_binary["BENIGN"] += benign
            label_counts_binary["ATTACK"] += attack
        elif "attack_cat" in chunk.columns:
            ac = chunk["attack_cat"].map(normalize_attack_cat)
            benign = int((ac == "Normal").sum())
            label_counts_binary["BENIGN"] += benign
            label_counts_binary["ATTACK"] += int(len(ac) - benign)

        # Multiclass counts
        if "attack_cat" in chunk.columns:
            ac = chunk["attack_cat"].map(normalize_attack_cat)
            vc = ac.value_counts(dropna=False)
            for k, v in vc.items():
                attack_cat_counts[str(k)] = attack_cat_counts.get(str(k), 0) + int(v)

        if sample_for_dups > 0 and sum(len(x) for x in sample_frames) < sample_for_dups:
            take = min(len(chunk), sample_for_dups - sum(len(x) for x in sample_frames))
            sample_frames.append(chunk.head(take))

    dup_est = 0
    if sample_frames:
        sdf = pd.concat(sample_frames, ignore_index=True)
        dup_est = int(sdf.duplicated().sum())

    return FileDeepSummary(
        file=path.name,
        rows=int(total_rows),
        missing_by_col=missing_by_col,
        nonfinite_by_col=nonfinite_by_col,
        label_counts_binary=label_counts_binary,
        attack_cat_counts=dict(sorted(attack_cat_counts.items(), key=lambda x: x[1], reverse=True)),
        duplicate_rows_estimate=dup_est,
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=str, default=str(DEFAULT_ROOT), help="Folder with NUSW-NB15 CSV files")
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT), help="Output folder for reports")
    ap.add_argument("--deep", action="store_true", help="Run full chunk-based analysis")
    ap.add_argument("--head_rows", type=int, default=8, help="Rows sampled for quick schema preview")
    ap.add_argument("--chunksize", type=int, default=250_000)
    ap.add_argument("--include_meta", action="store_true", help="Also include metadata CSVs such as feature dictionary/list events")
    args = ap.parse_args()

    root = resolve_from_root(args.root)
    out_dir = resolve_from_root(args.out)
    safe_mkdir(out_dir)

    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Root does not exist or is not a folder: {root}")

    csvs = list_csvs(root, data_only=(not args.include_meta))
    if not csvs:
        raise SystemExit(f"No CSV files found in: {root}")

    print("== NUSW-NB15 folder analysis ==")
    print(f"Repo root: {repo_root()}")
    print(f"Input dir: {root}")
    print(f"Out dir  : {out_dir}")
    print(f"Deep mode: {args.deep}")

    quick: List[FileQuickSummary] = []
    deep: List[FileDeepSummary] = []

    for i, csv_path in enumerate(csvs, start=1):
        print(f"\n({i}/{len(csvs)}) {csv_path.name}")
        q = quick_analyze_csv(csv_path, head_rows=args.head_rows)
        quick.append(q)

        schema_df = pd.DataFrame(
            {
                "column_raw": q.columns_raw,
                "column_norm": q.columns_norm,
                "sample_dtype": [q.sample_dtypes[c] for c in q.columns_raw],
            }
        )
        schema_df.to_csv(out_dir / f"{csv_path.stem}__schema.csv", index=False)

        if args.deep:
            d = deep_analyze_csv(csv_path, delimiter=q.delimiter, chunksize=args.chunksize)
            deep.append(d)

            ddf = pd.DataFrame(
                {
                    "column": list(d.missing_by_col.keys()),
                    "missing_count": list(d.missing_by_col.values()),
                    "nonfinite_count": [d.nonfinite_by_col.get(c, 0) for c in d.missing_by_col.keys()],
                }
            )
            ddf.to_csv(out_dir / f"{csv_path.stem}__deep_counts.csv", index=False)

            if d.attack_cat_counts:
                pd.Series(d.attack_cat_counts).to_csv(out_dir / f"{csv_path.stem}__attack_cat_counts.csv", header=["count"])

    quick_json = out_dir / "quick_summary.json"
    quick_json.write_text(json.dumps([asdict(x) for x in quick], ensure_ascii=False, indent=2), encoding="utf-8")

    deep_json = out_dir / "deep_summary.json"
    if args.deep:
        deep_json.write_text(json.dumps([asdict(x) for x in deep], ensure_ascii=False, indent=2), encoding="utf-8")

    train_file, test_file = detect_train_test_files(csvs)

    summary_txt = out_dir / "SUMMARY.txt"
    total_bytes = sum(x.size_bytes for x in quick)
    all_cols = set()
    for q in quick:
        all_cols.update(q.columns_norm)

    with summary_txt.open("w", encoding="utf-8") as w:
        w.write("== NUSW-NB15 SUMMARY ==\n\n")
        w.write(f"CSV files: {len(quick)}\n")
        w.write(f"Total size: {human_mb(total_bytes)}\n")
        w.write(f"Unique normalized columns: {len(all_cols)}\n")
        w.write(f"Detected official train file: {train_file.name if train_file else 'not found'}\n")
        w.write(f"Detected official test file: {test_file.name if test_file else 'not found'}\n\n")

        if args.deep and deep:
            benign = sum(d.label_counts_binary.get("BENIGN", 0) for d in deep)
            attack = sum(d.label_counts_binary.get("ATTACK", 0) for d in deep)
            w.write("[Global Binary Label Estimate]\n")
            w.write(f"BENIGN: {benign}\n")
            w.write(f"ATTACK: {attack}\n\n")

            ac_global: Dict[str, int] = {}
            for d in deep:
                for k, v in d.attack_cat_counts.items():
                    ac_global[k] = ac_global.get(k, 0) + int(v)
            w.write("[Top attack_cat values]\n")
            for k, v in sorted(ac_global.items(), key=lambda x: x[1], reverse=True)[:20]:
                w.write(f"{k}: {v}\n")

    print("\nDone")
    print(f"Reports: {out_dir}")
    print("- SUMMARY.txt")
    print("- quick_summary.json")
    if args.deep:
        print("- deep_summary.json")


if __name__ == "__main__":
    pd.options.mode.chained_assignment = None
    main()
