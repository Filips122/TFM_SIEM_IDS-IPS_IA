#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
analyze_cic_folder.py

Analiza carpetas con múltiples CSV (CIC-IDS2017):
- MachineLearningCVE (features para ML/DL)
- TrafficLabelling (flows etiquetados)

Genera reportes:
- columnas, tipos (muestra), head
- opcional: recorrido completo en chunks (--deep) para missing, non-finite, label counts
- comparación de columnas entre ambas carpetas

Rutas por defecto (relativas a la raíz del repo):
- src/datasets/CIC-IDS2017/MachineLearningCVE
- src/datasets/CIC-IDS2017/TrafficLabelling
- out/

Uso:
  python src/helpers/analyze_cic_folder.py --deep
  python src/helpers/analyze_cic_folder.py --out out --deep
  python src/helpers/analyze_cic_folder.py --ml_dir "..." --flows_dir "..." --deep
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd


# -----------------------------
# Paths (defaults por repo)
# -----------------------------

def repo_root() -> Path:
    # Este archivo está en: <root>/src/helpers/analyze_cic_folder.py
    return Path(__file__).resolve().parents[2]


def resolve_from_root(p: str | Path) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


DEFAULT_DATASET_BASE = Path("src/datasets/CIC-IDS2017")
DEFAULT_ML_DIR = DEFAULT_DATASET_BASE / "MachineLearningCVE"
DEFAULT_FLOWS_DIR = DEFAULT_DATASET_BASE / "TrafficLabelling"
DEFAULT_OUT_DIR = Path("out/CIC-IDS2017")


# -----------------------------
# Utilidades
# -----------------------------

def sniff_delimiter(path: Path, default: str = ",") -> str:
    """Intenta detectar delimitador leyendo un pequeño fragmento."""
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            sample = f.read(8192)
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except Exception:
        return default


def clean_colname(c: str) -> str:
    """Normaliza nombres de columnas para comparar (sin tocar el CSV original)."""
    c2 = c.replace("\ufeff", "")  # BOM
    c2 = " ".join(c2.split())     # colapsa whitespace
    return c2.strip()


def find_label_column(columns: List[str]) -> Optional[str]:
    """Encuentra columna Label (tolerante a espacios/casos)."""
    normalized = {clean_colname(c).lower(): c for c in columns}
    for key in ["label", "class", "attack", "attacktype"]:
        if key in normalized:
            return normalized[key]
    return None


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def human_mb(num_bytes: int) -> str:
    return f"{num_bytes / (1024 * 1024):.2f} MB"


@dataclass
class FileQuickSummary:
    dataset: str
    file: str
    size_bytes: int
    size_human: str
    delimiter: str
    n_cols: int
    columns_raw: List[str]
    columns_clean: List[str]
    sample_dtypes: Dict[str, str]
    label_column: Optional[str]
    sample_head_csv: str


@dataclass
class FileDeepSummary:
    dataset: str
    file: str
    rows: int
    missing_by_col: Dict[str, int]
    nonfinite_by_col: Dict[str, int]
    label_counts: Optional[Dict[str, int]]
    dup_rows_estimate: Optional[int]


# -----------------------------
# Análisis por archivo
# -----------------------------

def quick_analyze_csv(path: Path, dataset_name: str, head_rows: int = 8) -> FileQuickSummary:
    delim = sniff_delimiter(path)
    df_head = pd.read_csv(
        path,
        sep=delim,
        nrows=head_rows,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace",
        on_bad_lines="skip",
    )

    cols_raw = list(df_head.columns)
    cols_clean = [clean_colname(c) for c in cols_raw]
    label_col = find_label_column(cols_raw)
    sample_dtypes = {c: str(df_head[c].dtype) for c in cols_raw}
    sample_head_csv = df_head.to_csv(index=False)

    stat = path.stat()
    return FileQuickSummary(
        dataset=dataset_name,
        file=str(path),
        size_bytes=stat.st_size,
        size_human=human_mb(stat.st_size),
        delimiter=delim,
        n_cols=len(cols_raw),
        columns_raw=cols_raw,
        columns_clean=cols_clean,
        sample_dtypes=sample_dtypes,
        label_column=label_col,
        sample_head_csv=sample_head_csv,
    )


def deep_analyze_csv(
    path: Path,
    dataset_name: str,
    delimiter: str,
    columns_raw: List[str],
    label_column: Optional[str],
    chunksize: int = 250_000,
    max_label_values: int = 200,
    sample_for_dups: int = 50_000,
) -> FileDeepSummary:
    missing = {c: 0 for c in columns_raw}
    nonfinite = {c: 0 for c in columns_raw}
    label_counts: Optional[Dict[str, int]] = {} if label_column else None
    total_rows = 0

    dups_estimate: Optional[int] = None
    sample_frames = []

    reader = pd.read_csv(
        path,
        sep=delimiter,
        chunksize=chunksize,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace",
        on_bad_lines="skip",
    )

    for chunk in reader:
        total_rows += len(chunk)

        for c in columns_raw:
            if c in chunk.columns:
                missing[c] += int(chunk[c].isna().sum())

        for c in chunk.columns:
            if pd.api.types.is_numeric_dtype(chunk[c]):
                arr = chunk[c].to_numpy(copy=False)
                not_finite = np.sum(~np.isfinite(arr))
                nan_cnt = np.sum(np.isnan(arr))
                nonfinite[c] += int(not_finite - nan_cnt)
            else:
                if chunk[c].dtype == object:
                    s = chunk[c].astype(str)
                    nonfinite[c] += int(
                        (s.str.lower().isin(["inf", "+inf", "-inf", "infinity", "+infinity", "-infinity"])).sum()
                    )

        if label_column and label_counts is not None and label_column in chunk.columns:
            vc = chunk[label_column].astype(str).value_counts(dropna=False)
            for k, v in vc.items():
                if len(label_counts) >= max_label_values and k not in label_counts:
                    continue
                label_counts[k] = int(label_counts.get(k, 0) + int(v))

        if sample_for_dups > 0 and sum(len(x) for x in sample_frames) < sample_for_dups:
            take = min(len(chunk), sample_for_dups - sum(len(x) for x in sample_frames))
            sample_frames.append(chunk.head(take))

    if sample_frames:
        sample_df = pd.concat(sample_frames, ignore_index=True)
        dups_estimate = int(sample_df.duplicated().sum())

    return FileDeepSummary(
        dataset=dataset_name,
        file=str(path),
        rows=int(total_rows),
        missing_by_col=missing,
        nonfinite_by_col=nonfinite,
        label_counts=label_counts,
        dup_rows_estimate=dups_estimate,
    )


# -----------------------------
# Análisis por carpeta
# -----------------------------

def collect_csv_files(folder: Path) -> List[Path]:
    return sorted([p for p in folder.rglob("*.csv") if p.is_file()])


def analyze_folder(
    folder: Path,
    dataset_name: str,
    outdir: Path,
    deep: bool,
    head_rows: int,
) -> Tuple[List[FileQuickSummary], List[FileDeepSummary]]:
    csv_files = collect_csv_files(folder)
    safe_mkdir(outdir)

    quick_summaries: List[FileQuickSummary] = []
    deep_summaries: List[FileDeepSummary] = []

    for i, f in enumerate(csv_files, start=1):
        print(f"\n[{dataset_name}] ({i}/{len(csv_files)}) Analizando: {f.name}")
        q = quick_analyze_csv(f, dataset_name=dataset_name, head_rows=head_rows)
        quick_summaries.append(q)

        schema_df = pd.DataFrame({
            "column_raw": q.columns_raw,
            "column_clean": q.columns_clean,
            "sample_dtype": [q.sample_dtypes[c] for c in q.columns_raw],
        })
        schema_path = outdir / f"{dataset_name}__{f.stem}__schema.csv"
        schema_df.to_csv(schema_path, index=False)

        head_path = outdir / f"{dataset_name}__{f.stem}__head.csv"
        head_path.write_text(q.sample_head_csv, encoding="utf-8")

        if deep:
            d = deep_analyze_csv(
                f,
                dataset_name=dataset_name,
                delimiter=q.delimiter,
                columns_raw=q.columns_raw,
                label_column=q.label_column,
            )
            deep_summaries.append(d)

            deep_df = pd.DataFrame({
                "column_raw": q.columns_raw,
                "missing_count": [d.missing_by_col.get(c, 0) for c in q.columns_raw],
                "nonfinite_count": [d.nonfinite_by_col.get(c, 0) for c in q.columns_raw],
            })
            deep_path = outdir / f"{dataset_name}__{f.stem}__deep_counts.csv"
            deep_df.to_csv(deep_path, index=False)

            if d.label_counts is not None:
                lc = pd.Series(d.label_counts).sort_values(ascending=False)
                lc_path = outdir / f"{dataset_name}__{f.stem}__label_counts.csv"
                lc.to_csv(lc_path, header=["count"])

    return quick_summaries, deep_summaries


def compare_columns(quick_summaries: List[FileQuickSummary]) -> pd.DataFrame:
    by_dataset: Dict[str, set] = {}
    for q in quick_summaries:
        by_dataset.setdefault(q.dataset, set()).update(q.columns_clean)

    datasets = sorted(by_dataset.keys())
    if len(datasets) < 2:
        return pd.DataFrame()

    a, b = datasets[0], datasets[1]
    set_a, set_b = by_dataset[a], by_dataset[b]

    only_a = sorted(set_a - set_b)
    only_b = sorted(set_b - set_a)
    both = sorted(set_a & set_b)

    rows = []
    for c in both:
        rows.append({"column_clean": c, "in_" + a: True, "in_" + b: True, "status": "both"})
    for c in only_a:
        rows.append({"column_clean": c, "in_" + a: True, "in_" + b: False, "status": f"only_{a}"})
    for c in only_b:
        rows.append({"column_clean": c, "in_" + a: False, "in_" + b: True, "status": f"only_{b}"})

    return pd.DataFrame(rows).sort_values(["status", "column_clean"]).reset_index(drop=True)


# -----------------------------
# Main
# -----------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ml_dir", type=str, default=str(DEFAULT_ML_DIR), help="Carpeta ML (default: MachineLearningCVE)")
    ap.add_argument("--flows_dir", type=str, default=str(DEFAULT_FLOWS_DIR), help="Carpeta flows (default: TrafficLabelling)")
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT_DIR), help="Carpeta salida (default: out/ en raíz del repo)")
    ap.add_argument("--deep", action="store_true", help="Recorrido completo en chunks para missing/labels/etc (más lento)")
    ap.add_argument("--head_rows", type=int, default=8, help="Filas a guardar como muestra (head)")
    args = ap.parse_args()

    ml_dir = resolve_from_root(args.ml_dir)
    flows_dir = resolve_from_root(args.flows_dir)
    outdir = resolve_from_root(args.out)
    safe_mkdir(outdir)

    if not ml_dir.exists() or not ml_dir.is_dir():
        raise SystemExit(f"ml_dir no existe o no es carpeta: {ml_dir}")
    if not flows_dir.exists() or not flows_dir.is_dir():
        raise SystemExit(f"flows_dir no existe o no es carpeta: {flows_dir}")

    print("== Análisis CIC-IDS2017 (carpetas CSV) ==")
    print(f"Repo root : {repo_root()}")
    print(f"ML dir    : {ml_dir}")
    print(f"Flows dir : {flows_dir}")
    print(f"Out dir   : {outdir}")
    print(f"Deep      : {args.deep}")

    ml_out = outdir / "MachineLearningCVE"
    fl_out = outdir / "TrafficLabelling"
    safe_mkdir(ml_out)
    safe_mkdir(fl_out)

    ml_quick, ml_deep = analyze_folder(ml_dir, "MachineLearningCVE", ml_out, args.deep, args.head_rows)
    fl_quick, fl_deep = analyze_folder(flows_dir, "TrafficLabelling", fl_out, args.deep, args.head_rows)

    all_quick = ml_quick + fl_quick
    all_deep = ml_deep + fl_deep

    quick_json_path = outdir / "quick_summary.json"
    quick_json_path.write_text(json.dumps([asdict(q) for q in all_quick], ensure_ascii=False, indent=2), encoding="utf-8")

    if args.deep:
        deep_json_path = outdir / "deep_summary.json"
        deep_json_path.write_text(json.dumps([asdict(d) for d in all_deep], ensure_ascii=False, indent=2), encoding="utf-8")

    cmp_df = compare_columns(all_quick)
    if not cmp_df.empty:
        cmp_path = outdir / "column_comparison_clean.csv"
        cmp_df.to_csv(cmp_path, index=False)

    summary_txt = outdir / "SUMMARY.txt"
    with summary_txt.open("w", encoding="utf-8") as w:
        w.write("== SUMMARY ==\n\n")
        for dataset_name, quick_list in [("MachineLearningCVE", ml_quick), ("TrafficLabelling", fl_quick)]:
            w.write(f"[{dataset_name}]\n")
            w.write(f"  CSV files: {len(quick_list)}\n")
            total_bytes = sum(q.size_bytes for q in quick_list)
            w.write(f"  Total size: {human_mb(total_bytes)}\n")
            cols = set()
            labels = 0
            for q in quick_list:
                cols.update(q.columns_clean)
                if q.label_column:
                    labels += 1
            w.write(f"  Unique columns (clean): {len(cols)}\n")
            w.write(f"  Files with Label column: {labels}\n\n")

        if not cmp_df.empty:
            w.write("[COLUMN COMPARISON]\n")
            w.write(f"  Columns in both: {(cmp_df['status'] == 'both').sum()}\n")
            w.write(f"  Only in MachineLearningCVE: {(cmp_df['status'] == 'only_MachineLearningCVE').sum()}\n")
            w.write(f"  Only in TrafficLabelling: {(cmp_df['status'] == 'only_TrafficLabelling').sum()}\n\n")

        if args.deep:
            w.write("[DEEP MODE]\n")
            all_label_counts = {}
            for d in all_deep:
                if d.label_counts:
                    for k, v in d.label_counts.items():
                        all_label_counts[k] = all_label_counts.get(k, 0) + v
            if all_label_counts:
                top = sorted(all_label_counts.items(), key=lambda x: x[1], reverse=True)[:30]
                w.write("  Top global label counts:\n")
                for k, v in top:
                    w.write(f"    {k}: {v}\n")
                w.write("\n")

    print("\nListo ✅")
    print(f"Reportes en: {outdir}")
    print(f"- {summary_txt.name}")
    print("- quick_summary.json")
    if args.deep:
        print("- deep_summary.json")
    if not cmp_df.empty:
        print("- column_comparison_clean.csv")


if __name__ == "__main__":
    pd.options.mode.chained_assignment = None
    main()