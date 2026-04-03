#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


def repo_root() -> Path:
    # <root>/src/helpers/analyze_csr_lanl_folder_v2.py
    return Path(__file__).resolve().parents[2]


def resolve_from_root(p: str | Path) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


DEFAULT_ROOT = Path("out/CSR-LANL")
DEFAULT_OUT = Path("out/CSR-LANL_analysis_v2")

# Field names below follow common LANL examples and are only used as readable defaults.
FILE_SCHEMAS: Dict[str, List[str]] = {
    "auth.txt.gz": [
        "time",
        "src_user",
        "dst_user",
        "src_computer",
        "dst_computer",
        "auth_type",
        "logon_type",
        "auth_orient",
        "result",
    ],
    "dns.txt.gz": ["time", "src_computer", "dst_computer"],
    "flows.txt.gz": [
        "time",
        "duration",
        "src_computer",
        "src_port",
        "dst_computer",
        "dst_port",
        "protocol",
        "packet_count",
        "byte_count",
    ],
    "proc.txt.gz": ["time", "user", "computer", "process", "event_type"],
    "redteam.txt.gz": ["time", "user", "src_computer", "dst_computer"],
}

MISSING_TOKENS = {"", "?", "-", "na", "n/a", "null", "none", "nan"}


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def human_mb(size: int) -> str:
    return f"{size / (1024 * 1024):.2f} MB"


def list_gz_files(root: Path) -> List[Path]:
    out = sorted([p for p in root.glob("*.gz") if p.is_file()])
    return [p for p in out if p.name.lower().endswith(".txt.gz") or p.name.lower().endswith(".gz")]


def sniff_delimiter_gz(path: Path, default: str = ",") -> str:
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as f:
            sample = f.read(8192)
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except Exception:
        return default


def is_missing_token(value: str) -> bool:
    return value.strip().lower() in MISSING_TOKENS


def normalize_value(value: str) -> str:
    v = value.strip()
    return "" if is_missing_token(v) else v


def generic_columns(n_fields: int) -> List[str]:
    return [f"col_{i + 1}" for i in range(n_fields)]


def infer_columns(file_name: str, n_fields: int) -> tuple[List[str], str]:
    schema = FILE_SCHEMAS.get(file_name.lower())
    if schema and len(schema) == n_fields:
        return list(schema), "known_schema"
    if schema and len(schema) != n_fields:
        return generic_columns(n_fields), "fallback_generic"
    return generic_columns(n_fields), "generic"


def parse_time_int(value: str) -> Optional[int]:
    v = value.strip()
    if not v:
        return None
    try:
        return int(v)
    except Exception:
        return None


def sanitize_name(name: str) -> str:
    out = name.replace(".txt.gz", "").replace(".gz", "")
    out = out.replace(".", "_").replace(" ", "_")
    return out


@dataclass
class FileSummary:
    file: str
    size_bytes: int
    size_human: str
    delimiter: str
    schema_source: str
    expected_fields: int
    observed_field_counts: Dict[str, int]
    total_lines_read: int
    valid_rows: int
    bad_rows: int
    sample_rows: int
    columns: List[str]
    missing_by_col: Dict[str, int]
    missing_pct_by_col: Dict[str, float]
    sample_profile_by_col: Dict[str, Dict[str, object]]
    time_min: Optional[int]
    time_max: Optional[int]


def build_sample_profile(
    sample_rows: List[List[str]],
    columns: List[str],
    top_k: int,
) -> Dict[str, Dict[str, object]]:
    if not sample_rows:
        return {c: {"dtype_guess": "unknown", "sample_non_null": 0, "sample_unique": 0, "top_values": {}} for c in columns}

    df = pd.DataFrame(sample_rows, columns=columns)
    profile: Dict[str, Dict[str, object]] = {}

    for c in columns:
        s = df[c].astype(str).map(normalize_value)
        non_null = s[s != ""]
        top_values = {str(k): int(v) for k, v in non_null.value_counts().head(top_k).items()}

        numeric = pd.to_numeric(non_null, errors="coerce")
        numeric_ratio = float(numeric.notna().mean()) if len(non_null) > 0 else 0.0

        data: Dict[str, object] = {
            "sample_non_null": int(len(non_null)),
            "sample_unique": int(non_null.nunique(dropna=True)),
            "top_values": top_values,
            "numeric_ratio": round(numeric_ratio, 4),
        }

        if len(non_null) > 0 and numeric_ratio >= 0.95:
            data["dtype_guess"] = "numeric"
            data["numeric_min"] = float(numeric.min())
            data["numeric_max"] = float(numeric.max())
            data["numeric_mean"] = float(numeric.mean())
        else:
            data["dtype_guess"] = "categorical"

        profile[c] = data

    return profile


def analyze_gz_file(
    path: Path,
    sample_rows_limit: int,
    top_k: int,
    max_rows: Optional[int],
) -> Tuple[FileSummary, pd.DataFrame]:
    delimiter = sniff_delimiter_gz(path)
    schema = FILE_SCHEMAS.get(path.name.lower())
    expected_fields = len(schema) if schema else 0
    columns: List[str] = list(schema) if schema else []
    schema_source = "known_schema" if schema else "unknown"

    observed_counts: Counter[int] = Counter()
    total_lines_read = 0
    valid_rows = 0
    bad_rows = 0
    sample_rows: List[List[str]] = []
    time_min: Optional[int] = None
    time_max: Optional[int] = None
    missing_by_col: Dict[str, int] = {}

    with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as f:
        for line in f:
            if max_rows is not None and total_lines_read >= max_rows:
                break

            total_lines_read += 1
            values = line.rstrip("\r\n").split(delimiter)
            observed_counts[len(values)] += 1

            if expected_fields == 0:
                expected_fields = len(values)
                columns, schema_source = infer_columns(path.name, expected_fields)
                missing_by_col = {c: 0 for c in columns}

            if len(values) != expected_fields:
                bad_rows += 1
                continue

            if not missing_by_col:
                missing_by_col = {c: 0 for c in columns}

            valid_rows += 1

            for i, v in enumerate(values):
                if is_missing_token(v):
                    missing_by_col[columns[i]] += 1

            if columns and columns[0].lower() in {"time", "timestamp", "ts"}:
                t = parse_time_int(values[0])
                if t is not None:
                    if time_min is None or t < time_min:
                        time_min = t
                    if time_max is None or t > time_max:
                        time_max = t

            if len(sample_rows) < sample_rows_limit:
                sample_rows.append([normalize_value(v) for v in values])

    if expected_fields == 0:
        expected_fields = 0
        columns = []
        schema_source = "empty"

    missing_pct = {
        c: (round((missing_by_col.get(c, 0) * 100.0) / valid_rows, 4) if valid_rows > 0 else 0.0)
        for c in columns
    }

    sample_profile = build_sample_profile(sample_rows=sample_rows, columns=columns, top_k=top_k)
    sample_df = pd.DataFrame(sample_rows, columns=columns) if columns else pd.DataFrame()

    stat = path.stat()
    summary = FileSummary(
        file=path.name,
        size_bytes=int(stat.st_size),
        size_human=human_mb(int(stat.st_size)),
        delimiter=delimiter,
        schema_source=schema_source,
        expected_fields=int(expected_fields),
        observed_field_counts={str(k): int(v) for k, v in sorted(observed_counts.items())},
        total_lines_read=int(total_lines_read),
        valid_rows=int(valid_rows),
        bad_rows=int(bad_rows),
        sample_rows=int(len(sample_rows)),
        columns=columns,
        missing_by_col={k: int(v) for k, v in missing_by_col.items()},
        missing_pct_by_col=missing_pct,
        sample_profile_by_col=sample_profile,
        time_min=time_min,
        time_max=time_max,
    )
    return summary, sample_df


def save_plot(fig: plt.Figure, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(out_path, dpi=140)
    plt.close(fig)


def plot_missing_by_col(summary: FileSummary, out_path: Path) -> None:
    if not summary.columns:
        return

    col_order = sorted(summary.columns, key=lambda c: summary.missing_pct_by_col.get(c, 0.0), reverse=True)
    values = [summary.missing_pct_by_col.get(c, 0.0) for c in col_order]

    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.bar(col_order, values, color="#4C78A8")
    ax.set_title(f"Missing % by column - {summary.file}")
    ax.set_xlabel("column")
    ax.set_ylabel("missing %")
    ax.tick_params(axis="x", rotation=45, labelsize=8)
    save_plot(fig, out_path)


def split_numeric_and_categorical(sample_df: pd.DataFrame) -> Tuple[List[str], List[str]]:
    numeric_cols: List[str] = []
    categorical_cols: List[str] = []

    for c in sample_df.columns:
        s = sample_df[c].astype(str).map(normalize_value)
        non_null = s[s != ""]
        if non_null.empty:
            continue

        numeric = pd.to_numeric(non_null, errors="coerce")
        numeric_ratio = float(numeric.notna().mean())
        if numeric_ratio >= 0.95:
            numeric_cols.append(c)
        else:
            categorical_cols.append(c)

    return numeric_cols, categorical_cols


def plot_time_hist(sample_df: pd.DataFrame, file_name: str, out_path: Path) -> None:
    if "time" not in sample_df.columns:
        return
    time_vals = pd.to_numeric(sample_df["time"].astype(str).map(normalize_value), errors="coerce").dropna()
    if time_vals.empty:
        return

    bins = min(60, max(20, int(time_vals.nunique() ** 0.5)))
    fig, ax = plt.subplots(figsize=(9.5, 4.5))
    ax.hist(time_vals.to_numpy(), bins=bins, color="#72B7B2", edgecolor="white")
    ax.set_title(f"Time distribution (sample) - {file_name}")
    ax.set_xlabel("time")
    ax.set_ylabel("count")
    save_plot(fig, out_path)


def plot_numeric_hist(sample_df: pd.DataFrame, col: str, file_name: str, out_path: Path) -> None:
    vals = pd.to_numeric(sample_df[col].astype(str).map(normalize_value), errors="coerce").dropna()
    if vals.empty:
        return

    bins = min(60, max(20, int(len(vals) ** 0.5)))
    fig, ax = plt.subplots(figsize=(9.0, 4.2))
    ax.hist(vals.to_numpy(), bins=bins, color="#F58518", edgecolor="white")
    ax.set_title(f"{col} distribution (sample) - {file_name}")
    ax.set_xlabel(col)
    ax.set_ylabel("count")
    save_plot(fig, out_path)


def plot_top_categories(sample_df: pd.DataFrame, col: str, file_name: str, top_k: int, out_path: Path) -> None:
    s = sample_df[col].astype(str).map(normalize_value)
    vc = s[s != ""].value_counts().head(top_k)
    if vc.empty:
        return

    fig, ax = plt.subplots(figsize=(10.0, 5.0))
    vc.sort_values().plot(kind="barh", ax=ax, color="#54A24B")
    ax.set_title(f"Top {min(top_k, len(vc))} {col} values (sample) - {file_name}")
    ax.set_xlabel("count")
    ax.set_ylabel(col)
    save_plot(fig, out_path)


def generate_file_plots(
    summary: FileSummary,
    sample_df: pd.DataFrame,
    out_dir: Path,
    plot_top_k: int,
) -> None:
    file_key = sanitize_name(summary.file)
    file_plot_dir = out_dir / "plots" / file_key
    safe_mkdir(file_plot_dir)

    plot_missing_by_col(summary, file_plot_dir / "missing_pct_by_col.png")
    if sample_df.empty:
        return

    plot_time_hist(sample_df, summary.file, file_plot_dir / "time_histogram.png")
    numeric_cols, categorical_cols = split_numeric_and_categorical(sample_df)

    # Avoid repeating time histogram when selecting numeric columns.
    numeric_cols = [c for c in numeric_cols if c != "time"]
    for c in numeric_cols[:2]:
        plot_numeric_hist(sample_df, c, summary.file, file_plot_dir / f"numeric_{sanitize_name(c)}_hist.png")

    cat_rank = []
    for c in categorical_cols:
        non_null = sample_df[c].astype(str).map(normalize_value)
        non_null = non_null[non_null != ""]
        if non_null.empty:
            continue
        cat_rank.append((c, int(non_null.nunique())))

    cat_rank.sort(key=lambda x: x[1])
    for c, _ in cat_rank[:2]:
        plot_top_categories(sample_df, c, summary.file, plot_top_k, file_plot_dir / f"top_{sanitize_name(c)}.png")


def generate_global_plots(summaries: List[FileSummary], out_dir: Path) -> None:
    if not summaries:
        return

    safe_mkdir(out_dir / "plots")
    files = [sanitize_name(s.file) for s in summaries]

    fig1, ax1 = plt.subplots(figsize=(9.5, 4.6))
    ax1.bar(files, [s.size_bytes / (1024 * 1024) for s in summaries], color="#4C78A8")
    ax1.set_title("Compressed size by file")
    ax1.set_xlabel("file")
    ax1.set_ylabel("size (MB)")
    ax1.tick_params(axis="x", rotation=30)
    save_plot(fig1, out_dir / "plots" / "global_compressed_size_mb.png")

    fig2, ax2 = plt.subplots(figsize=(9.5, 4.6))
    ax2.bar(files, [s.valid_rows for s in summaries], color="#72B7B2")
    ax2.set_title("Valid rows processed by file")
    ax2.set_xlabel("file")
    ax2.set_ylabel("valid rows")
    ax2.tick_params(axis="x", rotation=30)
    save_plot(fig2, out_dir / "plots" / "global_valid_rows.png")

    fig3, ax3 = plt.subplots(figsize=(9.5, 4.6))
    bad_pct = [((s.bad_rows * 100.0) / s.total_lines_read if s.total_lines_read > 0 else 0.0) for s in summaries]
    ax3.bar(files, bad_pct, color="#E45756")
    ax3.set_title("Bad row percentage by file")
    ax3.set_xlabel("file")
    ax3.set_ylabel("bad rows %")
    ax3.tick_params(axis="x", rotation=30)
    save_plot(fig3, out_dir / "plots" / "global_bad_row_pct.png")


def write_summary_txt(out_dir: Path, file_summaries: List[FileSummary], max_rows: Optional[int], plots_enabled: bool) -> None:
    summary_path = out_dir / "SUMMARY.txt"
    total_bytes = sum(s.size_bytes for s in file_summaries)
    total_valid_rows = sum(s.valid_rows for s in file_summaries)
    total_bad_rows = sum(s.bad_rows for s in file_summaries)

    with summary_path.open("w", encoding="utf-8") as w:
        w.write("== CSR-LANL SMALL EDA V2 ==\n\n")
        w.write(f"Repo root: {repo_root()}\n")
        w.write(f"Files analyzed: {len(file_summaries)}\n")
        w.write(f"Compressed size total: {human_mb(total_bytes)}\n")
        w.write(f"Valid rows total: {total_valid_rows}\n")
        w.write(f"Bad rows total: {total_bad_rows}\n")
        w.write(f"Row cap (--max_rows): {max_rows if max_rows is not None else 'none'}\n")
        w.write(f"Plots enabled: {plots_enabled}\n\n")

        for s in file_summaries:
            w.write(f"[{s.file}]\n")
            w.write(f"size={s.size_human}, delimiter={repr(s.delimiter)}, schema={s.schema_source}\n")
            w.write(
                f"rows_read={s.total_lines_read}, valid_rows={s.valid_rows}, bad_rows={s.bad_rows}, fields={s.expected_fields}\n"
            )
            if s.time_min is not None and s.time_max is not None:
                w.write(f"time_range=[{s.time_min}, {s.time_max}]\n")

            for col in s.columns[:5]:
                p = s.sample_profile_by_col.get(col, {})
                miss = s.missing_pct_by_col.get(col, 0.0)
                dtype_guess = p.get("dtype_guess", "unknown")
                unique = p.get("sample_unique", 0)
                w.write(f"  - {col}: missing={miss:.3f}%, dtype_guess={dtype_guess}, sample_unique={unique}\n")
            w.write("\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Small streaming EDA V2 for CSR-LANL .txt.gz files")
    ap.add_argument("--root", type=str, default=str(DEFAULT_ROOT), help="Folder with CSR-LANL .gz files")
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT), help="Output folder for reports")
    ap.add_argument("--sample_rows", type=int, default=100_000, help="Rows kept per file for sample profiling")
    ap.add_argument("--top_k", type=int, default=10, help="Top frequent values kept per sampled column")
    ap.add_argument("--max_rows", type=int, default=None, help="Optional hard cap rows per file for faster debug runs")
    ap.add_argument("--no_plots", action="store_true", help="Disable plot generation")
    args = ap.parse_args()

    root = resolve_from_root(args.root)
    out_dir = resolve_from_root(args.out)
    safe_mkdir(out_dir)

    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Root does not exist or is not a directory: {root}")

    files = list_gz_files(root)
    if not files:
        raise SystemExit(f"No .gz files found in: {root}")

    plots_enabled = not args.no_plots

    print("== CSR-LANL analysis V2 ==")
    print(f"Repo root: {repo_root()}")
    print(f"Input dir: {root}")
    print(f"Out dir  : {out_dir}")
    print(f"Files    : {len(files)}")
    print(f"Plots    : {plots_enabled}")

    summaries: List[FileSummary] = []
    for i, p in enumerate(files, start=1):
        print(f"\n({i}/{len(files)}) {p.name}")
        s, sample_df = analyze_gz_file(
            path=p,
            sample_rows_limit=args.sample_rows,
            top_k=args.top_k,
            max_rows=args.max_rows,
        )
        summaries.append(s)

        if s.columns:
            pd.DataFrame(
                {
                    "column": s.columns,
                    "missing_count": [s.missing_by_col.get(c, 0) for c in s.columns],
                    "missing_pct": [s.missing_pct_by_col.get(c, 0.0) for c in s.columns],
                }
            ).to_csv(out_dir / f"{Path(s.file).stem}__missing.csv", index=False)

        if plots_enabled:
            generate_file_plots(summary=s, sample_df=sample_df, out_dir=out_dir, plot_top_k=args.top_k)

    if plots_enabled:
        generate_global_plots(summaries=summaries, out_dir=out_dir)

    quick_json = out_dir / "quick_summary.json"
    quick_json.write_text(json.dumps([asdict(s) for s in summaries], ensure_ascii=False, indent=2), encoding="utf-8")
    write_summary_txt(out_dir=out_dir, file_summaries=summaries, max_rows=args.max_rows, plots_enabled=plots_enabled)

    print("\nDone")
    print(f"Reports: {out_dir}")
    print("- SUMMARY.txt")
    print("- quick_summary.json")
    if plots_enabled:
        print("- plots/*.png")


if __name__ == "__main__":
    pd.options.mode.chained_assignment = None
    main()
