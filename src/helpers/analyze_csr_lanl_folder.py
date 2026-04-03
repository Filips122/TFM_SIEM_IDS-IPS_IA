#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd


def repo_root() -> Path:
    # <root>/src/helpers/analyze_csr_lanl_folder.py
    return Path(__file__).resolve().parents[2]


def resolve_from_root(p: str | Path) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


DEFAULT_ROOT = Path("out/CSR-LANL")
DEFAULT_OUT = Path("out/CSR-LANL_analysis")

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
) -> FileSummary:
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

    stat = path.stat()
    return FileSummary(
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


def write_summary_txt(out_dir: Path, file_summaries: List[FileSummary], max_rows: Optional[int]) -> None:
    summary_path = out_dir / "SUMMARY.txt"
    total_bytes = sum(s.size_bytes for s in file_summaries)
    total_valid_rows = sum(s.valid_rows for s in file_summaries)
    total_bad_rows = sum(s.bad_rows for s in file_summaries)

    with summary_path.open("w", encoding="utf-8") as w:
        w.write("== CSR-LANL SMALL EDA ==\n\n")
        w.write(f"Repo root: {repo_root()}\n")
        w.write(f"Files analyzed: {len(file_summaries)}\n")
        w.write(f"Compressed size total: {human_mb(total_bytes)}\n")
        w.write(f"Valid rows total: {total_valid_rows}\n")
        w.write(f"Bad rows total: {total_bad_rows}\n")
        w.write(f"Row cap (--max_rows): {max_rows if max_rows is not None else 'none'}\n\n")

        for s in file_summaries:
            w.write(f"[{s.file}]\n")
            w.write(f"size={s.size_human}, delimiter={repr(s.delimiter)}, schema={s.schema_source}\n")
            w.write(
                f"rows_read={s.total_lines_read}, valid_rows={s.valid_rows}, bad_rows={s.bad_rows}, fields={s.expected_fields}\n"
            )
            if s.time_min is not None and s.time_max is not None:
                w.write(f"time_range=[{s.time_min}, {s.time_max}]\n")

            # Show only a few quick highlights to keep this report small.
            for col in s.columns[:5]:
                p = s.sample_profile_by_col.get(col, {})
                miss = s.missing_pct_by_col.get(col, 0.0)
                dtype_guess = p.get("dtype_guess", "unknown")
                unique = p.get("sample_unique", 0)
                w.write(f"  - {col}: missing={miss:.3f}%, dtype_guess={dtype_guess}, sample_unique={unique}\n")
            w.write("\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Small streaming EDA for CSR-LANL .txt.gz files")
    ap.add_argument("--root", type=str, default=str(DEFAULT_ROOT), help="Folder with CSR-LANL .gz files")
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT), help="Output folder for reports")
    ap.add_argument("--sample_rows", type=int, default=100_000, help="Rows kept per file for sample profiling")
    ap.add_argument("--top_k", type=int, default=10, help="Top frequent values kept per sampled column")
    ap.add_argument("--max_rows", type=int, default=None, help="Optional hard cap rows per file for faster debug runs")
    args = ap.parse_args()

    root = resolve_from_root(args.root)
    out_dir = resolve_from_root(args.out)
    safe_mkdir(out_dir)

    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Root does not exist or is not a directory: {root}")

    files = list_gz_files(root)
    if not files:
        raise SystemExit(f"No .gz files found in: {root}")

    print("== CSR-LANL analysis ==")
    print(f"Repo root: {repo_root()}")
    print(f"Input dir: {root}")
    print(f"Out dir  : {out_dir}")
    print(f"Files    : {len(files)}")

    summaries: List[FileSummary] = []
    for i, p in enumerate(files, start=1):
        print(f"\n({i}/{len(files)}) {p.name}")
        s = analyze_gz_file(
            path=p,
            sample_rows_limit=args.sample_rows,
            top_k=args.top_k,
            max_rows=args.max_rows,
        )
        summaries.append(s)

        # Per-file compact CSV with missing stats.
        if s.columns:
            pd.DataFrame(
                {
                    "column": s.columns,
                    "missing_count": [s.missing_by_col.get(c, 0) for c in s.columns],
                    "missing_pct": [s.missing_pct_by_col.get(c, 0.0) for c in s.columns],
                }
            ).to_csv(out_dir / f"{Path(s.file).stem}__missing.csv", index=False)

    quick_json = out_dir / "quick_summary.json"
    quick_json.write_text(json.dumps([asdict(s) for s in summaries], ensure_ascii=False, indent=2), encoding="utf-8")
    write_summary_txt(out_dir=out_dir, file_summaries=summaries, max_rows=args.max_rows)

    print("\nDone")
    print(f"Reports: {out_dir}")
    print("- SUMMARY.txt")
    print("- quick_summary.json")


if __name__ == "__main__":
    pd.options.mode.chained_assignment = None
    main()
