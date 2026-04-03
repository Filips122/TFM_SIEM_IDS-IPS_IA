#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import io
import json
import tarfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


DEFAULT_ROOT = Path("out/UGR16")
DEFAULT_OUT = Path("out/UGR16_analysis")

MAIN_CSV_ARCHIVE_SUFFIX = "_csv.tar.gz"
NFCAPD_ARCHIVE_SUFFIX = "_nfcapd.tar.gz"
ATTACK_TS_PREFIX = "attack_ts_"
ATTACK_ARCHIVE_PREFIXES = ("blacklist_", "spam_", "sshscan_", "udpscan_")
MAIN_FLOW_PREFIXES = ("march_", "april_", "may_", "june_", "july_", "august_")

MISSING_TOKENS = {"", "?", "-", "na", "n/a", "null", "none", "nan"}
MONTH_ORDER = {
    "March 2016": 3,
    "April 2016": 4,
    "May 2016": 5,
    "June 2016": 6,
    "July 2016": 7,
    "August 2016": 8,
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_from_root(p: str | Path) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


def safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def human_mb(size: int) -> str:
    return f"{size / (1024 * 1024):.2f} MB"


def rel_to(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except Exception:
        return str(path)


def normalize_value(value: object) -> str:
    s = str(value).strip()
    return "" if s.lower() in MISSING_TOKENS else s


def is_number_token(value: str) -> bool:
    s = value.strip()
    if not s:
        return False
    try:
        float(s)
        return True
    except Exception:
        return False


def guess_delimiter(text: str) -> str:
    candidates = [",", ";", "\t", "|"]
    sample = text[:65536]

    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=candidates)
        return dialect.delimiter
    except Exception:
        lines = [ln for ln in sample.splitlines() if ln.strip()]
        if not lines:
            return ","
        first = lines[0]
        scored = sorted(((first.count(c), c) for c in candidates), reverse=True)
        return scored[0][1] if scored[0][0] > 0 else ","


def looks_like_header(row: List[str]) -> bool:
    if not row:
        return False
    alpha = 0
    numeric = 0
    for cell in row:
        s = cell.strip()
        if not s:
            continue
        if any(ch.isalpha() for ch in s):
            alpha += 1
        if is_number_token(s):
            numeric += 1
    if alpha == 0:
        return False
    return alpha >= max(1, len(row) // 2) and numeric <= len(row) // 3


def generic_columns(n_fields: int) -> List[str]:
    return [f"col_{i + 1}" for i in range(n_fields)]


def sanitize_name(name: str) -> str:
    out = name.replace(".tar.gz", "").replace(".csv", "")
    out = out.replace(" ", "_").replace("#", "num")
    out = out.replace("/", "_").replace("\\", "_")
    return out


def is_probably_text_blob(blob: bytes) -> bool:
    if not blob:
        return False

    # If null bytes appear, this is very likely binary.
    if b"\x00" in blob:
        return False

    printable = 0
    for b in blob:
        if b in (9, 10, 13) or 32 <= b <= 126:
            printable += 1
    return (printable / len(blob)) >= 0.75


def month_week_from_path(path: Path, root: Path) -> tuple[str, str, str]:
    rel = path.resolve().relative_to(root.resolve())
    parts = rel.parts
    month = parts[0] if len(parts) >= 1 else "UnknownMonth"
    week = parts[1] if len(parts) >= 2 else "UnknownWeek"
    return month, week, f"{month} | {week}"


def week_sort_key(week_key: str) -> tuple[int, int, str]:
    month, _, week = week_key.partition(" | ")
    month_idx = MONTH_ORDER.get(month, 99)

    digits = ""
    for ch in week:
        if ch.isdigit():
            digits += ch
    week_num = int(digits) if digits else 99
    return month_idx, week_num, week_key


def choose_col(columns: List[str], candidates: List[str]) -> Optional[str]:
    low = {c.lower(): c for c in columns}
    for cand in candidates:
        if cand.lower() in low:
            return low[cand.lower()]
    for c in columns:
        cl = c.lower()
        for cand in candidates:
            if cand.lower() in cl:
                return c
    return None


@dataclass
class InventoryEntry:
    file: str
    month: str
    week: str
    week_key: str
    kind: str
    size_bytes: int
    size_human: str


@dataclass
class AttackFileSummary:
    file: str
    month: str
    week: str
    week_key: str
    rows: int
    attack_minutes: int
    attack_ratio_pct: float
    time_start: Optional[str]
    time_end: Optional[str]
    family_minutes: Dict[str, int]


@dataclass
class MainArchiveSummary:
    file: str
    month: str
    week: str
    week_key: str
    size_bytes: int
    size_human: str
    csv_members: int
    sampled_rows: int
    bad_rows: int
    delimiter: str
    n_cols: int
    columns: List[str]
    missing_pct_by_col: Dict[str, float]
    sample_profile_by_col: Dict[str, Dict[str, object]]


def discover_files(root: Path) -> tuple[List[InventoryEntry], List[Path], List[Path], List[Path], List[Path]]:
    inventory: List[InventoryEntry] = []
    attack_ts_files: List[Path] = []
    main_csv_archives: List[Path] = []
    attack_csv_archives: List[Path] = []
    nfcapd_archives: List[Path] = []

    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        name = p.name.lower()
        month, week, week_key = month_week_from_path(p, root)
        size_bytes = int(p.stat().st_size)

        kind = "other"
        if name.startswith(ATTACK_TS_PREFIX) and name.endswith(".csv"):
            kind = "attack_ts"
            attack_ts_files.append(p)
        elif name.endswith(NFCAPD_ARCHIVE_SUFFIX):
            kind = "nfcapd_archive"
            nfcapd_archives.append(p)
        elif name.endswith(MAIN_CSV_ARCHIVE_SUFFIX):
            if name.startswith(MAIN_FLOW_PREFIXES):
                kind = "main_csv_archive"
                main_csv_archives.append(p)
            else:
                kind = "attack_csv_archive"
                attack_csv_archives.append(p)

        inventory.append(
            InventoryEntry(
                file=str(p),
                month=month,
                week=week,
                week_key=week_key,
                kind=kind,
                size_bytes=size_bytes,
                size_human=human_mb(size_bytes),
            )
        )

    return inventory, attack_ts_files, main_csv_archives, attack_csv_archives, nfcapd_archives


def analyze_attack_ts(path: Path, root: Path) -> AttackFileSummary:
    month, week, week_key = month_week_from_path(path, root)
    df = pd.read_csv(path, low_memory=False)
    if df.empty:
        return AttackFileSummary(
            file=str(path),
            month=month,
            week=week,
            week_key=week_key,
            rows=0,
            attack_minutes=0,
            attack_ratio_pct=0.0,
            time_start=None,
            time_end=None,
            family_minutes={},
        )

    ts_col = df.columns[0]
    if ts_col != "timestamp":
        df = df.rename(columns={ts_col: "timestamp"})

    non_attack_cols = {"timestamp", "counter(mins)"}
    attack_cols = [c for c in df.columns if c not in non_attack_cols]

    for c in attack_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

    if attack_cols:
        any_attack = (df[attack_cols].sum(axis=1) > 0)
        family_minutes = {c: int((df[c] > 0).sum()) for c in attack_cols}
    else:
        any_attack = pd.Series([False] * len(df))
        family_minutes = {}

    ts = pd.to_datetime(df["timestamp"], errors="coerce") if "timestamp" in df.columns else pd.Series(dtype="datetime64[ns]")
    start = ts.min()
    end = ts.max()

    rows = int(len(df))
    attack_minutes = int(any_attack.sum())
    ratio = round((attack_minutes * 100.0) / rows, 4) if rows > 0 else 0.0

    return AttackFileSummary(
        file=str(path),
        month=month,
        week=week,
        week_key=week_key,
        rows=rows,
        attack_minutes=attack_minutes,
        attack_ratio_pct=ratio,
        time_start=(None if pd.isna(start) else str(start)),
        time_end=(None if pd.isna(end) else str(end)),
        family_minutes=family_minutes,
    )


def build_sample_profile(sample_df: pd.DataFrame, top_k: int) -> tuple[Dict[str, float], Dict[str, Dict[str, object]]]:
    missing_pct: Dict[str, float] = {}
    profile: Dict[str, Dict[str, object]] = {}

    if sample_df.empty:
        return missing_pct, profile

    for col in sample_df.columns:
        raw = sample_df[col].astype(str)
        clean = raw.map(normalize_value)

        miss = int((clean == "").sum())
        missing_pct[col] = round((miss * 100.0) / len(clean), 4) if len(clean) > 0 else 0.0

        non_null = clean[clean != ""]
        top_vals = {str(k): int(v) for k, v in non_null.value_counts().head(top_k).items()}

        numeric = pd.to_numeric(non_null, errors="coerce")
        numeric_ratio = float(numeric.notna().mean()) if len(non_null) > 0 else 0.0
        p: Dict[str, object] = {
            "sample_non_null": int(len(non_null)),
            "sample_unique": int(non_null.nunique(dropna=True)),
            "numeric_ratio": round(numeric_ratio, 4),
            "top_values": top_vals,
        }
        if len(non_null) > 0 and numeric_ratio >= 0.95:
            p["dtype_guess"] = "numeric"
            p["numeric_min"] = float(numeric.min())
            p["numeric_max"] = float(numeric.max())
            p["numeric_mean"] = float(numeric.mean())
        else:
            p["dtype_guess"] = "categorical"
        profile[col] = p

    return missing_pct, profile


def sample_main_csv_archive(
    path: Path,
    root: Path,
    sample_rows: int,
    sample_members: int,
    top_k: int,
    max_member_bytes: int,
) -> tuple[MainArchiveSummary, pd.DataFrame]:
    month, week, week_key = month_week_from_path(path, root)

    columns: List[str] = []
    delimiter = ","
    sampled_rows: List[List[str]] = []
    bad_rows = 0
    csv_members = 0

    with tarfile.open(path, "r:gz") as tar:
        members = [m for m in tar.getmembers() if m.isfile()]

        for member in members[: max(1, sample_members)]:
            if len(sampled_rows) >= sample_rows:
                break

            fh = tar.extractfile(member)
            if fh is None:
                continue

            head = fh.read(min(4096, max_member_bytes))
            if not is_probably_text_blob(head):
                continue

            remainder = b""
            if max_member_bytes > len(head):
                remainder = fh.read(max_member_bytes - len(head))
            raw = head + remainder
            if not raw:
                continue

            csv_members += 1

            text = raw.decode("utf-8", errors="replace")
            delim = guess_delimiter(text)
            lines = [ln for ln in text.splitlines() if ln.strip()]
            if not lines:
                continue

            parsed: List[List[str]] = []
            reader = csv.reader(io.StringIO("\n".join(lines)), delimiter=delim)
            for row in reader:
                if row:
                    parsed.append(row)
            if not parsed:
                continue

            width_counts = Counter(len(r) for r in parsed if len(r) > 0)
            if not width_counts:
                continue

            expected_width = int(width_counts.most_common(1)[0][0])
            filtered_rows = [r for r in parsed if len(r) == expected_width]
            if not filtered_rows:
                continue

            this_header = filtered_rows[0]
            has_header = looks_like_header(this_header)
            data_rows = filtered_rows[1:] if has_header else filtered_rows

            if not columns:
                if has_header:
                    columns = [c.strip() if c.strip() else f"col_{i + 1}" for i, c in enumerate(this_header)]
                else:
                    columns = generic_columns(expected_width)
                delimiter = delim

            expected = len(columns)
            for row in data_rows:
                if len(sampled_rows) >= sample_rows:
                    break
                if len(row) != expected:
                    bad_rows += 1
                    continue
                sampled_rows.append([normalize_value(v) for v in row])

    if not columns:
        sample_df = pd.DataFrame()
        missing_pct, profile = {}, {}
    else:
        sample_df = pd.DataFrame(sampled_rows, columns=columns)
        missing_pct, profile = build_sample_profile(sample_df, top_k=top_k)

    size_bytes = int(path.stat().st_size)
    summary = MainArchiveSummary(
        file=str(path),
        month=month,
        week=week,
        week_key=week_key,
        size_bytes=size_bytes,
        size_human=human_mb(size_bytes),
        csv_members=csv_members,
        sampled_rows=int(len(sampled_rows)),
        bad_rows=int(bad_rows),
        delimiter=delimiter,
        n_cols=int(len(columns)),
        columns=columns,
        missing_pct_by_col=missing_pct,
        sample_profile_by_col=profile,
    )
    return summary, sample_df


def save_plot(fig: plt.Figure, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(out_path, dpi=140)
    plt.close(fig)


def plot_inventory_by_kind(inventory_df: pd.DataFrame, out_path: Path) -> None:
    if inventory_df.empty:
        return

    g = (
        inventory_df.groupby("kind", as_index=False)
        .agg(files=("file", "count"), size_gb=("size_bytes", lambda s: float(s.sum()) / (1024 ** 3)))
        .sort_values("size_gb", ascending=False)
    )
    fig, ax = plt.subplots(figsize=(9.5, 4.6))
    ax.bar(g["kind"], g["size_gb"], color="#4C78A8")
    ax.set_title("UGR16 compressed size by file type")
    ax.set_xlabel("file type")
    ax.set_ylabel("size (GB)")
    ax.tick_params(axis="x", rotation=20)
    save_plot(fig, out_path)


def plot_attack_minutes_by_week(attack_df: pd.DataFrame, out_path: Path) -> None:
    if attack_df.empty:
        return

    plot_df = attack_df.sort_values("week_key", key=lambda s: s.map(week_sort_key))
    fig, ax = plt.subplots(figsize=(11, 5.5))
    ax.bar(plot_df["week_key"], plot_df["attack_minutes"], color="#E45756")
    ax.set_title("Attack minutes by week (from attack_ts)")
    ax.set_xlabel("week")
    ax.set_ylabel("attack minutes")
    ax.tick_params(axis="x", rotation=50, labelsize=8)
    save_plot(fig, out_path)


def plot_attack_ratio_by_week(attack_df: pd.DataFrame, out_path: Path) -> None:
    if attack_df.empty:
        return

    plot_df = attack_df.sort_values("week_key", key=lambda s: s.map(week_sort_key))
    fig, ax = plt.subplots(figsize=(11, 5.5))
    ax.bar(plot_df["week_key"], plot_df["attack_ratio_pct"], color="#F58518")
    ax.set_title("Attack ratio by week")
    ax.set_xlabel("week")
    ax.set_ylabel("attack ratio %")
    ax.tick_params(axis="x", rotation=50, labelsize=8)
    save_plot(fig, out_path)


def plot_attack_families(family_totals: Dict[str, int], out_path: Path) -> None:
    if not family_totals:
        return

    items = sorted(family_totals.items(), key=lambda x: x[1], reverse=True)
    names = [k for k, _ in items]
    values = [v for _, v in items]

    fig, ax = plt.subplots(figsize=(9.5, 4.8))
    ax.bar(names, values, color="#54A24B")
    ax.set_title("Attack-family active minutes (global)")
    ax.set_xlabel("attack family")
    ax.set_ylabel("active minutes")
    ax.tick_params(axis="x", rotation=25)
    save_plot(fig, out_path)


def plot_main_archive_sample_rows(main_df: pd.DataFrame, out_path: Path) -> None:
    if main_df.empty:
        return

    plot_df = main_df.sort_values("week_key", key=lambda s: s.map(week_sort_key))
    labels = [sanitize_name(Path(x).name) for x in plot_df["file"]]
    fig, ax = plt.subplots(figsize=(11, 5.5))
    ax.bar(labels, plot_df["sampled_rows"], color="#72B7B2")
    ax.set_title("Sampled rows by main flow archive")
    ax.set_xlabel("archive")
    ax.set_ylabel("sampled rows")
    ax.tick_params(axis="x", rotation=60, labelsize=8)
    save_plot(fig, out_path)


def plot_archive_focus_features(main_summaries: List[MainArchiveSummary], sample_dfs: Dict[str, pd.DataFrame], out_dir: Path) -> None:
    # Create a few focused plots from the first non-empty sampled archive.
    selected: Optional[MainArchiveSummary] = None
    selected_df: Optional[pd.DataFrame] = None
    for s in main_summaries:
        df = sample_dfs.get(s.file)
        if df is not None and not df.empty:
            selected = s
            selected_df = df
            break

    if selected is None or selected_df is None:
        return

    columns = list(selected_df.columns)
    missing_top = sorted(columns, key=lambda c: selected.missing_pct_by_col.get(c, 0.0), reverse=True)[:20]
    miss_vals = [selected.missing_pct_by_col.get(c, 0.0) for c in missing_top]

    fig1, ax1 = plt.subplots(figsize=(11, 4.8))
    ax1.bar(missing_top, miss_vals, color="#4C78A8")
    ax1.set_title(f"Missing % by column (sample) - {Path(selected.file).name}")
    ax1.set_xlabel("column")
    ax1.set_ylabel("missing %")
    ax1.tick_params(axis="x", rotation=45, labelsize=8)
    save_plot(fig1, out_dir / "plots" / "sample_missing_pct_by_col.png")

    time_col = choose_col(columns, ["te", "time", "timestamp", "ts"])
    if time_col:
        vals = pd.to_numeric(selected_df[time_col], errors="coerce").dropna()
        if not vals.empty:
            fig2, ax2 = plt.subplots(figsize=(10.2, 4.6))
            bins = min(70, max(20, int(vals.nunique() ** 0.5)))
            ax2.hist(vals.to_numpy(), bins=bins, color="#72B7B2", edgecolor="white")
            ax2.set_title(f"Time distribution (sample) - {Path(selected.file).name}")
            ax2.set_xlabel(time_col)
            ax2.set_ylabel("count")
            save_plot(fig2, out_dir / "plots" / "sample_time_distribution.png")

    proto_col = choose_col(columns, ["pr", "proto", "protocol"])
    if proto_col:
        vc = selected_df[proto_col].astype(str).map(normalize_value)
        vc = vc[vc != ""].value_counts().head(10)
        if not vc.empty:
            fig3, ax3 = plt.subplots(figsize=(9.8, 4.8))
            vc.sort_values().plot(kind="barh", ax=ax3, color="#54A24B")
            ax3.set_title(f"Top protocol values (sample) - {Path(selected.file).name}")
            ax3.set_xlabel("count")
            ax3.set_ylabel(proto_col)
            save_plot(fig3, out_dir / "plots" / "sample_protocol_top_values.png")


def write_recommended_files_md(
    out_dir: Path,
    root: Path,
    main_csv_archives: List[Path],
    attack_ts_files: List[Path],
    attack_csv_archives: List[Path],
    nfcapd_archives: List[Path],
    attack_df: pd.DataFrame,
) -> None:
    rec_path = out_dir / "RECOMMENDED_FILES.md"

    top_weeks = attack_df.sort_values("attack_ratio_pct", ascending=False).head(5) if not attack_df.empty else pd.DataFrame()

    with rec_path.open("w", encoding="utf-8") as w:
        w.write("# UGR16 Recommended Files for Full App\n\n")
        w.write("## Core files (use these in the full pipeline)\n\n")
        w.write("1. Main weekly flow archives (`*_week*_csv.tar.gz`) for traffic features and baseline behavior.\n")
        w.write("2. Matching attack timeline files (`attack_ts_*.csv`) for weak supervision and evaluation windows.\n")
        w.write("\n")
        w.write(f"Detected main weekly flow archives: {len(main_csv_archives)}\n")
        w.write(f"Detected attack timeline files: {len(attack_ts_files)}\n\n")

        w.write("## Optional files\n\n")
        w.write(
            "- `blacklist_*_csv.tar.gz`, `spam_*_csv.tar.gz`, `sshscan_*_csv.tar.gz`, `udpscan_*_csv.tar.gz`, "
            "`dos_*_csv.tar.gz`, `scan11_*_csv.tar.gz`, `scan44_*_csv.tar.gz`\n"
        )
        w.write("  - Use for targeted validation of specific anomaly families.\n")
        w.write("- `*_nfcapd.tar.gz`\n")
        w.write("  - Keep only if you need original raw flow captures for future reprocessing.\n\n")

        w.write(f"Detected attack-specific archives: {len(attack_csv_archives)}\n")
        w.write(f"Detected nfcapd archives: {len(nfcapd_archives)}\n\n")

        if not top_weeks.empty:
            w.write("## Highest attack-density weeks (good for stress-testing)\n\n")
            for _, r in top_weeks.iterrows():
                w.write(f"- {r['week_key']}: attack_ratio={r['attack_ratio_pct']:.2f}%, attack_minutes={int(r['attack_minutes'])}\n")
            w.write("\n")

        w.write("## Practical split for the thesis app\n\n")
        w.write("- Build baseline and drift models with all main weekly flow archives + all attack_ts files.\n")
        w.write("- Keep August as final holdout month when possible to emulate forward-in-time validation.\n")
        w.write("- Use attack-specific archives only for secondary family-focused experiments.\n\n")

        w.write("## Paths (examples)\n\n")
        for p in sorted(main_csv_archives)[:5]:
            w.write(f"- {rel_to(p, repo_root())}\n")
        for p in sorted(attack_ts_files)[:5]:
            w.write(f"- {rel_to(p, repo_root())}\n")


def write_summary_txt(
    out_dir: Path,
    root: Path,
    inventory_df: pd.DataFrame,
    attack_df: pd.DataFrame,
    family_totals: Dict[str, int],
    main_df: pd.DataFrame,
    sample_rows: int,
    sample_members: int,
) -> None:
    summary_path = out_dir / "SUMMARY.txt"
    with summary_path.open("w", encoding="utf-8") as w:
        w.write("== UGR16 SMALL EDA ==\n\n")
        w.write(f"Repo root: {repo_root()}\n")
        w.write(f"Input root: {root}\n")
        w.write(f"Sample rows per archive: {sample_rows}\n")
        w.write(f"Sample members per archive: {sample_members}\n\n")

        if not inventory_df.empty:
            total_files = int(len(inventory_df))
            total_size = int(inventory_df["size_bytes"].sum())
            w.write("[Inventory]\n")
            w.write(f"files: {total_files}\n")
            w.write(f"compressed size total: {human_mb(total_size)}\n")
            kind_counts = inventory_df["kind"].value_counts().to_dict()
            for k, v in kind_counts.items():
                w.write(f"  - {k}: {v}\n")
            w.write("\n")

        if not attack_df.empty:
            total_rows = int(attack_df["rows"].sum())
            total_attack = int(attack_df["attack_minutes"].sum())
            ratio = round((total_attack * 100.0) / total_rows, 4) if total_rows > 0 else 0.0
            w.write("[attack_ts]\n")
            w.write(f"files: {len(attack_df)}\n")
            w.write(f"total minutes: {total_rows}\n")
            w.write(f"attack minutes: {total_attack}\n")
            w.write(f"global attack ratio: {ratio}%\n")
            if family_totals:
                w.write("top families:\n")
                for k, v in sorted(family_totals.items(), key=lambda x: x[1], reverse=True):
                    w.write(f"  - {k}: {v}\n")
            w.write("\n")

        if not main_df.empty:
            w.write("[main weekly flow archives]\n")
            w.write(f"archives analyzed: {len(main_df)}\n")
            w.write(f"total sampled rows: {int(main_df['sampled_rows'].sum())}\n")
            w.write(f"total bad rows in samples: {int(main_df['bad_rows'].sum())}\n")
            w.write("\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Small EDA for UGR16 weekly folder layout")
    ap.add_argument("--root", type=str, default=str(DEFAULT_ROOT), help="UGR16 root folder")
    ap.add_argument("--out", type=str, default=str(DEFAULT_OUT), help="Output folder")
    ap.add_argument("--sample_rows", type=int, default=15000, help="Rows sampled per main weekly CSV archive")
    ap.add_argument("--sample_members", type=int, default=1, help="CSV members sampled per tar archive")
    ap.add_argument("--top_k", type=int, default=10, help="Top frequent values in profile")
    ap.add_argument("--max_member_bytes", type=int, default=8_000_000, help="Byte cap read per sampled member")
    ap.add_argument("--max_archives", type=int, default=None, help="Optional cap to analyze only the first N main archives")
    ap.add_argument("--no_plots", action="store_true", help="Disable plot generation")
    args = ap.parse_args()

    root = resolve_from_root(args.root)
    out_dir = resolve_from_root(args.out)
    safe_mkdir(out_dir)

    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Root does not exist or is not a folder: {root}")

    inventory, attack_ts_files, main_archives, attack_archives, nfcapd_archives = discover_files(root)
    if not inventory:
        raise SystemExit(f"No files found in: {root}")

    if args.max_archives is not None and args.max_archives > 0:
        main_archives = main_archives[: args.max_archives]

    print("== UGR16 analysis ==")
    print(f"Repo root: {repo_root()}")
    print(f"Input dir: {root}")
    print(f"Out dir  : {out_dir}")
    print(f"Files discovered: {len(inventory)}")
    print(f"Main flow archives: {len(main_archives)}")
    print(f"attack_ts files: {len(attack_ts_files)}")

    inventory_df = pd.DataFrame([asdict(x) for x in inventory])
    inventory_df.to_csv(out_dir / "inventory.csv", index=False)

    attack_summaries = [analyze_attack_ts(p, root=root) for p in attack_ts_files]
    attack_df = pd.DataFrame([asdict(x) for x in attack_summaries]) if attack_summaries else pd.DataFrame()

    family_totals: Dict[str, int] = defaultdict(int)
    if not attack_df.empty:
        expanded = pd.json_normalize(attack_df["family_minutes"]).fillna(0).astype(int)
        attack_df = pd.concat([attack_df.drop(columns=["family_minutes"]), expanded], axis=1)
        for col in expanded.columns:
            family_totals[col] = int(expanded[col].sum())
        attack_df = attack_df.sort_values("week_key", key=lambda s: s.map(week_sort_key)).reset_index(drop=True)
        attack_df.to_csv(out_dir / "attack_weekly_summary.csv", index=False)
        if family_totals:
            pd.DataFrame({"family": list(family_totals.keys()), "active_minutes": list(family_totals.values())}).sort_values(
                "active_minutes", ascending=False
            ).to_csv(out_dir / "attack_family_totals.csv", index=False)

    main_summaries: List[MainArchiveSummary] = []
    sample_dfs: Dict[str, pd.DataFrame] = {}

    for i, archive_path in enumerate(main_archives, start=1):
        print(f"({i}/{len(main_archives)}) sampling: {archive_path.name}")
        summary, sample_df = sample_main_csv_archive(
            path=archive_path,
            root=root,
            sample_rows=args.sample_rows,
            sample_members=args.sample_members,
            top_k=args.top_k,
            max_member_bytes=args.max_member_bytes,
        )
        main_summaries.append(summary)
        sample_dfs[summary.file] = sample_df

        if summary.columns:
            pd.DataFrame(
                {
                    "column": summary.columns,
                    "missing_pct": [summary.missing_pct_by_col.get(c, 0.0) for c in summary.columns],
                    "dtype_guess": [str(summary.sample_profile_by_col.get(c, {}).get("dtype_guess", "unknown")) for c in summary.columns],
                }
            ).to_csv(out_dir / f"{sanitize_name(Path(summary.file).name)}__sample_schema.csv", index=False)

    main_df = pd.DataFrame([asdict(x) for x in main_summaries]) if main_summaries else pd.DataFrame()
    if not main_df.empty:
        main_df = main_df.sort_values("week_key", key=lambda s: s.map(week_sort_key)).reset_index(drop=True)
        main_df.to_csv(out_dir / "main_archive_sample_summary.csv", index=False)

    quick_json = out_dir / "quick_summary.json"
    payload = {
        "inventory": [asdict(x) for x in inventory],
        "attack_ts": [asdict(x) for x in attack_summaries],
        "main_archives": [asdict(x) for x in main_summaries],
        "family_totals": dict(family_totals),
    }
    quick_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    write_summary_txt(
        out_dir=out_dir,
        root=root,
        inventory_df=inventory_df,
        attack_df=attack_df,
        family_totals=dict(family_totals),
        main_df=main_df,
        sample_rows=args.sample_rows,
        sample_members=args.sample_members,
    )

    write_recommended_files_md(
        out_dir=out_dir,
        root=root,
        main_csv_archives=main_archives,
        attack_ts_files=attack_ts_files,
        attack_csv_archives=attack_archives,
        nfcapd_archives=nfcapd_archives,
        attack_df=attack_df,
    )

    if not args.no_plots:
        plot_inventory_by_kind(inventory_df=inventory_df, out_path=out_dir / "plots" / "inventory_size_by_kind.png")
        plot_attack_minutes_by_week(attack_df=attack_df, out_path=out_dir / "plots" / "attack_minutes_by_week.png")
        plot_attack_ratio_by_week(attack_df=attack_df, out_path=out_dir / "plots" / "attack_ratio_by_week.png")
        plot_attack_families(family_totals=dict(family_totals), out_path=out_dir / "plots" / "attack_family_totals.png")
        plot_main_archive_sample_rows(main_df=main_df, out_path=out_dir / "plots" / "sampled_rows_by_archive.png")
        plot_archive_focus_features(main_summaries=main_summaries, sample_dfs=sample_dfs, out_dir=out_dir)

    print("\nDone")
    print(f"Reports: {out_dir}")
    print("- SUMMARY.txt")
    print("- RECOMMENDED_FILES.md")
    print("- inventory.csv")
    print("- attack_weekly_summary.csv (if attack_ts exists)")
    print("- main_archive_sample_summary.csv (if main archives exist)")
    print("- quick_summary.json")


if __name__ == "__main__":
    pd.options.mode.chained_assignment = None
    main()
