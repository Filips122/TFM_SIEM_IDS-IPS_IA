from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from prepare_dataset import PROTOCOL_COLUMNS, discover_main_archives, normalize_label, repo_root, resolve_from_root, select_archives


HELPER_DIR = repo_root() / "src" / "helpers"
if str(HELPER_DIR) not in sys.path:
    sys.path.insert(0, str(HELPER_DIR))

from analyze_ugr_folder import analyze_attack_ts, sample_main_csv_archive  # type: ignore


DEFAULT_IN_DIR = Path("out/UGR16")
DEFAULT_OUT_BASE = Path("src/models/UGR16/artifacts/raw_validation")


def now_run_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def rel_to_repo(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo_root().resolve()))
    except Exception:
        return str(path)


def safe_ratio(num: float, den: float) -> float:
    if den <= 0:
        return 0.0
    return float(num / den)


def clean_string_series(series: pd.Series) -> pd.Series:
    return series.astype(str).str.strip()


def numeric_profile(series: pd.Series) -> Dict[str, float]:
    clean = clean_string_series(series)
    non_empty = clean != ""
    parsed = pd.to_numeric(clean.where(non_empty), errors="coerce")
    non_empty_count = int(non_empty.sum())
    parsed_count = int(parsed.notna().sum())
    non_negative_count = int((parsed.dropna() >= 0).sum())

    return {
        "non_empty_ratio": round(safe_ratio(non_empty_count, len(clean)), 6),
        "numeric_ratio": round(safe_ratio(parsed_count, non_empty_count), 6),
        "non_negative_ratio": round(safe_ratio(non_negative_count, max(parsed_count, 1)), 6),
        "min": None if parsed_count == 0 else float(parsed.min()),
        "max": None if parsed_count == 0 else float(parsed.max()),
    }


def ip_profile(series: pd.Series) -> Dict[str, object]:
    clean = clean_string_series(series)
    non_empty = clean[clean != ""]
    valid = 0
    private = 0
    version_counts: Counter[str] = Counter()

    for value in non_empty:
        try:
            ip_obj = ipaddress.ip_address(value)
        except ValueError:
            continue
        valid += 1
        if ip_obj.is_private:
            private += 1
        version_counts[f"ipv{ip_obj.version}"] += 1

    top_values = non_empty.value_counts(dropna=False).head(10).to_dict()
    return {
        "non_empty_ratio": round(safe_ratio(len(non_empty), len(clean)), 6),
        "parseable_ratio": round(safe_ratio(valid, max(len(non_empty), 1)), 6),
        "private_ratio": round(safe_ratio(private, max(valid, 1)), 6),
        "ip_versions": dict(version_counts),
        "top_values": {str(key): int(value) for key, value in top_values.items()},
    }


def protocol_profile(series: pd.Series) -> Dict[str, object]:
    clean = clean_string_series(series).str.upper()
    non_empty = clean[clean != ""]
    known = non_empty.isin(PROTOCOL_COLUMNS)
    top_values = non_empty.value_counts(dropna=False).head(10).to_dict()
    return {
        "non_empty_ratio": round(safe_ratio(len(non_empty), len(clean)), 6),
        "known_ratio": round(safe_ratio(int(known.sum()), max(len(non_empty), 1)), 6),
        "top_values": {str(key): int(value) for key, value in top_values.items()},
    }


def zero_profile(series: pd.Series) -> Dict[str, float]:
    numeric = numeric_profile(series)
    parsed = pd.to_numeric(clean_string_series(series), errors="coerce").dropna()
    zero_count = int((parsed == 0).sum())
    numeric["zero_ratio"] = round(safe_ratio(zero_count, max(len(parsed), 1)), 6)
    return numeric


def categorical_profile(series: pd.Series, top_k: int = 10) -> Dict[str, object]:
    clean = clean_string_series(series)
    non_empty = clean[clean != ""]
    top_values = non_empty.value_counts(dropna=False).head(top_k).to_dict()
    return {
        "non_empty_ratio": round(safe_ratio(len(non_empty), len(clean)), 6),
        "unique_values": int(non_empty.nunique(dropna=True)),
        "top_values": {str(key): int(value) for key, value in top_values.items()},
    }


def label_profile(series: pd.Series, top_k: int = 10) -> Dict[str, object]:
    normalized = clean_string_series(series).map(normalize_label)
    counts = normalized.value_counts(dropna=False)
    total = int(counts.sum())
    benign_count = int(counts.get("background", 0))
    attack_count = int(total - benign_count)
    attack_only = counts[counts.index != "background"]
    top_values = counts.head(top_k).to_dict()

    return {
        "total_rows": total,
        "background_ratio": round(safe_ratio(benign_count, max(total, 1)), 6),
        "attack_ratio": round(safe_ratio(attack_count, max(total, 1)), 6),
        "unique_labels": int(counts.size),
        "top_values": {str(key): int(value) for key, value in top_values.items()},
        "attack_only_counts": {str(key): int(value) for key, value in attack_only.to_dict().items()},
    }


def check_semantics(report: Dict[str, Dict[str, object]], n_cols: int) -> Dict[str, object]:
    checks = {
        "n_cols_is_13": n_cols == 13,
        "col_1_timestamp_like": float(report["col_1"]["parseable_ratio"]) >= 0.95,
        "col_2_numeric_duration_like": float(report["col_2"]["numeric_ratio"]) >= 0.95,
        "col_3_ip_like": float(report["col_3"]["parseable_ratio"]) >= 0.95,
        "col_4_ip_like": float(report["col_4"]["parseable_ratio"]) >= 0.95,
        "col_5_numeric_port_like": float(report["col_5"]["numeric_ratio"]) >= 0.95,
        "col_6_numeric_port_like": float(report["col_6"]["numeric_ratio"]) >= 0.95,
        "col_7_protocol_like": float(report["col_7"]["known_ratio"]) >= 0.9,
        "col_8_flags_present": float(report["col_8"]["non_empty_ratio"]) >= 0.5,
        "col_9_zero_like": float(report["col_9"]["zero_ratio"]) >= 0.9,
        "col_10_numeric_ttl_like": float(report["col_10"]["numeric_ratio"]) >= 0.95,
        "col_11_numeric_packets_like": float(report["col_11"]["numeric_ratio"]) >= 0.95,
        "col_12_numeric_bytes_like": float(report["col_12"]["numeric_ratio"]) >= 0.95,
        "col_13_label_like": int(report["col_13"]["unique_labels"]) >= 2,
    }
    return {
        "ok": all(checks.values()),
        "checks": checks,
    }


def timestamp_profile(series: pd.Series) -> Dict[str, object]:
    clean = clean_string_series(series)
    non_empty = clean[clean != ""]
    parsed = pd.to_datetime(non_empty, errors="coerce")
    valid = parsed.dropna()
    return {
        "non_empty_ratio": round(safe_ratio(len(non_empty), len(clean)), 6),
        "parseable_ratio": round(safe_ratio(len(valid), max(len(non_empty), 1)), 6),
        "min": None if valid.empty else str(valid.min()),
        "max": None if valid.empty else str(valid.max()),
    }


def analyze_archive(
    archive_path: Path,
    root: Path,
    sample_rows: int,
    sample_members: int,
    top_k: int,
    max_member_bytes: int,
) -> Dict[str, object]:
    summary, sample_df = sample_main_csv_archive(
        archive_path,
        root=root,
        sample_rows=sample_rows,
        sample_members=sample_members,
        top_k=top_k,
        max_member_bytes=max_member_bytes,
    )

    if sample_df.empty or summary.n_cols < 13:
        return {
            "archive": rel_to_repo(archive_path),
            "week_key": summary.week_key,
            "ok": False,
            "reason": "empty_sample_or_insufficient_columns",
            "sampled_rows": int(summary.sampled_rows),
            "n_cols": int(summary.n_cols),
        }

    columns_report: Dict[str, Dict[str, object]] = {
        "col_1": timestamp_profile(sample_df.iloc[:, 0]),
        "col_2": numeric_profile(sample_df.iloc[:, 1]),
        "col_3": ip_profile(sample_df.iloc[:, 2]),
        "col_4": ip_profile(sample_df.iloc[:, 3]),
        "col_5": numeric_profile(sample_df.iloc[:, 4]),
        "col_6": numeric_profile(sample_df.iloc[:, 5]),
        "col_7": protocol_profile(sample_df.iloc[:, 6]),
        "col_8": categorical_profile(sample_df.iloc[:, 7], top_k=top_k),
        "col_9": zero_profile(sample_df.iloc[:, 8]),
        "col_10": numeric_profile(sample_df.iloc[:, 9]),
        "col_11": numeric_profile(sample_df.iloc[:, 10]),
        "col_12": numeric_profile(sample_df.iloc[:, 11]),
        "col_13": label_profile(sample_df.iloc[:, 12], top_k=top_k),
    }
    semantics = check_semantics(columns_report, summary.n_cols)

    attack_ts_path = archive_path.parent / f"attack_ts_{archive_path.stem.replace('_csv.tar', '')}.csv"
    if not attack_ts_path.exists():
        attack_ts_path = next(iter(sorted(archive_path.parent.glob("attack_ts_*.csv"))), None)

    attack_ts_summary = None
    if attack_ts_path is not None and attack_ts_path.exists():
        attack_ts_obj = analyze_attack_ts(attack_ts_path, root=root)
        attack_ts_summary = {
            "file": rel_to_repo(attack_ts_path),
            "rows": int(attack_ts_obj.rows),
            "attack_minutes": int(attack_ts_obj.attack_minutes),
            "attack_ratio_pct": float(attack_ts_obj.attack_ratio_pct),
            "time_start": attack_ts_obj.time_start,
            "time_end": attack_ts_obj.time_end,
            "family_minutes": dict(sorted(attack_ts_obj.family_minutes.items(), key=lambda item: item[1], reverse=True)),
        }

    return {
        "archive": rel_to_repo(archive_path),
        "week_key": summary.week_key,
        "ok": bool(semantics["ok"]),
        "sampled_rows": int(summary.sampled_rows),
        "csv_members": int(summary.csv_members),
        "bad_rows": int(summary.bad_rows),
        "n_cols": int(summary.n_cols),
        "delimiter": summary.delimiter,
        "columns": list(summary.columns),
        "semantic_checks": semantics,
        "column_profiles": columns_report,
        "attack_ts": attack_ts_summary,
    }


def aggregate_multiclass_quality(archive_reports: List[Dict[str, object]]) -> Dict[str, object]:
    total_counts: Counter[str] = Counter()
    attack_counts: Counter[str] = Counter()

    for report in archive_reports:
        label_info = report.get("column_profiles", {}).get("col_13", {})
        top_values = label_info.get("top_values", {})
        attack_only = label_info.get("attack_only_counts", {})
        for key, value in top_values.items():
            total_counts[str(key)] += int(value)
        for key, value in attack_only.items():
            attack_counts[str(key)] += int(value)

    total_attack = int(sum(attack_counts.values()))
    majority_label = None
    majority_share = 0.0
    if attack_counts:
        majority_label, majority_count = attack_counts.most_common(1)[0]
        majority_share = safe_ratio(majority_count, max(total_attack, 1))

    classes_ge_1pct = sorted([label for label, value in attack_counts.items() if safe_ratio(value, max(total_attack, 1)) >= 0.01])
    status = "provisionally_acceptable"
    reasons: List[str] = []
    if len(classes_ge_1pct) < 3:
        status = "review_needed"
        reasons.append("fewer than three attack classes exceed 1% of sampled attack rows")
    if majority_share > 0.85:
        status = "review_needed"
        reasons.append("one attack class dominates more than 85% of sampled attack rows")
    if total_attack < 1000:
        status = "review_needed"
        reasons.append("sampled attack rows are too small for a confident multiclass judgement")

    return {
        "status": status,
        "reasons": reasons,
        "sample_attack_rows": total_attack,
        "attack_class_counts": dict(attack_counts.most_common()),
        "majority_attack_label": majority_label,
        "majority_attack_share": round(majority_share, 6),
        "classes_ge_1pct": classes_ge_1pct,
        "sample_all_label_counts": dict(total_counts.most_common()),
    }


def write_markdown(path: Path, report: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("# UGR16 Raw Semantic Validation\n\n")
        handle.write(f"- subset: {report['subset']}\n")
        handle.write(f"- archives_checked: {report['archives_checked']}\n")
        handle.write(f"- sample_rows_per_archive: {report['sample_rows_per_archive']}\n")
        handle.write(f"- sample_members_per_archive: {report['sample_members_per_archive']}\n")
        handle.write(f"- overall_ok: {report['ok']}\n\n")

        multiclass = report["multiclass_quality"]
        handle.write("## Multiclass Weak-Label Review\n\n")
        handle.write(f"- status: {multiclass['status']}\n")
        handle.write(f"- sampled_attack_rows: {multiclass['sample_attack_rows']}\n")
        handle.write(f"- majority_attack_label: {multiclass['majority_attack_label']}\n")
        handle.write(f"- majority_attack_share: {multiclass['majority_attack_share']}\n")
        if multiclass["reasons"]:
            handle.write("- reasons:\n")
            for reason in multiclass["reasons"]:
                handle.write(f"  - {reason}\n")
        handle.write("\n## Archive Checks\n\n")
        for archive in report["archives"]:
            checks = archive.get("semantic_checks", {}).get("checks", {})
            failed = [name for name, value in checks.items() if not value]
            handle.write(f"### {archive['week_key']}\n\n")
            handle.write(f"- archive: {archive['archive']}\n")
            handle.write(f"- ok: {archive['ok']}\n")
            handle.write(f"- sampled_rows: {archive['sampled_rows']}\n")
            handle.write(f"- n_cols: {archive['n_cols']}\n")
            handle.write(f"- failed_checks: {failed if failed else 'none'}\n")
            attack_ts = archive.get("attack_ts")
            if attack_ts:
                handle.write(f"- attack_ts_ratio_pct: {attack_ts['attack_ratio_pct']}\n")
            label_info = archive.get("column_profiles", {}).get("col_13", {})
            handle.write(f"- sample_label_top_values: {label_info.get('top_values', {})}\n\n")


def build_report(
    archive_reports: List[Dict[str, object]],
    subset: str,
    input_dir: Path,
    sample_rows: int,
    sample_members: int,
    completed_archives: int,
    total_archives: int,
) -> Dict[str, object]:
    return {
        "ok": bool(archive_reports) and all(bool(item.get("ok", False)) for item in archive_reports),
        "subset": subset,
        "input_dir": str(input_dir),
        "archives_checked": len(archive_reports),
        "archives_total": total_archives,
        "completed_archives": completed_archives,
        "sample_rows_per_archive": sample_rows,
        "sample_members_per_archive": sample_members,
        "archives": archive_reports,
        "multiclass_quality": aggregate_multiclass_quality(archive_reports),
    }


def write_report_files(out_dir: Path, report: Dict[str, object], partial: bool) -> None:
    suffix = ".partial" if partial else ""
    (out_dir / f"summary{suffix}.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_markdown(out_dir / f"summary{suffix}.md", report)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_dir", type=str, default=str(DEFAULT_IN_DIR))
    ap.add_argument("--subset", type=str, default="thesis_v1", choices=["thesis_v1", "all_main"])
    ap.add_argument("--sample_rows", type=int, default=20000)
    ap.add_argument("--sample_members", type=int, default=1)
    ap.add_argument("--top_k", type=int, default=10)
    ap.add_argument("--max_member_bytes", type=int, default=10 * 1024 * 1024)
    ap.add_argument("--max_archives", type=int, default=None)
    ap.add_argument("--out_dir", type=str, default=None)
    args = ap.parse_args()

    in_dir = resolve_from_root(args.in_dir)
    if not in_dir.exists() or not in_dir.is_dir():
        raise SystemExit(f"Input folder does not exist: {in_dir}")

    archives = select_archives(discover_main_archives(in_dir), in_dir, args.subset)
    if not archives:
        raise SystemExit(f"No UGR16 archives selected in: {in_dir}")
    if args.max_archives is not None:
        if args.max_archives <= 0:
            raise SystemExit("max_archives must be > 0")
        archives = archives[: args.max_archives]

    out_dir = resolve_from_root(args.out_dir) if args.out_dir else resolve_from_root(DEFAULT_OUT_BASE / now_run_id())
    out_dir.mkdir(parents=True, exist_ok=True)

    archive_reports = []
    total_archives = len(archives)
    for index, archive in enumerate(archives, start=1):
        print(f"[{index}/{total_archives}] {archive.name}", flush=True)
        archive_reports.append(
            analyze_archive(
                archive_path=archive,
                root=in_dir,
                sample_rows=args.sample_rows,
                sample_members=args.sample_members,
                top_k=args.top_k,
                max_member_bytes=args.max_member_bytes,
            )
        )
        partial_report = build_report(
            archive_reports=archive_reports,
            subset=args.subset,
            input_dir=in_dir,
            sample_rows=args.sample_rows,
            sample_members=args.sample_members,
            completed_archives=index,
            total_archives=total_archives,
        )
        write_report_files(out_dir, partial_report, partial=(index < total_archives))

    report = build_report(
        archive_reports=archive_reports,
        subset=args.subset,
        input_dir=in_dir,
        sample_rows=args.sample_rows,
        sample_members=args.sample_members,
        completed_archives=total_archives,
        total_archives=total_archives,
    )
    write_report_files(out_dir, report, partial=False)

    print(json.dumps({
        "ok": report["ok"],
        "out_dir": str(out_dir),
        "archives_checked": report["archives_checked"],
        "multiclass_quality": report["multiclass_quality"],
    }, ensure_ascii=False, indent=2))

    if not report["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()