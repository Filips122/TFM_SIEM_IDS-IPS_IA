#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import pandas as pd

try:
    import pyarrow.parquet as pq
except Exception:  # pragma: no cover - dependency is already required by dataset preparation
    pq = None

from data_loader import resolve_from_root, split_folder


SPLITS = ("train", "val", "test")
PIPELINES = ("binary", "multiclass", "anomaly")
GROUP_FOLD_SPLIT_MODES = {"groupkfold", "redteam_stratified_groupkfold"}
DESIRED_COLUMNS = ["target", "entity", "window_start", "window_end", "redteam_exact", "redteam_near", "source_families"]


@dataclass
class SplitStats:
    rows: int = 0
    label_counts: Dict[str, int] = field(default_factory=dict)
    redteam_exact_windows: int = 0
    redteam_near_windows: int = 0
    entities: Set[str] = field(default_factory=set)
    redteam_entities: Set[str] = field(default_factory=set)
    source_families: Set[str] = field(default_factory=set)
    min_window_start: Optional[int] = None
    max_window_start: Optional[int] = None

    @property
    def attack_windows(self) -> int:
        return sum(count for label, count in self.label_counts.items() if str(label).upper() != "BENIGN")

    @property
    def attack_rate(self) -> float:
        return float(self.attack_windows / self.rows) if self.rows else 0.0

    @property
    def days(self) -> int:
        if self.min_window_start is None or self.max_window_start is None:
            return 0
        return int(self.max_window_start // 86_400 - self.min_window_start // 86_400 + 1)

    def update_time_range(self, values: pd.Series) -> None:
        numeric = pd.to_numeric(values, errors="coerce").dropna()
        if numeric.empty:
            return
        current_min = int(numeric.min())
        current_max = int(numeric.max())
        self.min_window_start = current_min if self.min_window_start is None else min(self.min_window_start, current_min)
        self.max_window_start = current_max if self.max_window_start is None else max(self.max_window_start, current_max)

    def to_json(self) -> Dict[str, Any]:
        return {
            "rows": int(self.rows),
            "label_counts": {str(key): int(value) for key, value in sorted(self.label_counts.items())},
            "attack_windows": int(self.attack_windows),
            "attack_rate": self.attack_rate,
            "redteam_exact_windows": int(self.redteam_exact_windows),
            "redteam_near_windows": int(self.redteam_near_windows),
            "entities": int(len(self.entities)),
            "redteam_entities": int(len(self.redteam_entities)),
            "source_families": sorted(self.source_families),
            "min_window_start": self.min_window_start,
            "max_window_start": self.max_window_start,
            "days": self.days,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate prepared CSR-LANL dataset splits.")
    parser.add_argument("--datasets_base", default="src/models/CSR-LANL/datasets_redteam")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--split_modes", nargs="*", default=["date", "random", "groupkfold", "redteam_stratified_groupkfold"])
    parser.add_argument("--folds", nargs="*", type=int, default=None)
    parser.add_argument("--pipelines", nargs="*", default=list(PIPELINES))
    parser.add_argument("--min_attack_windows_val", type=int, default=10)
    parser.add_argument("--min_attack_windows_test", type=int, default=10)
    parser.add_argument("--min_redteam_entities_test", type=int, default=5)
    parser.add_argument("--out_dir", default="src/models/CSR-LANL/artifacts/split_validation")
    parser.add_argument("--fail_on_error", action="store_true")
    return parser.parse_args()


def parquet_columns(path: Path) -> List[str]:
    if pq is None:
        return list(pd.read_parquet(path, columns=[]).columns)
    return list(pq.ParquetFile(path).schema_arrow.names)


def read_selected_parquet(path: Path) -> pd.DataFrame:
    columns = [column for column in DESIRED_COLUMNS if column in parquet_columns(path)]
    return pd.read_parquet(path, columns=columns)


def parquet_files(folder: Path) -> List[Path]:
    return sorted(path for path in folder.rglob("*.parquet") if path.is_file())


def bool_count(series: pd.Series) -> int:
    if series.dtype == bool:
        return int(series.fillna(False).sum())
    normalized = series.astype(str).str.strip().str.lower()
    return int(normalized.isin(["true", "1", "yes", "y"]).sum())


def update_set_from_series(target: Set[str], series: pd.Series) -> None:
    values = series.dropna().astype(str).str.strip()
    values = values[values != ""]
    target.update(values.tolist())


def read_split_stats(folder: Path) -> Tuple[Optional[SplitStats], Optional[str]]:
    files = parquet_files(folder)
    if not files:
        return None, f"missing_parquet_files:{folder}"
    stats = SplitStats()
    for path in files:
        frame = read_selected_parquet(path)
        stats.rows += int(len(frame))
        if "target" not in frame.columns:
            return None, f"missing_target_column:{path}"
        for label, count in frame["target"].astype(str).value_counts(dropna=False).items():
            stats.label_counts[str(label)] = stats.label_counts.get(str(label), 0) + int(count)
        if "redteam_exact" in frame.columns:
            stats.redteam_exact_windows += bool_count(frame["redteam_exact"])
        if "redteam_near" in frame.columns:
            stats.redteam_near_windows += bool_count(frame["redteam_near"])
        if "entity" in frame.columns:
            update_set_from_series(stats.entities, frame["entity"])
            if "redteam_exact" in frame.columns:
                redteam_mask = frame["redteam_exact"].astype(str).str.strip().str.lower().isin(["true", "1", "yes", "y"])
                update_set_from_series(stats.redteam_entities, frame.loc[redteam_mask, "entity"])
        if "source_families" in frame.columns:
            update_set_from_series(stats.source_families, frame["source_families"])
        if "window_start" in frame.columns:
            stats.update_time_range(frame["window_start"])
    return stats, None


def auto_folds(datasets_base: str, dataset: str, split_mode: str) -> List[int]:
    root = resolve_from_root(datasets_base) / split_mode / dataset
    if not root.exists():
        return []
    folds = []
    for child in root.iterdir():
        if child.is_dir() and child.name.startswith("fold_"):
            try:
                folds.append(int(child.name.split("_", 1)[1]))
            except ValueError:
                continue
    return sorted(folds)


def iter_mode_folds(args: argparse.Namespace, split_mode: str) -> Iterable[Optional[int]]:
    if split_mode not in GROUP_FOLD_SPLIT_MODES:
        yield None
        return
    folds = args.folds if args.folds is not None else auto_folds(args.datasets_base, args.dataset, split_mode)
    if not folds:
        yield 0
        return
    for fold in folds:
        yield fold


def severity(statuses: Sequence[str]) -> str:
    if "fail" in statuses:
        return "fail"
    if "warn" in statuses:
        return "warn"
    return "ok"


def add_issue(issues: List[Dict[str, Any]], status: str, code: str, detail: str) -> None:
    issues.append({"status": status, "code": code, "detail": detail})


def validate_pipeline(
    args: argparse.Namespace,
    split_mode: str,
    fold: Optional[int],
    pipeline: str,
) -> Dict[str, Any]:
    split_stats: Dict[str, SplitStats] = {}
    issues: List[Dict[str, Any]] = []

    for split in SPLITS:
        folder = split_folder(args.datasets_base, split_mode, args.dataset, pipeline, split, fold)
        stats, error = read_split_stats(folder)
        if error:
            add_issue(issues, "fail", "missing_split", error)
            continue
        if stats is not None:
            split_stats[split] = stats
            if stats.rows == 0:
                add_issue(issues, "fail", "empty_split", f"{pipeline}/{split} has zero rows")

    train = split_stats.get("train")
    val = split_stats.get("val")
    test = split_stats.get("test")
    if pipeline == "anomaly" and train and train.attack_windows != 0:
        add_issue(issues, "fail", "anomaly_train_not_benign", f"anomaly train has {train.attack_windows} attack windows")
    if val and val.attack_windows < args.min_attack_windows_val:
        add_issue(issues, "warn", "low_val_attack_windows", f"val has {val.attack_windows} attack windows")
    if test and test.attack_windows < args.min_attack_windows_test:
        add_issue(issues, "warn", "low_test_attack_windows", f"test has {test.attack_windows} attack windows")
    if test and len(test.redteam_entities) < args.min_redteam_entities_test:
        add_issue(issues, "warn", "low_test_redteam_entities", f"test has {len(test.redteam_entities)} red-team entities")

    if split_mode == "date" and train and val and test:
        ranges = [train, val, test]
        labels = ["train", "val", "test"]
        for left, right, left_label, right_label in zip(ranges, ranges[1:], labels, labels[1:]):
            if left.max_window_start is not None and right.min_window_start is not None and left.max_window_start >= right.min_window_start:
                add_issue(
                    issues,
                    "fail",
                    "date_time_overlap",
                    f"{left_label}.max_window_start >= {right_label}.min_window_start",
                )

    if split_mode == "random":
        add_issue(issues, "warn", "random_split_not_operational", "random split is useful as a sanity check, not as primary CSR evidence")

    if split_mode in GROUP_FOLD_SPLIT_MODES and train and val and test:
        pairs = [("train", train), ("val", val), ("test", test)]
        for left_label, left_stats in pairs:
            for right_label, right_stats in pairs:
                if left_label >= right_label:
                    continue
                overlap = left_stats.entities.intersection(right_stats.entities)
                if overlap:
                    add_issue(
                        issues,
                        "fail",
                        "group_entity_overlap",
                        f"{left_label}/{right_label} share {len(overlap)} entities",
                    )

    return {
        "split_mode": split_mode,
        "fold": fold,
        "pipeline": pipeline,
        "status": severity([issue["status"] for issue in issues]),
        "issues": issues,
        "splits": {split: stats.to_json() for split, stats in split_stats.items()},
    }


def main() -> None:
    args = parse_args()
    reports: List[Dict[str, Any]] = []
    for split_mode in args.split_modes:
        for fold in iter_mode_folds(args, split_mode):
            for pipeline in args.pipelines:
                reports.append(validate_pipeline(args, split_mode, fold, pipeline))

    payload: Dict[str, Any] = {
        "dataset": args.dataset,
        "datasets_base": str(resolve_from_root(args.datasets_base)),
        "thresholds": {
            "min_attack_windows_val": args.min_attack_windows_val,
            "min_attack_windows_test": args.min_attack_windows_test,
            "min_redteam_entities_test": args.min_redteam_entities_test,
        },
        "status": severity([report["status"] for report in reports]),
        "reports": reports,
    }
    out_dir = resolve_from_root(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "split_validation.json"
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    rows = []
    for report in reports:
        row = {
            "split_mode": report["split_mode"],
            "fold": report["fold"],
            "pipeline": report["pipeline"],
            "status": report["status"],
            "issue_codes": ";".join(issue["code"] for issue in report["issues"]),
        }
        for split in SPLITS:
            stats = report["splits"].get(split, {})
            row[f"{split}_rows"] = stats.get("rows")
            row[f"{split}_attack_windows"] = stats.get("attack_windows")
            row[f"{split}_redteam_entities"] = stats.get("redteam_entities")
            row[f"{split}_days"] = stats.get("days")
        rows.append(row)
    pd.DataFrame(rows).to_csv(out_dir / "split_validation_summary.csv", index=False)
    print("Saved:", out_path)
    if args.fail_on_error and payload["status"] == "fail":
        raise SystemExit(1)


if __name__ == "__main__":
    main()