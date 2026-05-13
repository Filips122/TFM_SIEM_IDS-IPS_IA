from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

import pandas as pd

try:
    import pyarrow.parquet as pq
except Exception:
    pq = None


def ensure_parquet_engine() -> None:
    has_pyarrow = importlib.util.find_spec("pyarrow") is not None
    has_fastparquet = importlib.util.find_spec("fastparquet") is not None
    if has_pyarrow or has_fastparquet:
        return

    raise SystemExit(
        "Parquet validation requires either pyarrow or fastparquet. "
        "Install one of them first, for example: pip install pyarrow"
    )


def repo_root() -> Path:
    # <root>/src/models/UGR16/validate_datasets.py
    return Path(__file__).resolve().parents[3]


def resolve_from_root(p: str | Path) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


def list_parquets(folder: Path) -> List[Path]:
    if not folder.exists():
        return []
    return sorted([p for p in folder.rglob("*.parquet") if p.is_file()])


def load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_label_map(obj: Dict) -> Dict[str, int]:
    return {str(key): int(value) for key, value in obj.items()}


def read_schema_names(path: Path) -> List[str]:
    if pq is not None:
        return list(pq.ParquetFile(path).schema_arrow.names)
    return list(pd.read_parquet(path).columns)


def read_target_values(paths: List[Path]) -> Set[str]:
    labels: Set[str] = set()
    for path in paths:
        df = pd.read_parquet(path, columns=["target"])
        labels.update(df["target"].astype(str).dropna().unique().tolist())
    return labels


def read_target_counts(paths: List[Path]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for path in paths:
        df = pd.read_parquet(path, columns=["target"])
        if df.empty:
            continue
        for label, value in df["target"].astype(str).value_counts(dropna=False).items():
            counts[str(label)] = counts.get(str(label), 0) + int(value)
    return counts


def read_distinct_values(paths: List[Path], column: str) -> Set[str]:
    values: Set[str] = set()
    for path in paths:
        df = pd.read_parquet(path, columns=[column])
        values.update(df[column].astype(str).dropna().unique().tolist())
    return values


def read_time_bounds(paths: List[Path]) -> Optional[Tuple[pd.Timestamp, pd.Timestamp]]:
    min_ts: Optional[pd.Timestamp] = None
    max_ts: Optional[pd.Timestamp] = None

    for path in paths:
        df = pd.read_parquet(path, columns=["event_ts"])
        if df.empty:
            continue
        ts = pd.to_datetime(df["event_ts"], errors="coerce").dropna()
        if ts.empty:
            continue
        path_min = ts.min()
        path_max = ts.max()
        min_ts = path_min if min_ts is None else min(min_ts, path_min)
        max_ts = path_max if max_ts is None else max(max_ts, path_max)

    if min_ts is None or max_ts is None:
        return None
    return min_ts, max_ts


def expected_label_order(labels: Sequence[str], pipeline: str) -> List[str]:
    ordered = sorted({str(label) for label in labels if str(label).strip()})
    if pipeline == "binary" and "BENIGN" in ordered and "ATTACK" in ordered:
        return ["BENIGN", "ATTACK"]
    return ordered


def validate_label_domain(pipeline: str, split_to_labels: Dict[str, Set[str]]) -> Dict:
    expected_binary = {"BENIGN", "ATTACK"}

    if pipeline == "binary" or pipeline == "binary_raw":
        merged = set().union(*split_to_labels.values()) if split_to_labels else set()
        ok = merged.issubset(expected_binary) and len(merged) > 0
        return {
            "ok": ok,
            "expected": sorted(expected_binary),
            "observed": sorted(merged),
        }

    if pipeline == "anomaly":
        train_labels = split_to_labels.get("train", set())
        val_labels = split_to_labels.get("val", set())
        test_labels = split_to_labels.get("test", set())
        train_ok = (not train_labels) or train_labels == {"BENIGN"}
        eval_ok = val_labels.issubset(expected_binary) and test_labels.issubset(expected_binary)
        return {
            "ok": train_ok and eval_ok,
            "train_expected": ["BENIGN"],
            "train_observed": sorted(train_labels),
            "val_observed": sorted(val_labels),
            "test_observed": sorted(test_labels),
        }

    merged = set().union(*split_to_labels.values()) if split_to_labels else set()
    bad = {value for value in merged if value.strip() == "" or value.lower() in {"nan", "none", "null"}}
    return {
        "ok": len(merged) > 0 and not bad,
        "observed_count": len(merged),
        "empty_or_invalid_labels": sorted(bad),
    }


def validate_split_schema(paths: List[Path], expected_features: List[str]) -> Dict:
    feature_set = set(expected_features)
    ref_schema: Optional[List[str]] = None
    schema_mismatches: List[str] = []
    feature_order_mismatches: List[str] = []
    missing_feature_columns: Dict[str, List[str]] = {}

    for path in paths:
        schema = read_schema_names(path)
        if ref_schema is None:
            ref_schema = schema
        elif schema != ref_schema:
            schema_mismatches.append(str(path))

        actual_feature_order = [column for column in schema if column in feature_set]
        missing = [column for column in expected_features if column not in schema]
        if actual_feature_order != expected_features or missing:
            feature_order_mismatches.append(str(path))
            if missing:
                missing_feature_columns[str(path)] = missing

    if ref_schema is None:
        return {
            "ok": False,
            "reason": "no parquet files",
        }

    return {
        "ok": not schema_mismatches and not feature_order_mismatches and "target" in ref_schema,
        "schema_consistent_within_split": not schema_mismatches,
        "feature_order_ok": not feature_order_mismatches,
        "has_target_column": "target" in ref_schema,
        "has_label_raw_column": "label_raw" in ref_schema,
        "n_columns": len(ref_schema),
        "reference_schema": ref_schema,
        "schema_mismatches": schema_mismatches[:10],
        "feature_order_mismatches": feature_order_mismatches[:10],
        "missing_feature_columns": missing_feature_columns,
    }


def validate_dataset_label_map(pipeline_root: Path, pipeline: str, train_labels: Set[str]) -> Dict:
    if pipeline in {"anomaly", "binary_raw"}:
        return {"ok": True, "required": False}

    path = pipeline_root / "label_map.json"
    expected = {label: idx for idx, label in enumerate(expected_label_order(sorted(train_labels), pipeline))}

    if not path.exists():
        return {
            "ok": False,
            "required": True,
            "path": str(path),
            "expected": expected,
            "reason": "missing label_map.json",
        }

    observed = normalize_label_map(load_json(path))
    return {
        "ok": bool(expected) and observed == expected,
        "required": True,
        "path": str(path),
        "expected": expected,
        "observed": observed,
    }


def validate_pipeline_split_set(base_dir: Path, pipeline: str, split_map: Dict[str, str], expected_features: List[str]) -> Dict:
    split_details: Dict[str, Dict] = {}
    labels_by_split: Dict[str, Set[str]] = {}
    split_schemas: Dict[str, List[str]] = {}
    missing_splits: List[str] = []

    pipeline_root = base_dir / pipeline
    for split, subdir in split_map.items():
        split_dir = pipeline_root / subdir
        paths = list_parquets(split_dir)
        if not paths:
            split_details[split] = {
                "ok": False,
                "split_dir": str(split_dir),
                "n_files": 0,
                "reason": "no parquet files",
            }
            labels_by_split[split] = set()
            missing_splits.append(split)
            continue

        schema_info = validate_split_schema(paths, expected_features)
        labels = read_target_values(paths)
        labels_by_split[split] = labels
        split_schemas[split] = list(schema_info.get("reference_schema", []))
        split_details[split] = {
            "ok": schema_info.get("ok", False),
            "split_dir": str(split_dir),
            "n_files": len(paths),
            "labels": sorted(labels),
            **schema_info,
        }

    non_empty_schemas = {split: schema for split, schema in split_schemas.items() if schema}
    cross_split_schema_consistent = True
    if non_empty_schemas:
        reference = next(iter(non_empty_schemas.values()))
        cross_split_schema_consistent = all(schema == reference for schema in non_empty_schemas.values())

    labels_info = validate_label_domain(pipeline, labels_by_split)
    label_map_info = validate_dataset_label_map(pipeline_root, pipeline, labels_by_split.get("train", set()))

    ok = (
        bool(non_empty_schemas)
        and cross_split_schema_consistent
        and labels_info.get("ok", False)
        and label_map_info.get("ok", False)
        and all(detail.get("ok", False) for detail in split_details.values() if detail.get("n_files", 0) > 0)
    )

    return {
        "ok": ok,
        "cross_split_schema_consistent": cross_split_schema_consistent,
        "missing_splits": missing_splits,
        "labels": labels_info,
        "label_map": label_map_info,
        "splits": split_details,
    }


def validate_date_temporal_order(mode_dir: Path) -> Dict:
    split_paths = {
        split: list_parquets(mode_dir / "binary_raw" / split)
        for split in ["train", "val", "test"]
    }
    bounds = {split: read_time_bounds(paths) for split, paths in split_paths.items()}

    if any(value is None for value in bounds.values()):
        return {
            "ok": False,
            "reason": "missing event_ts coverage",
            "bounds": {split: None if value is None else [value[0].isoformat(), value[1].isoformat()] for split, value in bounds.items()},
        }

    train_bounds = bounds["train"]
    val_bounds = bounds["val"]
    test_bounds = bounds["test"]
    assert train_bounds is not None and val_bounds is not None and test_bounds is not None

    ok = train_bounds[1] <= val_bounds[0] and val_bounds[1] <= test_bounds[0]
    return {
        "ok": ok,
        "bounds": {
            "train": [train_bounds[0].isoformat(), train_bounds[1].isoformat()],
            "val": [val_bounds[0].isoformat(), val_bounds[1].isoformat()],
            "test": [test_bounds[0].isoformat(), test_bounds[1].isoformat()],
        },
    }


def validate_groupkfold_leakage(fold_dir: Path) -> Dict:
    week_sets = {
        split: read_distinct_values(list_parquets(fold_dir / "binary_raw" / split), "week_key_meta")
        for split in ["train", "val", "test"]
    }
    ok = (
        bool(week_sets["train"])
        and bool(week_sets["val"])
        and bool(week_sets["test"])
        and week_sets["train"].isdisjoint(week_sets["val"])
        and week_sets["train"].isdisjoint(week_sets["test"])
        and week_sets["val"].isdisjoint(week_sets["test"])
    )
    return {
        "ok": ok,
        "week_sets": {split: sorted(values) for split, values in week_sets.items()},
    }


def validate_binary_balance(base_dir: Path) -> Dict:
    details: Dict[str, Dict] = {}
    ok = True
    for split in ["train", "val", "test"]:
        split_dir = base_dir / "binary" / split
        summary_path = split_dir / "balance_summary.json"
        paths = list_parquets(split_dir)
        actual_counts = read_target_counts(paths)
        if not summary_path.exists():
            details[split] = {
                "ok": False,
                "reason": "missing balance_summary.json",
                "actual_counts": actual_counts,
            }
            ok = False
            continue

        summary = load_json(summary_path)
        expected_counts = summary.get("after") or summary.get("label_counts") or {}
        normalized_expected = {str(key): int(value) for key, value in expected_counts.items()}
        split_ok = normalized_expected == actual_counts
        if summary.get("reason") == "stratified_downsample":
            split_ok = split_ok and summary.get("stratify_cols") == ["week_key_meta", "timeline_hour_attack_active_meta"]

        details[split] = {
            "ok": split_ok,
            "summary_path": str(summary_path),
            "actual_counts": actual_counts,
            "expected_counts": normalized_expected,
            "summary_reason": summary.get("reason"),
            "stratify_cols": summary.get("stratify_cols"),
        }
        ok = ok and split_ok

    return {
        "ok": ok,
        "splits": details,
    }


def validate_mode(base: Path, mode: str) -> Dict:
    report: Dict = {"mode": mode, "ok": True, "details": {}}
    mode_dir = base / mode / "UGR16"
    if not mode_dir.exists():
        return {"mode": mode, "ok": False, "error": f"Missing mode directory: {mode_dir}"}

    feature_columns_path = mode_dir / "feature_columns.json"
    if not feature_columns_path.exists():
        return {"mode": mode, "ok": False, "error": f"Missing feature_columns.json: {feature_columns_path}"}
    expected_features = json.loads(feature_columns_path.read_text(encoding="utf-8"))

    if mode == "groupkfold":
        folds = sorted([path for path in mode_dir.glob("fold_*") if path.is_dir()])
        if not folds:
            return {"mode": mode, "ok": False, "error": f"No folds found in {mode_dir}"}

        for fold_dir in folds:
            fold_report: Dict = {}
            for pipeline in ["binary_raw", "binary", "multiclass", "anomaly"]:
                split_map = {"train": "train", "val": "val", "test": "test"}
                if pipeline == "anomaly":
                    split_map = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}
                pipeline_report = validate_pipeline_split_set(fold_dir, pipeline, split_map, expected_features)
                if not pipeline_report.get("ok", False):
                    report["ok"] = False
                fold_report[pipeline] = pipeline_report

            fold_report["grouped_leakage"] = validate_groupkfold_leakage(fold_dir)
            fold_report["binary_balance"] = validate_binary_balance(fold_dir)
            if not fold_report["grouped_leakage"].get("ok", False) or not fold_report["binary_balance"].get("ok", False):
                report["ok"] = False

            report["details"][fold_dir.name] = fold_report

        return report

    for pipeline in ["binary_raw", "binary", "multiclass", "anomaly"]:
        split_map = {"train": "train", "val": "val", "test": "test"}
        if pipeline == "anomaly":
            split_map = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}
        pipeline_report = validate_pipeline_split_set(mode_dir, pipeline, split_map, expected_features)
        if not pipeline_report.get("ok", False):
            report["ok"] = False
        report["details"][pipeline] = pipeline_report

    report["details"]["binary_balance"] = validate_binary_balance(mode_dir)
    if not report["details"]["binary_balance"].get("ok", False):
        report["ok"] = False

    if mode == "date":
        report["details"]["date_temporal_order"] = validate_date_temporal_order(mode_dir)
        if not report["details"]["date_temporal_order"].get("ok", False):
            report["ok"] = False

    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets_base", default="src/models/UGR16/datasets")
    ap.add_argument("--modes", nargs="+", default=["date", "random", "groupkfold"])
    ap.add_argument("--out_json", default=None)
    args = ap.parse_args()

    ensure_parquet_engine()

    base = resolve_from_root(args.datasets_base)
    report = {
        "ok": True,
        "datasets_base": str(base),
        "modes": {},
    }

    for mode in args.modes:
        mode_report = validate_mode(base, mode)
        report["modes"][mode] = mode_report
        if not mode_report.get("ok", False):
            report["ok"] = False

    if args.out_json:
        out_path = resolve_from_root(args.out_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()