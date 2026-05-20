#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pandas as pd


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
    # <root>/src/models/UNSW-NB15/validate_datasets.py
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


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_dataset_profile(profile_path: Path, expected_mode: str) -> Dict[str, Any]:
    if not profile_path.exists():
        return {"ok": False, "error": f"Missing dataset profile: {profile_path}"}

    try:
        profile = read_json(profile_path)
    except Exception as exc:
        return {"ok": False, "error": f"Invalid dataset profile JSON: {exc}"}

    config = profile.get("config", {}) if isinstance(profile, dict) else {}
    errors: List[str] = []
    warnings: List[str] = []

    if profile.get("dataset") != "NUSW-NB15":
        errors.append("dataset_mismatch")
    if config.get("split_mode") != expected_mode:
        errors.append("split_mode_mismatch")
    if not profile.get("config_fingerprint"):
        errors.append("missing_config_fingerprint")
    if not profile.get("input_files"):
        errors.append("missing_input_files")
    if int(profile.get("feature_count") or 0) <= 0:
        errors.append("missing_feature_count")
    if not profile.get("stats") and expected_mode != "groupkfold":
        warnings.append("missing_embedded_stats")

    return {
        "ok": len(errors) == 0,
        "path": str(profile_path),
        "split_mode": config.get("split_mode"),
        "source_set": config.get("source_set"),
        "feature_count": profile.get("feature_count"),
        "input_file_count": profile.get("input_file_count"),
        "config_fingerprint": profile.get("config_fingerprint"),
        "errors": errors,
        "warnings": warnings,
    }


def validate_stats_file(base_dir: Path, pipeline: str, min_positive_eval: int) -> Dict[str, Any]:
    stats_path = base_dir / pipeline / "stats.json"
    if not stats_path.exists():
        return {"ok": False, "error": f"Missing stats file: {stats_path}"}

    try:
        data = read_json(stats_path)
    except Exception as exc:
        return {"ok": False, "error": f"Invalid stats JSON: {exc}"}

    errors: List[str] = []
    warnings: List[str] = []

    def split_value(split: str, key: str) -> int:
        info = data.get(split, {}) if isinstance(data, dict) else {}
        return int(info.get(key) or 0)

    for split in ["train", "val", "test"]:
        if split_value(split, "rows") <= 0:
            errors.append(f"{split}_empty")

    if pipeline == "anomaly":
        if split_value("train", "benign") <= 0:
            errors.append("anomaly_train_without_benign")
        checked_splits = ["val", "test"]
    else:
        if split_value("train", "benign") <= 0:
            errors.append("train_without_benign")
        if split_value("train", "attack") <= 0:
            errors.append("train_without_attack")
        checked_splits = ["val", "test"]

    for split in checked_splits:
        positives = split_value(split, "attack")
        if positives <= 0:
            errors.append(f"{split}_without_attack")
        elif positives < min_positive_eval:
            warnings.append(f"{split}_low_attack_count:{positives}<min_positive_eval:{min_positive_eval}")

    return {
        "ok": len(errors) == 0,
        "path": str(stats_path),
        "errors": errors,
        "warnings": warnings,
        "splits": data,
    }


def read_union_columns(paths: List[Path]) -> Set[str]:
    cols: Set[str] = set()
    for p in paths:
        df = pd.read_parquet(p)
        cols.update(df.columns)
    return cols


def read_target_values(paths: List[Path]) -> Set[str]:
    labels: Set[str] = set()
    for p in paths:
        df = pd.read_parquet(p, columns=["target"])
        labels.update(df["target"].astype(str).dropna().unique().tolist())
    return labels


def validate_label_domain(pipeline: str, split_to_labels: Dict[str, Set[str]]) -> Dict:
    expected_binary = {"BENIGN", "ATTACK"}

    if pipeline == "binary":
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
        ok = train_ok and eval_ok
        return {
            "ok": ok,
            "train_expected": ["BENIGN"],
            "train_observed": sorted(train_labels),
            "val_observed": sorted(val_labels),
            "test_observed": sorted(test_labels),
        }

    merged = set().union(*split_to_labels.values()) if split_to_labels else set()
    bad = {v for v in merged if v.strip() == "" or v.lower() in {"nan", "none", "null"}}
    ok = len(merged) > 0 and not bad
    return {
        "ok": ok,
        "observed_count": len(merged),
        "empty_or_invalid_labels": sorted(bad),
    }


def validate_pipeline_split_set(base_dir: Path, pipeline: str, split_map: Dict[str, str], min_positive_eval: int) -> Dict:
    cols_by_split: Dict[str, Set[str]] = {}
    labels_by_split: Dict[str, Set[str]] = {}
    missing_splits: List[str] = []

    for split, sub in split_map.items():
        pdir = base_dir / pipeline / sub
        paths = list_parquets(pdir)
        if not paths:
            cols_by_split[split] = set()
            labels_by_split[split] = set()
            missing_splits.append(split)
            continue

        cols_by_split[split] = read_union_columns(paths)
        if "target" in cols_by_split[split]:
            labels_by_split[split] = read_target_values(paths)
        else:
            labels_by_split[split] = set()

    non_empty_cols = {k: v for k, v in cols_by_split.items() if v}
    if not non_empty_cols:
        return {
            "ok": False,
            "reason": "no parquet files",
            "missing_splits": missing_splits,
        }

    ref = next(iter(non_empty_cols.values()))
    consistent_schema = all(v == ref for v in non_empty_cols.values())
    has_target = "target" in ref
    has_label_raw = "label_raw" in ref
    labels_info = validate_label_domain(pipeline, labels_by_split)
    stats_info = validate_stats_file(base_dir, pipeline, min_positive_eval=min_positive_eval)
    label_coverage = {"ok": True, "unseen_by_split": {}}
    if pipeline in {"binary", "multiclass"}:
        train_labels = labels_by_split.get("train", set())
        for split in ["val", "test"]:
            unseen = sorted(labels_by_split.get(split, set()) - train_labels)
            if unseen:
                label_coverage["ok"] = False
                label_coverage["unseen_by_split"][split] = unseen

    ok = (
        consistent_schema
        and has_target
        and labels_info.get("ok", False)
        and stats_info.get("ok", False)
        and label_coverage.get("ok", False)
    )

    return {
        "ok": ok,
        "schema_consistent": consistent_schema,
        "has_target_column": has_target,
        "has_label_raw_column": has_label_raw,
        "n_columns": len(ref),
        "splits_present": sorted(non_empty_cols.keys()),
        "missing_splits": missing_splits,
        "labels": labels_info,
        "label_coverage": label_coverage,
        "stats": stats_info,
    }


def validate_mode(base: Path, mode: str, min_positive_eval: int, folds: Optional[List[int]] = None) -> Dict:
    out: Dict = {"mode": mode, "ok": True, "details": {}}

    if mode == "groupkfold":
        mode_dir = base / "groupkfold" / "NUSW-NB15"
        profile_info = validate_dataset_profile(mode_dir / "dataset_profile.json", mode)
        out["profile"] = profile_info
        if not profile_info.get("ok", False):
            out["ok"] = False

        if folds is None:
            fold_dirs = sorted([p for p in mode_dir.glob("fold_*") if p.is_dir()])
        else:
            fold_dirs = [mode_dir / f"fold_{fold}" for fold in folds]

        if not fold_dirs:
            return {"mode": mode, "ok": False, "error": f"No folds found in {mode_dir}"}

        out["selected_folds"] = [fd.name for fd in fold_dirs]
        for fd in fold_dirs:
            if not fd.exists():
                out["ok"] = False
                out["details"][fd.name] = {"ok": False, "error": f"Missing fold directory: {fd}"}
                continue

            fold_info = {}
            fold_profile = validate_dataset_profile(fd / "dataset_profile.json", mode)
            fold_info["dataset_profile"] = fold_profile
            if not fold_profile.get("ok", False):
                out["ok"] = False
            for pipeline in ["binary", "multiclass", "anomaly"]:
                if pipeline == "anomaly":
                    split_map = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}
                else:
                    split_map = {"train": "train", "val": "val", "test": "test"}

                pipeline_info = validate_pipeline_split_set(fd, pipeline, split_map, min_positive_eval)
                if not pipeline_info.get("ok", False):
                    out["ok"] = False
                fold_info[pipeline] = pipeline_info

            out["details"][fd.name] = fold_info

        return out

    mode_dir = base / mode / "NUSW-NB15"
    if not mode_dir.exists():
        return {"mode": mode, "ok": False, "error": f"Missing mode directory: {mode_dir}"}

    profile_info = validate_dataset_profile(mode_dir / "dataset_profile.json", mode)
    out["profile"] = profile_info
    if not profile_info.get("ok", False):
        out["ok"] = False

    mode_info = {}
    for pipeline in ["binary", "multiclass", "anomaly"]:
        if pipeline == "anomaly":
            split_map = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}
        else:
            split_map = {"train": "train", "val": "val", "test": "test"}

        pipeline_info = validate_pipeline_split_set(mode_dir, pipeline, split_map, min_positive_eval)
        if not pipeline_info.get("ok", False):
            out["ok"] = False
        mode_info[pipeline] = pipeline_info

    out["details"] = mode_info
    return out


def expected_label_order(labels: Set[str], pipeline: str) -> List[str]:
    ordered = sorted([str(x) for x in labels])
    if pipeline == "binary" and "BENIGN" in ordered and "ATTACK" in ordered:
        return ["BENIGN", "ATTACK"]
    return ordered


def expected_label_map(base: Path, split_mode: str, pipeline: str, fold: Optional[str]) -> Optional[Dict[str, int]]:
    if pipeline == "anomaly":
        return None

    if split_mode == "groupkfold":
        if fold is None:
            return None
        train_dir = base / "groupkfold" / "NUSW-NB15" / fold / pipeline / "train"
    else:
        train_dir = base / split_mode / "NUSW-NB15" / pipeline / "train"

    paths = list_parquets(train_dir)
    if not paths:
        return None

    labels = read_target_values(paths)
    if not labels:
        return None

    ordered = expected_label_order(labels, pipeline)
    return {lbl: i for i, lbl in enumerate(ordered)}


def normalize_label_map(obj: Dict) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for k, v in obj.items():
        out[str(k)] = int(v)
    return out


def infer_pipeline_from_model(model_name: str) -> Optional[str]:
    low = model_name.lower()
    if "multiclass" in low:
        return "multiclass"
    if "binary" in low:
        return "binary"
    return None


def validate_label_maps(base: Path, artifacts_base: Path, scope: str = "latest") -> Dict:
    result: Dict = {
        "ok": True,
        "checked": 0,
        "details": [],
        "scope": scope,
        "note": "Checks binary and multiclass label_map.json reproducibility against dataset train targets",
    }

    if not artifacts_base.exists():
        result["ok"] = False
        result["error"] = f"Artifacts directory does not exist: {artifacts_base}"
        return result

    candidates: List[Dict] = []

    for model_dir in sorted([p for p in artifacts_base.iterdir() if p.is_dir() and p.name != "compare_models"]):
        pipeline = infer_pipeline_from_model(model_dir.name)
        if pipeline is None:
            continue

        for mode_dir in sorted([p for p in model_dir.iterdir() if p.is_dir()]):
            split_mode = mode_dir.name
            for run_dir in sorted([p for p in mode_dir.iterdir() if p.is_dir()]):
                fold_dirs = sorted([p for p in run_dir.glob("fold_*") if p.is_dir()])

                # Grouped runs: one label_map.json per fold
                if fold_dirs:
                    for fd in fold_dirs:
                        lm_path = fd / "label_map.json"
                        if not lm_path.exists():
                            continue

                        expected = expected_label_map(base, split_mode, pipeline, fd.name)
                        observed = normalize_label_map(json.loads(lm_path.read_text(encoding="utf-8")))
                        candidates.append(
                            {
                                "model": model_dir.name,
                                "pipeline": pipeline,
                                "split_mode": split_mode,
                                "run_id": run_dir.name,
                                "fold": fd.name,
                                "observed": observed,
                                "expected": expected,
                            }
                        )
                    continue

                lm_path = run_dir / "label_map.json"
                if not lm_path.exists():
                    continue

                expected = expected_label_map(base, split_mode, pipeline, None)
                observed = normalize_label_map(json.loads(lm_path.read_text(encoding="utf-8")))
                candidates.append(
                    {
                        "model": model_dir.name,
                        "pipeline": pipeline,
                        "split_mode": split_mode,
                        "run_id": run_dir.name,
                        "fold": None,
                        "observed": observed,
                        "expected": expected,
                    }
                )

    selected: List[Dict]
    if scope == "all":
        selected = candidates
    else:
        latest_by_key: Dict[tuple, Dict] = {}
        for c in candidates:
            key = (c["model"], c["pipeline"], c["split_mode"], c.get("fold"))
            prev = latest_by_key.get(key)
            if prev is None or str(c["run_id"]) > str(prev["run_id"]):
                latest_by_key[key] = c
        selected = list(latest_by_key.values())

    historical_mismatch = 0
    if scope == "latest":
        for c in candidates:
            if c.get("expected") is not None and c.get("observed") != c.get("expected"):
                historical_mismatch += 1

    for c in sorted(selected, key=lambda x: (x["model"], x["split_mode"], str(x.get("fold")), x["run_id"])):
        status = "ok"
        if c["expected"] is None:
            status = "missing_expected"
            result["ok"] = False
        elif c["observed"] != c["expected"]:
            status = "mismatch"
            result["ok"] = False

        c_out = dict(c)
        c_out["status"] = status
        result["details"].append(c_out)
        result["checked"] += 1

    result["historical_mismatch_count"] = historical_mismatch

    if result["checked"] == 0:
        result["ok"] = False
        result["error"] = "No label_map.json files found for binary/multiclass artifacts"

    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets_base", default="src/models/UNSW-NB15/datasets")
    ap.add_argument("--artifacts_base", default="src/models/UNSW-NB15/artifacts")
    ap.add_argument("--label_map_scope", default="none", choices=["none", "latest", "all"])
    ap.add_argument("--min_positive_eval", type=int, default=10)
    ap.add_argument("--modes", nargs="+", default=["random", "groupkfold"])
    ap.add_argument("--folds", nargs="+", type=int, default=None, help="Groupkfold fold numbers to validate. If omitted, all existing fold_* directories are validated.")
    ap.add_argument("--out", default="src/models/UNSW-NB15/datasets/validation_report.json")
    args = ap.parse_args()

    ensure_parquet_engine()

    base = resolve_from_root(args.datasets_base)
    artifacts_base = resolve_from_root(args.artifacts_base)
    report = {"base": str(base), "modes": []}

    global_ok = True
    for mode in args.modes:
        mode_folds = args.folds if mode == "groupkfold" else None
        r = validate_mode(base, mode, min_positive_eval=args.min_positive_eval, folds=mode_folds)
        report["modes"].append(r)
        if not r.get("ok", False):
            global_ok = False

    if args.label_map_scope == "none":
        label_map_report = {"ok": True, "skipped": True, "reason": "label_map_scope=none"}
    else:
        label_map_report = validate_label_maps(base, artifacts_base, scope=args.label_map_scope)
    report["label_mapping"] = label_map_report
    report["artifacts_base"] = str(artifacts_base)
    if not label_map_report.get("ok", False):
        global_ok = False

    report["ok"] = global_ok

    out_path = resolve_from_root(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Validation report written to: {out_path}")
    print(f"Global OK: {global_ok}")
    if not global_ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
