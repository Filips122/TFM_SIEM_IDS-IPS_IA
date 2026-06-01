#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


PIPELINES = ["binary", "multiclass", "anomaly"]
SPLITS = ["train", "val", "test"]
GROUP_FOLD_SPLIT_MODES = {"groupkfold", "redteam_stratified_groupkfold"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_from_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root() / candidate).resolve()


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def has_parquet(folder: Path) -> bool:
    return folder.exists() and any(path.is_file() for path in folder.rglob("*.parquet"))


def split_folder(base_dir: Path, pipeline: str, split: str) -> Path:
    if pipeline == "anomaly":
        sub = {"train": "train_benign", "val": "val_mixed", "test": "test_mixed"}[split]
        return base_dir / "anomaly" / sub
    return base_dir / pipeline / split


def validate_profile(base_dir: Path, expected_mode: str) -> Dict[str, Any]:
    path = base_dir / "dataset_profile.json"
    if not path.exists():
        return {"ok": False, "errors": ["missing_dataset_profile"], "path": str(path)}
    try:
        profile = read_json(path)
    except Exception as exc:
        return {"ok": False, "errors": [f"invalid_dataset_profile:{exc}"], "path": str(path)}

    config = profile.get("config", {}) if isinstance(profile, dict) else {}
    errors: List[str] = []
    warnings: List[str] = []
    if profile.get("dataset") != "CSR-LANL":
        errors.append("dataset_mismatch")
    if config.get("split_mode") != expected_mode:
        errors.append("split_mode_mismatch")
    if not profile.get("config_fingerprint"):
        errors.append("missing_config_fingerprint")
    if profile.get("sampling_profile") != "redteam_centered":
        warnings.append(f"sampling_profile={profile.get('sampling_profile')}")

    redteam = profile.get("redteam_policy", {}) if isinstance(profile, dict) else {}
    if int(redteam.get("matched_redteam_entity_windows") or 0) <= 0:
        errors.append("no_matched_redteam_entity_windows")

    return {
        "ok": len(errors) == 0,
        "path": str(path),
        "sampling_profile": profile.get("sampling_profile"),
        "config_fingerprint": profile.get("config_fingerprint"),
        "matched_redteam_entity_windows": redteam.get("matched_redteam_entity_windows"),
        "redteam_entity_windows": redteam.get("redteam_entity_windows"),
        "errors": errors,
        "warnings": warnings,
    }


def split_value(stats: Dict[str, Any], split: str, key: str) -> int:
    info = stats.get(split, {}) if isinstance(stats, dict) else {}
    return int(info.get(key) or 0)


def validate_stats(base_dir: Path, pipeline: str, min_positive_eval: int) -> Dict[str, Any]:
    path = base_dir / pipeline / "stats.json"
    if not path.exists():
        return {"ok": False, "errors": ["missing_stats"], "warnings": [], "path": str(path)}
    try:
        stats = read_json(path)
    except Exception as exc:
        return {"ok": False, "errors": [f"invalid_stats:{exc}"], "warnings": [], "path": str(path)}

    errors: List[str] = []
    warnings: List[str] = []
    for split in SPLITS:
        if split_value(stats, split, "rows") <= 0:
            errors.append(f"{pipeline}_{split}_empty")

    if pipeline == "anomaly":
        if split_value(stats, "train", "benign") <= 0:
            errors.append("anomaly_train_without_benign")
        eval_splits = ["val", "test"]
    else:
        if split_value(stats, "train", "benign") <= 0:
            errors.append(f"{pipeline}_train_without_benign")
        if split_value(stats, "train", "attack") <= 0:
            errors.append(f"{pipeline}_train_without_attack")
        eval_splits = ["val", "test"]

    for split in eval_splits:
        positives = split_value(stats, split, "attack")
        if positives <= 0:
            errors.append(f"{pipeline}_{split}_without_attack")
        elif positives < min_positive_eval:
            warnings.append(f"{pipeline}_{split}_low_attack_count:{positives}<min_positive_eval:{min_positive_eval}")

    return {"ok": len(errors) == 0, "path": str(path), "errors": errors, "warnings": warnings, "splits": stats}


def validate_split_files(base_dir: Path, pipeline: str) -> Dict[str, Any]:
    missing: List[str] = []
    for split in SPLITS:
        folder = split_folder(base_dir, pipeline, split)
        if not has_parquet(folder):
            missing.append(str(folder))
    return {"ok": len(missing) == 0, "missing": missing}


def validate_dataset_root(base_dir: Path, mode: str, min_positive_eval: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {"path": str(base_dir), "ok": True, "profile": validate_profile(base_dir, mode), "pipelines": {}}
    if not result["profile"].get("ok", False):
        result["ok"] = False

    for pipeline in PIPELINES:
        files = validate_split_files(base_dir, pipeline)
        stats = validate_stats(base_dir, pipeline, min_positive_eval=min_positive_eval)
        result["pipelines"][pipeline] = {"files": files, "stats": stats}
        if not files.get("ok", False) or not stats.get("ok", False):
            result["ok"] = False
    return result


def validate_mode(base: Path, dataset: str, mode: str, min_positive_eval: int) -> Dict[str, Any]:
    mode_root = base / mode / dataset
    if mode in GROUP_FOLD_SPLIT_MODES:
        folds = sorted([path for path in mode_root.glob("fold_*") if path.is_dir()])
        if not folds:
            return {"mode": mode, "ok": False, "error": f"No fold_* directories found in {mode_root}"}
        details = {fold.name: validate_dataset_root(fold, mode, min_positive_eval) for fold in folds}
        return {"mode": mode, "ok": all(item.get("ok", False) for item in details.values()), "details": details}

    if not mode_root.exists():
        return {"mode": mode, "ok": False, "error": f"Missing mode directory: {mode_root}"}
    detail = validate_dataset_root(mode_root, mode, min_positive_eval)
    return {"mode": mode, "ok": detail.get("ok", False), "details": detail}


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate prepared CSR-LANL datasets before training.")
    parser.add_argument("--datasets_base", default="src/models/CSR-LANL/datasets_redteam")
    parser.add_argument("--dataset", default="CSR-LANL")
    parser.add_argument("--modes", nargs="+", default=["date", "redteam_stratified_groupkfold"])
    parser.add_argument("--min_positive_eval", type=int, default=3)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    base = resolve_from_root(args.datasets_base)
    report: Dict[str, Any] = {"dataset": args.dataset, "datasets_base": str(base), "modes": []}
    global_ok = True
    for mode in args.modes:
        item = validate_mode(base, args.dataset, mode, args.min_positive_eval)
        report["modes"].append(item)
        if not item.get("ok", False):
            global_ok = False
    report["ok"] = global_ok

    out_path = resolve_from_root(args.out) if args.out else base / "validation_report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Validation report written to: {out_path}")
    print(f"Global OK: {global_ok}")
    if not global_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()