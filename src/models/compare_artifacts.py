#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import pandas as pd


METADATA_GROUP_CANDIDATES = [
    "feature_profile",
    "feature_count",
    "excluded_feature_count",
    "sampling_profile",
    "source_set",
    "sample_frac",
    "config_fingerprint",
]


def read_json_optional(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def selected_run_dirs(parent: Path, all_runs: bool) -> List[Path]:
    run_dirs = sorted([path for path in parent.iterdir() if path.is_dir()])
    if all_runs or not run_dirs:
        return run_dirs
    return [run_dirs[-1]]


def _sample_frac_from_metadata(metadata: Dict[str, Any]) -> Any:
    for key in ("sample_frac", "sample_fraction"):
        if key in metadata:
            return metadata.get(key)
    for nested_key in ("run_config", "training", "args", "config"):
        nested = metadata.get(nested_key)
        if isinstance(nested, dict):
            for key in ("sample_frac", "sample_fraction"):
                if key in nested:
                    return nested.get(key)
    return None


def _profile_from_metadata(run_metadata: Dict[str, Any], artifact_dir: Path) -> Dict[str, Any]:
    profile = read_json_optional(artifact_dir / "dataset_profile_ref.json")
    if profile is None:
        profile = read_json_optional(artifact_dir / "dataset_profile.json")
    if profile is None:
        profile = read_json_optional(artifact_dir / "feature_profile.json")
    if profile is None:
        embedded = run_metadata.get("dataset_profile")
        profile = embedded if isinstance(embedded, dict) else {}
    return profile or {}


def artifact_metadata(run_dir: Path, artifact_dir: Optional[Path] = None) -> Dict[str, Any]:
    artifact_dir = artifact_dir or run_dir
    run_metadata = read_json_optional(run_dir / "run_metadata.json") or {}
    profile = _profile_from_metadata(run_metadata, artifact_dir)

    return {
        "created_at_utc": run_metadata.get("created_at_utc"),
        "sample_frac": _sample_frac_from_metadata(run_metadata),
        "dataset_profile_status": profile.get("status"),
        "dataset_profile_path": profile.get("path"),
        "feature_profile": profile.get("feature_profile"),
        "feature_count": profile.get("feature_count"),
        "excluded_feature_count": profile.get("excluded_feature_count"),
        "sampling_profile": profile.get("sampling_profile"),
        "source_set": profile.get("source_set"),
        "config_fingerprint": profile.get("config_fingerprint"),
    }


def augment_row_metadata(row: Dict[str, Any], run_dir: Path, artifact_dir: Optional[Path] = None) -> Dict[str, Any]:
    row.update(artifact_metadata(run_dir, artifact_dir))
    return row


def aggregate_group_columns(dataframe: pd.DataFrame, base_columns: Iterable[str]) -> List[str]:
    columns = list(base_columns)
    for column in METADATA_GROUP_CANDIDATES:
        if column in dataframe.columns and dataframe[column].notna().any():
            columns.append(column)
    return columns


def key_to_dict(columns: List[str], key: Any) -> Dict[str, Any]:
    values = key if isinstance(key, tuple) else (key,)
    return dict(zip(columns, values))
