#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve_from_root(p: str | Path) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


def normalize_col(c: str) -> str:
    c = c.replace("\ufeff", "")
    c = " ".join(c.split())
    return c.strip().lower()


def read_columns(path: Path) -> list[str]:
    df0 = pd.read_csv(path, nrows=0, low_memory=False, encoding="utf-8", encoding_errors="replace", on_bad_lines="skip")
    return [normalize_col(c) for c in df0.columns]


def to_md_table(rows: list[dict]) -> str:
    if not rows:
        return "No rows"
    cols = list(rows[0].keys())
    header = "| " + " | ".join(cols) + " |"
    sep = "| " + " | ".join(["---"] * len(cols)) + " |"
    body = []
    for r in rows:
        body.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    return "\n".join([header, sep] + body)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="out/NUSW-NB15")
    ap.add_argument("--out", default="src/models/NUSW-NB15/artifacts/evaluations")
    args = ap.parse_args()

    root = resolve_from_root(args.root)
    out = resolve_from_root(args.out)
    out.mkdir(parents=True, exist_ok=True)

    primary_train = root / "UNSW_NB15_training-set.csv"
    primary_test = root / "UNSW_NB15_testing-set.csv"
    net_file = root / "train_test_network.csv"

    if not primary_train.exists() or not primary_test.exists() or not net_file.exists():
        raise SystemExit("Missing expected files in out/NUSW-NB15")

    train_cols = set(read_columns(primary_train))
    test_cols = set(read_columns(primary_test))
    primary_cols = train_cols.intersection(test_cols)
    net_cols = set(read_columns(net_file))

    overlap = sorted(primary_cols.intersection(net_cols))
    only_net = sorted(net_cols.difference(primary_cols))
    only_primary = sorted(primary_cols.difference(net_cols))

    has_primary_labels = ({"label", "attack_cat"}.intersection(primary_cols) != set())
    has_net_labels = ({"label", "attack_cat"}.intersection(net_cols) != set())

    overlap_ratio = (len(overlap) / len(primary_cols)) if primary_cols else 0.0

    recommendation = "defer"
    reason = "Schema mismatch or label incompatibility with current tabular pipeline"
    if has_net_labels and overlap_ratio >= 0.8:
        recommendation = "consider_integration"
        reason = "High column overlap and label availability"

    report = {
        "root": str(root),
        "primary_common_columns": len(primary_cols),
        "network_columns": len(net_cols),
        "overlap_columns": len(overlap),
        "overlap_ratio_vs_primary": round(float(overlap_ratio), 4),
        "primary_has_labels": has_primary_labels,
        "network_has_labels": has_net_labels,
        "recommendation": recommendation,
        "reason": reason,
        "overlap_sample": overlap[:40],
        "network_only_sample": only_net[:40],
        "primary_only_sample": only_primary[:40],
    }

    (out / "train_test_network_assessment.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    md_rows = [
        {
            "metric": "primary_common_columns",
            "value": report["primary_common_columns"],
        },
        {
            "metric": "network_columns",
            "value": report["network_columns"],
        },
        {
            "metric": "overlap_columns",
            "value": report["overlap_columns"],
        },
        {
            "metric": "overlap_ratio_vs_primary",
            "value": report["overlap_ratio_vs_primary"],
        },
        {
            "metric": "primary_has_labels",
            "value": report["primary_has_labels"],
        },
        {
            "metric": "network_has_labels",
            "value": report["network_has_labels"],
        },
        {
            "metric": "recommendation",
            "value": report["recommendation"],
        },
        {
            "metric": "reason",
            "value": report["reason"],
        },
    ]

    md = []
    md.append("# train_test_network.csv Assessment")
    md.append("")
    md.append(to_md_table(md_rows))
    md.append("")
    md.append("## Overlap Sample")
    md.append("")
    md.append("- " + "\n- ".join(report["overlap_sample"]) if report["overlap_sample"] else "- (none)")
    md.append("")
    md.append("## Network-only Sample")
    md.append("")
    md.append("- " + "\n- ".join(report["network_only_sample"]) if report["network_only_sample"] else "- (none)")
    md.append("")
    md.append("## Primary-only Sample")
    md.append("")
    md.append("- " + "\n- ".join(report["primary_only_sample"]) if report["primary_only_sample"] else "- (none)")

    (out / "train_test_network_assessment.md").write_text("\n".join(md), encoding="utf-8")

    print("Saved:", out)


if __name__ == "__main__":
    main()
