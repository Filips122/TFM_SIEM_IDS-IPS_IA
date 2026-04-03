#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except Exception:
    pa = None
    pq = None


def repo_root() -> Path:
    # <root>/src/models/NUSW-NB15/prepare_dataset.py
    return Path(__file__).resolve().parents[3]


def resolve_from_root(p: str | Path) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


DEFAULT_IN_DIR = Path("out/NUSW-NB15")
DEFAULT_OUT_DIR = Path("src/models/NUSW-NB15/datasets")

EXCLUDED_INPUT_PATTERNS = (
    "features",
    "list_events",
    "train_test_network",
)


def _ensure_pyarrow() -> None:
    if pa is None or pq is None:
        raise SystemExit("Missing pyarrow. Install with: pip install pyarrow")


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def normalize_colname(c: str) -> str:
    c = c.replace("\ufeff", "")
    c = " ".join(c.split())
    return c.strip().lower()


def normalize_text(v: object) -> str:
    s = str(v or "").strip()
    if s == "" or s.lower() in {"nan", "none", "null"}:
        return "Unknown"
    return s


def normalize_attack_cat(v: object) -> str:
    s = normalize_text(v)
    if s.lower() == "normal":
        return "Normal"
    return s


def list_data_csvs(root: Path) -> List[Path]:
    files = []
    for p in sorted(root.glob("*.csv")):
        if not p.is_file():
            continue
        name = p.name.lower()
        if any(k in name for k in EXCLUDED_INPUT_PATTERNS):
            continue
        files.append(p)
    return files


def detect_official_train_test(csvs: List[Path]) -> Tuple[Optional[Path], Optional[Path]]:
    train = None
    test = None
    for p in csvs:
        n = p.name.lower()
        if "training-set" in n:
            train = p
        elif "testing-set" in n:
            test = p
    return train, test


def detect_group_files(csvs: List[Path]) -> List[Path]:
    pat = re.compile(r"^unsw-nb15_\d+\.csv$", flags=re.IGNORECASE)
    out = [p for p in csvs if pat.match(p.name)]
    return sorted(out)


def select_csv_source_set(csvs: List[Path], source_set: str) -> List[Path]:
    train_file, test_file = detect_official_train_test(csvs)
    raw4 = detect_group_files(csvs)

    if source_set == "all":
        return csvs

    if source_set == "raw4":
        if not raw4:
            raise SystemExit("source_set=raw4 requested but UNSW-NB15_*.csv files were not found")
        return raw4

    if source_set == "official_pair":
        if train_file is None or test_file is None:
            raise SystemExit("source_set=official_pair requested but official training/testing files were not found")
        return [train_file, test_file]

    raise SystemExit(f"Unsupported source_set: {source_set}")


def _table_no_meta(df: pd.DataFrame) -> Any:
    return pa.Table.from_pandas(df, preserve_index=False).replace_schema_metadata(None)


@dataclass
class Stats:
    rows: int = 0
    benign: int = 0
    attack: int = 0
    label_counts: Dict[str, int] = None

    def __post_init__(self):
        if self.label_counts is None:
            self.label_counts = {}


def update_stats(st: Stats, counts: Dict[str, int], binary_view: bool) -> None:
    st.rows += int(sum(counts.values()))
    for k, v in counts.items():
        st.label_counts[k] = st.label_counts.get(k, 0) + int(v)

    if binary_view:
        st.benign += int(counts.get("BENIGN", 0))
        st.attack += int(counts.get("ATTACK", 0))
    else:
        benign = int(counts.get("Normal", 0))
        st.benign += benign
        st.attack += int(sum(counts.values()) - benign)


def write_stats(base_dir: Path, stats: Dict[str, Dict[str, Stats]]) -> None:
    for pipeline_name, splits in stats.items():
        out = base_dir / pipeline_name / "stats.json"
        safe_mkdir(out.parent)
        payload = {}
        for split, st in splits.items():
            payload[split] = {
                "rows": st.rows,
                "benign": st.benign,
                "attack": st.attack,
                "label_counts": dict(sorted(st.label_counts.items(), key=lambda x: x[1], reverse=True)),
            }
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def collect_categorical_vocab(csv_files: List[Path], chunksize: int) -> Dict[str, Dict[str, int]]:
    """
    Build deterministic category maps from all input files once.
    This keeps encoded values stable across splits/files.
    """
    cat_values: Dict[str, set] = {}
    excluded = {"label", "attack_cat"}

    for i, csv_path in enumerate(csv_files, start=1):
        print(f"[vocab] ({i}/{len(csv_files)}) {csv_path.name}")
        reader = pd.read_csv(
            csv_path,
            chunksize=chunksize,
            low_memory=False,
            encoding="utf-8",
            encoding_errors="replace",
            on_bad_lines="skip",
        )
        for chunk in reader:
            if chunk.empty:
                continue
            chunk.columns = [normalize_colname(c) for c in chunk.columns]
            for c in chunk.columns:
                if c in excluded:
                    continue
                if chunk[c].dtype == object:
                    s = chunk[c].map(normalize_text)
                    if c not in cat_values:
                        cat_values[c] = set()
                    cat_values[c].update(set(s.unique().tolist()))

    maps: Dict[str, Dict[str, int]] = {}
    for c, vals in cat_values.items():
        ordered = sorted(vals)
        maps[c] = {"__UNK__": 0}
        for idx, val in enumerate(ordered, start=1):
            maps[c][val] = idx
    return maps


def collect_feature_columns(csv_files: List[Path]) -> List[str]:
    cols = set()
    for p in csv_files:
        try:
            df0 = pd.read_csv(
                p,
                nrows=0,
                low_memory=False,
                encoding="utf-8",
                encoding_errors="replace",
                on_bad_lines="skip",
            )
        except Exception:
            continue
        for c in df0.columns:
            cn = normalize_colname(c)
            if cn in {"label", "attack_cat"}:
                continue
            cols.add(cn)
    return sorted(cols)


def derive_binary_target(df: pd.DataFrame) -> pd.Series:
    if "label" in df.columns:
        y = pd.to_numeric(df["label"], errors="coerce")
        out = pd.Series(np.where(y == 0, "BENIGN", "ATTACK"), index=df.index)
        out.loc[y.isna()] = "ATTACK"
        return out

    if "attack_cat" in df.columns:
        ac = df["attack_cat"].map(normalize_attack_cat)
        return ac.map(lambda x: "BENIGN" if x == "Normal" else "ATTACK")

    return pd.Series(["ATTACK"] * len(df), index=df.index)


def derive_multiclass_target(df: pd.DataFrame) -> pd.Series:
    if "attack_cat" in df.columns:
        return df["attack_cat"].map(normalize_attack_cat)
    if "label" in df.columns:
        y = pd.to_numeric(df["label"], errors="coerce")
        out = pd.Series(np.where(y == 0, "Normal", "UnknownAttack"), index=df.index)
        out.loc[y.isna()] = "UnknownAttack"
        return out
    return pd.Series(["UnknownAttack"] * len(df), index=df.index)


def preprocess_chunk(df: pd.DataFrame, cat_maps: Dict[str, Dict[str, int]]) -> pd.DataFrame:
    df = df.copy()
    df.columns = [normalize_colname(c) for c in df.columns]

    # Drop fully empty rows
    df = df.dropna(how="all")
    if df.empty:
        return df

    # Ensure attack_cat exists as text when available
    if "attack_cat" in df.columns:
        df["attack_cat"] = df["attack_cat"].map(normalize_attack_cat)

    # Replace infinities and textual variants
    df = df.replace([np.inf, -np.inf], np.nan)
    for c in df.columns:
        if df[c].dtype == object:
            s = df[c].astype(str).str.lower()
            mask = s.isin(["inf", "+inf", "-inf", "infinity", "+infinity", "-infinity"])
            if mask.any():
                df.loc[mask, c] = np.nan

    excluded = {"label", "attack_cat"}
    for c in df.columns:
        if c in excluded:
            continue
        if c in cat_maps:
            # Categorical -> stable numeric code
            m = cat_maps[c]
            vals = df[c].map(normalize_text)
            df[c] = vals.map(lambda x: m.get(x, m["__UNK__"])).astype("float64")
        else:
            df[c] = pd.to_numeric(df[c], errors="coerce").astype("float64")

    return df


def append_table(
    out_path: Path,
    df: pd.DataFrame,
    writers: Dict[Path, Any],
    schemas: Dict[Path, List[str]],
) -> None:
    if df.empty:
        return

    safe_mkdir(out_path.parent)

    if out_path not in schemas:
        schemas[out_path] = list(df.columns)
    else:
        for c in schemas[out_path]:
            if c not in df.columns:
                df[c] = np.nan
        df = df.reindex(columns=schemas[out_path])

    table = _table_no_meta(df)
    if out_path not in writers:
        writers[out_path] = pq.ParquetWriter(out_path, table.schema, compression="snappy")
    writers[out_path].write_table(table)


def close_writers(writers: Dict[Path, Any]) -> None:
    for w in writers.values():
        w.close()


def process_csv_random(
    csv_path: Path,
    out_dataset_dir: Path,
    cat_maps: Dict[str, Dict[str, int]],
    feature_cols: List[str],
    chunksize: int,
    rng: np.random.Generator,
    train_ratio: float,
    val_ratio: float,
) -> Dict[str, Dict[str, Dict[str, int]]]:
    thresholds = (train_ratio, train_ratio + val_ratio)
    stem = csv_path.stem

    counts = {
        "binary": {"train": {}, "val": {}, "test": {}},
        "multiclass": {"train": {}, "val": {}, "test": {}},
        "anomaly": {"train": {}, "val": {}, "test": {}},
    }

    writers: Dict[Path, Any] = {}
    schemas: Dict[Path, List[str]] = {}

    def bump(pipeline: str, split: str, y: pd.Series) -> None:
        vc = y.value_counts(dropna=False)
        for k, v in vc.items():
            ks = str(k)
            counts[pipeline][split][ks] = counts[pipeline][split].get(ks, 0) + int(v)

    reader = pd.read_csv(
        csv_path,
        chunksize=chunksize,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace",
        on_bad_lines="skip",
    )
    for chunk in reader:
        chunk = preprocess_chunk(chunk, cat_maps)
        if chunk.empty:
            continue

        y_bin = derive_binary_target(chunk)
        y_multi = derive_multiclass_target(chunk)
        base = chunk.drop(columns=[c for c in ("label", "attack_cat") if c in chunk.columns], errors="ignore")
        base = base.reindex(columns=feature_cols)

        r = rng.random(len(base))
        masks = {
            "train": r < thresholds[0],
            "val": (r >= thresholds[0]) & (r < thresholds[1]),
            "test": r >= thresholds[1],
        }

        for split, mask in masks.items():
            if not np.any(mask):
                continue

            # binary
            d_bin = base.loc[mask].copy()
            d_bin["label_raw"] = y_bin.loc[mask].values
            d_bin["target"] = y_bin.loc[mask].values
            out_bin = out_dataset_dir / "binary" / split / f"{stem}.parquet"
            append_table(out_bin, d_bin, writers, schemas)
            bump("binary", split, y_bin.loc[mask])

            # multiclass
            d_multi = base.loc[mask].copy()
            d_multi["label_raw"] = y_multi.loc[mask].values
            d_multi["target"] = y_multi.loc[mask].values
            out_multi = out_dataset_dir / "multiclass" / split / f"{stem}.parquet"
            append_table(out_multi, d_multi, writers, schemas)
            bump("multiclass", split, y_multi.loc[mask])

            # anomaly
            if split == "train":
                benign_mask = (y_bin.loc[mask] == "BENIGN").to_numpy()
                if np.any(benign_mask):
                    d_a = base.loc[mask].loc[benign_mask].copy()
                    d_a["label_raw"] = "BENIGN"
                    d_a["target"] = "BENIGN"
                    out_a = out_dataset_dir / "anomaly" / "train_benign" / f"{stem}.parquet"
                    append_table(out_a, d_a, writers, schemas)
                    bump("anomaly", "train", pd.Series(["BENIGN"] * len(d_a)))
            else:
                d_a = base.loc[mask].copy()
                d_a["label_raw"] = y_bin.loc[mask].values
                d_a["target"] = y_bin.loc[mask].values
                sub = "val_mixed" if split == "val" else "test_mixed"
                out_a = out_dataset_dir / "anomaly" / sub / f"{stem}.parquet"
                append_table(out_a, d_a, writers, schemas)
                bump("anomaly", split, y_bin.loc[mask])

    close_writers(writers)
    return counts


def process_csv_fixed_split(
    csv_path: Path,
    split: str,
    out_base: Path,
    cat_maps: Dict[str, Dict[str, int]],
    feature_cols: List[str],
    chunksize: int,
) -> Dict[str, Dict[str, int]]:
    counts = {
        "binary": {},
        "multiclass": {},
        "anomaly": {},
    }
    stem = csv_path.stem
    writers: Dict[Path, Any] = {}
    schemas: Dict[Path, List[str]] = {}

    def bump(name: str, y: pd.Series) -> None:
        vc = y.value_counts(dropna=False)
        for k, v in vc.items():
            ks = str(k)
            counts[name][ks] = counts[name].get(ks, 0) + int(v)

    reader = pd.read_csv(
        csv_path,
        chunksize=chunksize,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace",
        on_bad_lines="skip",
    )
    for chunk in reader:
        chunk = preprocess_chunk(chunk, cat_maps)
        if chunk.empty:
            continue

        y_bin = derive_binary_target(chunk)
        y_multi = derive_multiclass_target(chunk)
        base = chunk.drop(columns=[c for c in ("label", "attack_cat") if c in chunk.columns], errors="ignore")
        base = base.reindex(columns=feature_cols)

        d_bin = base.copy()
        d_bin["label_raw"] = y_bin.values
        d_bin["target"] = y_bin.values
        append_table(out_base / "binary" / split / f"{stem}.parquet", d_bin, writers, schemas)
        bump("binary", y_bin)

        d_multi = base.copy()
        d_multi["label_raw"] = y_multi.values
        d_multi["target"] = y_multi.values
        append_table(out_base / "multiclass" / split / f"{stem}.parquet", d_multi, writers, schemas)
        bump("multiclass", y_multi)

        if split == "train":
            d_a = base.loc[y_bin == "BENIGN"].copy()
            if not d_a.empty:
                d_a["label_raw"] = "BENIGN"
                d_a["target"] = "BENIGN"
                append_table(out_base / "anomaly" / "train_benign" / f"{stem}.parquet", d_a, writers, schemas)
                bump("anomaly", pd.Series(["BENIGN"] * len(d_a)))
        else:
            d_a = base.copy()
            d_a["label_raw"] = y_bin.values
            d_a["target"] = y_bin.values
            sub = "val_mixed" if split == "val" else "test_mixed"
            append_table(out_base / "anomaly" / sub / f"{stem}.parquet", d_a, writers, schemas)
            bump("anomaly", y_bin)

    close_writers(writers)
    return counts


def process_csv_anomaly_train_benign_only(
    csv_path: Path,
    out_base: Path,
    cat_maps: Dict[str, Dict[str, int]],
    feature_cols: List[str],
    chunksize: int,
    out_stem: str,
) -> int:
    """
    Append only BENIGN rows to anomaly/train_benign for policy-based fallback.
    Returns number of written benign rows.
    """
    total = 0
    writers: Dict[Path, Any] = {}
    schemas: Dict[Path, List[str]] = {}

    reader = pd.read_csv(
        csv_path,
        chunksize=chunksize,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace",
        on_bad_lines="skip",
    )

    for chunk in reader:
        chunk = preprocess_chunk(chunk, cat_maps)
        if chunk.empty:
            continue

        y_bin = derive_binary_target(chunk)
        benign_mask = y_bin == "BENIGN"
        if not bool(benign_mask.any()):
            continue

        base = chunk.drop(columns=[c for c in ("label", "attack_cat") if c in chunk.columns], errors="ignore")
        base = base.reindex(columns=feature_cols)

        d_a = base.loc[benign_mask].copy()
        if d_a.empty:
            continue

        d_a["label_raw"] = "BENIGN"
        d_a["target"] = "BENIGN"
        out_a = out_base / "anomaly" / "train_benign" / f"{out_stem}.parquet"
        append_table(out_a, d_a, writers, schemas)
        total += int(len(d_a))

    close_writers(writers)
    return total


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_dir", type=str, default=str(DEFAULT_IN_DIR))
    ap.add_argument("--out_dir", type=str, default=str(DEFAULT_OUT_DIR))
    ap.add_argument("--split_mode", type=str, default="random", choices=["random", "groupkfold", "official"])
    ap.add_argument("--chunksize", type=int, default=250_000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--train_ratio", type=float, default=0.70)
    ap.add_argument("--val_ratio", type=float, default=0.15)
    ap.add_argument("--all_folds", action="store_true")
    ap.add_argument("--fold", type=int, default=None)
    ap.add_argument("--n_folds", type=int, default=8, help="Number of groupkfold folds to generate")
    ap.add_argument("--source_set", type=str, default="raw4", choices=["all", "raw4", "official_pair"])
    ap.add_argument(
        "--anomaly_group_train_policy",
        type=str,
        default="strict",
        choices=["strict", "fallback_official_benign"],
        help="Policy for groupkfold anomaly train when no BENIGN samples are available",
    )
    args = ap.parse_args()

    _ensure_pyarrow()

    in_dir = resolve_from_root(args.in_dir)
    out_base = resolve_from_root(args.out_dir)
    out_mode = out_base / args.split_mode / "NUSW-NB15"
    safe_mkdir(out_mode)

    csvs_all = list_data_csvs(in_dir)
    csvs = select_csv_source_set(csvs_all, args.source_set)
    if not csvs:
        raise SystemExit(f"No data CSV files found in: {in_dir}")

    if args.split_mode == "random":
        if not (0.0 < args.train_ratio < 1.0) or not (0.0 <= args.val_ratio < 1.0) or not (args.train_ratio + args.val_ratio < 1.0):
            raise SystemExit("Invalid random ratios: requires 0<train<1, 0<=val<1, train+val<1")

    print("== prepare_dataset (NUSW-NB15) ==")
    print(f"Repo root : {repo_root()}")
    print(f"Input dir : {in_dir}")
    print(f"Split mode: {args.split_mode}")
    print(f"Out dir   : {out_mode}")
    print(f"Chunksize : {args.chunksize}")
    print(f"Source set: {args.source_set}")
    print(f"Anomaly group policy: {args.anomaly_group_train_policy}")
    print(f"CSV files : {[p.name for p in csvs]}")

    cat_maps = collect_categorical_vocab(csvs, chunksize=args.chunksize)
    feature_cols = collect_feature_columns(csvs)
    vocab_info = {k: len(v) for k, v in cat_maps.items()}
    (out_mode / "vocab_sizes.json").write_text(json.dumps(vocab_info, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_mode / "feature_columns.json").write_text(json.dumps(feature_cols, ensure_ascii=False, indent=2), encoding="utf-8")

    stats: Dict[str, Dict[str, Stats]] = {
        "binary": {"train": Stats(), "val": Stats(), "test": Stats()},
        "multiclass": {"train": Stats(), "val": Stats(), "test": Stats()},
        "anomaly": {"train": Stats(), "val": Stats(), "test": Stats()},
    }

    if args.split_mode == "random":
        rng = np.random.default_rng(args.seed)
        for i, csv_path in enumerate(csvs, start=1):
            print(f"\n({i}/{len(csvs)}) [random] {csv_path.name}")
            c = process_csv_random(
                csv_path=csv_path,
                out_dataset_dir=out_mode,
                cat_maps=cat_maps,
                feature_cols=feature_cols,
                chunksize=args.chunksize,
                rng=rng,
                train_ratio=args.train_ratio,
                val_ratio=args.val_ratio,
            )

            for split in ["train", "val", "test"]:
                update_stats(stats["binary"][split], c["binary"][split], binary_view=True)
                update_stats(stats["multiclass"][split], c["multiclass"][split], binary_view=False)
                update_stats(stats["anomaly"][split], c["anomaly"][split], binary_view=True)

        write_stats(out_mode, stats)

    elif args.split_mode == "groupkfold":
        group_files = detect_group_files(csvs)
        if not group_files:
            raise SystemExit("No UNSW-NB15_*.csv files found for groupkfold mode")

        if args.n_folds < 2:
            raise SystemExit("n_folds must be >= 2")

        n_groups = len(group_files)
        if args.n_folds > n_groups:
            print(f"[groupkfold] requested n_folds={args.n_folds} with {n_groups} source files.")
            print("[groupkfold] folds beyond available files will reuse source files via modulo mapping.")

        if (not args.all_folds) and (args.fold is None):
            args.fold = 0
        folds = list(range(args.n_folds)) if args.all_folds else [args.fold]

        for fold in folds:
            if fold is None or fold < 0 or fold >= args.n_folds:
                raise SystemExit(f"Invalid fold: {fold}")

            fold_dir = out_mode / f"fold_{fold}"
            safe_mkdir(fold_dir)

            mapped = fold % n_groups
            test_file = group_files[mapped]
            val_file = group_files[(mapped + 1) % n_groups]
            train_files = [p for p in group_files if p not in {test_file, val_file}]

            print(f"\n== [groupkfold] fold_{fold} ==")
            print(f"test : {test_file.name}")
            print(f"val  : {val_file.name}")
            print(f"train: {[p.name for p in train_files]}")

            fold_stats: Dict[str, Dict[str, Stats]] = {
                "binary": {"train": Stats(), "val": Stats(), "test": Stats()},
                "multiclass": {"train": Stats(), "val": Stats(), "test": Stats()},
                "anomaly": {"train": Stats(), "val": Stats(), "test": Stats()},
            }

            for p in train_files:
                c = process_csv_fixed_split(p, "train", fold_dir, cat_maps, feature_cols, args.chunksize)
                update_stats(fold_stats["binary"]["train"], c["binary"], True)
                update_stats(fold_stats["multiclass"]["train"], c["multiclass"], False)
                update_stats(fold_stats["anomaly"]["train"], c["anomaly"], True)

            anomaly_policy_info = {
                "policy": args.anomaly_group_train_policy,
                "fallback_applied": False,
                "fallback_source": None,
                "fallback_rows": 0,
            }

            if fold_stats["anomaly"]["train"].benign == 0 and args.anomaly_group_train_policy == "fallback_official_benign":
                official_train, _ = detect_official_train_test(csvs_all)
                if official_train is not None:
                    fallback_rows = process_csv_anomaly_train_benign_only(
                        csv_path=official_train,
                        out_base=fold_dir,
                        cat_maps=cat_maps,
                        feature_cols=feature_cols,
                        chunksize=args.chunksize,
                        out_stem="fallback_official_train_benign",
                    )
                    if fallback_rows > 0:
                        fold_stats["anomaly"]["train"].rows += fallback_rows
                        fold_stats["anomaly"]["train"].benign += fallback_rows
                        fold_stats["anomaly"]["train"].label_counts["BENIGN"] = (
                            fold_stats["anomaly"]["train"].label_counts.get("BENIGN", 0) + fallback_rows
                        )
                        anomaly_policy_info["fallback_applied"] = True
                        anomaly_policy_info["fallback_source"] = official_train.name
                        anomaly_policy_info["fallback_rows"] = int(fallback_rows)

            c = process_csv_fixed_split(val_file, "val", fold_dir, cat_maps, feature_cols, args.chunksize)
            update_stats(fold_stats["binary"]["val"], c["binary"], True)
            update_stats(fold_stats["multiclass"]["val"], c["multiclass"], False)
            update_stats(fold_stats["anomaly"]["val"], c["anomaly"], True)

            c = process_csv_fixed_split(test_file, "test", fold_dir, cat_maps, feature_cols, args.chunksize)
            update_stats(fold_stats["binary"]["test"], c["binary"], True)
            update_stats(fold_stats["multiclass"]["test"], c["multiclass"], False)
            update_stats(fold_stats["anomaly"]["test"], c["anomaly"], True)

            write_stats(fold_dir, fold_stats)
            (fold_dir / "anomaly_policy.json").write_text(
                json.dumps(anomaly_policy_info, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

    elif args.split_mode == "official":
        train_file, test_file = detect_official_train_test(csvs_all)
        if train_file is None or test_file is None:
            raise SystemExit("official mode requires UNSW_NB15_training-set.csv and UNSW_NB15_testing-set.csv")

        print(f"\n[official] train={train_file.name} test={test_file.name}")

        c = process_csv_fixed_split(train_file, "train", out_mode, cat_maps, feature_cols, args.chunksize)
        update_stats(stats["binary"]["train"], c["binary"], True)
        update_stats(stats["multiclass"]["train"], c["multiclass"], False)
        update_stats(stats["anomaly"]["train"], c["anomaly"], True)

        # split official testing file into val/test with fixed mask for reproducibility
        rng = np.random.default_rng(args.seed)
        tmp_counts = process_csv_random(
            csv_path=test_file,
            out_dataset_dir=out_mode,
            cat_maps=cat_maps,
            feature_cols=feature_cols,
            chunksize=args.chunksize,
            rng=rng,
            train_ratio=0.0,
            val_ratio=0.5,
        )
        update_stats(stats["binary"]["val"], tmp_counts["binary"]["val"], True)
        update_stats(stats["binary"]["test"], tmp_counts["binary"]["test"], True)
        update_stats(stats["multiclass"]["val"], tmp_counts["multiclass"]["val"], False)
        update_stats(stats["multiclass"]["test"], tmp_counts["multiclass"]["test"], False)
        update_stats(stats["anomaly"]["val"], tmp_counts["anomaly"]["val"], True)
        update_stats(stats["anomaly"]["test"], tmp_counts["anomaly"]["test"], True)

        write_stats(out_mode, stats)

    print("\nDone")
    print(f"Parquets generated under: {out_mode}")


if __name__ == "__main__":
    main()
