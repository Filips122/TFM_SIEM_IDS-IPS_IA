#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except Exception:
    pa = None
    pq = None


# ----------------------------
# Paths
# ----------------------------

def repo_root() -> Path:
    # <root>/src/models/CIC-IDS2017/prepare_sequence_dataset.py
    return Path(__file__).resolve().parents[3]


def resolve_from_root(p: str | Path) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


DEFAULT_TL_DIR = Path("src/datasets/CIC-IDS2017/TrafficLabelling")
DEFAULT_OUT_DIR = Path("src/models/CIC-IDS2017/datasets")


# ----------------------------
# Labels / grouping
# ----------------------------

def normalize_colname(c: str) -> str:
    c = c.replace("\ufeff", "")
    c = " ".join(c.split())
    return c.strip()


def find_label_col(cols: List[str]) -> Optional[str]:
    norm = {normalize_colname(c).lower(): c for c in cols}
    for k in ["label", "class", "attack", "attacktype"]:
        if k in norm:
            return norm[k]
    return None


def normalize_label(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"\s+", " ", s)
    s = s.replace("\ufffd", "-").replace("�", "-")
    s = s.replace("–", "-").replace("—", "-")
    s = re.sub(r"\s*-\s*", " - ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def grouped_label(label: str) -> str:
    l = normalize_label(label)
    if l == "BENIGN":
        return "BENIGN"
    if l.lower().startswith("web attack"):
        return "WebAttack"
    if l.lower().startswith("dos "):
        return "DoS"
    if "patator" in l.lower():
        return "BruteForce"
    key_map = {
        "DDoS": "DDoS",
        "PortScan": "PortScan",
        "Bot": "Bot",
        "Infiltration": "Infiltration",
        "Heartbleed": "Heartbleed",
    }
    if l in key_map:
        return key_map[l]
    return "OtherAttack"


def make_target(task: str, labels: pd.Series) -> pd.Series:
    labels = labels.astype(str).map(normalize_label)
    if task == "binary":
        return labels.map(lambda x: "BENIGN" if x == "BENIGN" else "ATTACK")
    if task == "multiclass":
        return labels
    if task == "multiclass_grouped":
        return labels.map(grouped_label)
    raise ValueError(f"task inválido: {task}")


def file_day_bucket(filename: str) -> str:
    name = filename.lower()
    if "monday" in name:
        return "Monday"
    if "tuesday" in name:
        return "Tuesday"
    if "wednesday" in name:
        return "Wednesday"
    if "thursday" in name:
        return "Thursday"
    if "friday" in name:
        return "Friday"
    return "Other"


def split_from_day(day: str) -> str:
    if day in {"Monday", "Tuesday", "Wednesday"}:
        return "train"
    if day == "Thursday":
        return "val"
    if day == "Friday":
        return "test"
    return "train"


# ----------------------------
# IO
# ----------------------------

def _ensure_pyarrow() -> None:
    if pa is None or pq is None:
        raise SystemExit("Falta pyarrow. Instala con: pip install pyarrow")


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def list_csvs(folder: Path) -> List[Path]:
    return sorted([p for p in folder.rglob("*.csv") if p.is_file()])


# ----------------------------
# Preprocess
# ----------------------------

TL_META_COLS = {"Flow ID", "Source IP", "Destination IP", "Timestamp"}


def replace_inf_with_nan(df: pd.DataFrame) -> pd.DataFrame:
    df = df.replace([np.inf, -np.inf], np.nan)
    for c in df.columns:
        if df[c].dtype == object:
            s = df[c].astype(str).str.lower()
            mask = s.isin(["inf", "+inf", "-inf", "infinity", "+infinity", "-infinity"])
            if mask.any():
                df.loc[mask, c] = np.nan
    return df


def drop_bad_labels(df: pd.DataFrame, label_col: str) -> pd.DataFrame:
    df = df.loc[df[label_col].notna()].copy()
    lab = df[label_col].astype(str).map(normalize_label)
    bad = (lab == "") | (lab.str.lower() == "nan")
    if bad.any():
        df = df.loc[~bad].copy()
        lab = lab.loc[~bad]
    df[label_col] = lab.values
    return df


def preprocess_chunk(chunk: pd.DataFrame) -> Tuple[pd.DataFrame, str]:
    chunk.columns = [normalize_colname(c) for c in chunk.columns]
    label_col = find_label_col(list(chunk.columns))
    if label_col is None:
        raise RuntimeError("No se encontró columna Label en el chunk.")

    chunk = drop_bad_labels(chunk, label_col)

    if "Timestamp" in chunk.columns:
        chunk["Timestamp"] = pd.to_datetime(chunk["Timestamp"], errors="coerce")

    for c in ["Flow ID", "Source IP", "Destination IP"]:
        if c in chunk.columns:
            chunk[c] = chunk[c].astype(str)

    chunk = replace_inf_with_nan(chunk)

    # a numérico todo excepto meta y label
    for c in chunk.columns:
        if c == label_col:
            continue
        if c in TL_META_COLS:
            continue
        chunk[c] = pd.to_numeric(chunk[c], errors="coerce")

    # schema estable: numéricas a float64
    for c in chunk.columns:
        if c == label_col or c in TL_META_COLS:
            continue
        if pd.api.types.is_numeric_dtype(chunk[c]) or pd.api.types.is_bool_dtype(chunk[c]):
            chunk[c] = chunk[c].astype("float64")

    return chunk, label_col


# ----------------------------
# Sequence building
# ----------------------------

def get_group_id(df: pd.DataFrame, group_key: str) -> pd.Series:
    if group_key == "source_ip":
        return df["Source IP"].astype(str)
    if group_key == "flow_id":
        return df["Flow ID"].astype(str)
    if group_key == "five_tuple":
        parts = [
            df["Source IP"].astype(str),
            df["Source Port"].astype(str),
            df["Destination IP"].astype(str),
            df["Destination Port"].astype(str),
            df["Protocol"].astype(str),
        ]
        return parts[0] + "|" + parts[1] + "|" + parts[2] + "|" + parts[3] + "|" + parts[4]
    raise ValueError(f"group_key inválido: {group_key}")


def feature_columns(df: pd.DataFrame, label_col: str) -> List[str]:
    drop = set(TL_META_COLS) | {label_col, "label_raw", "target"}
    cols = []
    for c in df.columns:
        if c in drop:
            continue
        if pd.api.types.is_numeric_dtype(df[c]) or pd.api.types.is_bool_dtype(df[c]):
            cols.append(c)
    return cols


def flatten_window(window: np.ndarray, feat_names: List[str], window_size: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    F = window.shape[1]
    for t in range(window_size):
        k = window_size - 1 - t  # t-0 = más reciente
        for j, feat in enumerate(feat_names):
            out[f"{feat}__t-{k}"] = float(window[t, j])
    return out


@dataclass
class SplitCounts:
    counts: Dict[str, Dict[str, int]]

    def __init__(self) -> None:
        self.counts = {"train": {}, "val": {}, "test": {}}

    def add(self, split: str, y: str) -> None:
        d = self.counts[split]
        d[y] = d.get(y, 0) + 1


# ----------------------------
# Writers
# ----------------------------

def _table_no_meta(df: pd.DataFrame):
    return pa.Table.from_pandas(df, preserve_index=False).replace_schema_metadata(None)


class ParquetBatchWriter:
    """
    Escribe en shards para evitar archivos gigantes:
      <out_dir>/<stem>__part0000.parquet
    """
    def __init__(self, out_dir: Path, stem: str, batch_size: int = 50_000) -> None:
        self.out_dir = out_dir
        self.stem = stem
        self.batch_size = batch_size
        self.part = 0
        self.buffer: List[Dict[str, Any]] = []

    def add_row(self, row: Dict[str, Any]) -> None:
        self.buffer.append(row)
        if len(self.buffer) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if not self.buffer:
            return
        safe_mkdir(self.out_dir)
        df = pd.DataFrame(self.buffer)
        cols = sorted(df.columns)
        df = df.reindex(columns=cols)
        table = _table_no_meta(df)
        out_path = self.out_dir / f"{self.stem}__part{self.part:04d}.parquet"
        pq.write_table(table, out_path, compression="snappy")
        self.part += 1
        self.buffer.clear()

    def close(self) -> None:
        self.flush()


# ----------------------------
# Core processing
# ----------------------------

def process_file_to_sequences(
    csv_path: Path,
    out_dir: Path,
    task: str,
    split_mode: str,
    split: str,
    chunksize: int,
    window_size: int,
    stride: int,
    group_key: str,
    fillna_value: float,
    random_rng: Optional[np.random.Generator],
    random_train_ratio: float,
    random_val_ratio: float,
    max_sequences: Optional[int],
) -> Tuple[SplitCounts, Dict[str, Any]]:
    _ensure_pyarrow()

    reader = pd.read_csv(
        csv_path,
        chunksize=chunksize,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace",
        on_bad_lines="skip",
    )

    writers: Dict[str, ParquetBatchWriter] = {}
    counts = SplitCounts()

    buf: Dict[str, Deque[np.ndarray]] = defaultdict(lambda: deque(maxlen=window_size))
    step_counter: Dict[str, int] = defaultdict(int)

    feat_names: Optional[List[str]] = None
    n_features: Optional[int] = None
    label_col_global: Optional[str] = None

    total_sequences = 0

    for chunk in reader:
        chunk, label_col = preprocess_chunk(chunk)
        if chunk.empty:
            continue

        label_col_global = label_col

        if feat_names is None:
            feat_names = feature_columns(chunk, label_col)
            if not feat_names:
                raise RuntimeError("No se detectaron features numéricas para secuencia.")
            n_features = len(feat_names)

        for c in feat_names:
            if c not in chunk.columns:
                chunk[c] = np.nan

        chunk[feat_names] = chunk[feat_names].fillna(fillna_value)

        gid = get_group_id(chunk, group_key=group_key)
        labels = chunk[label_col].astype(str).map(normalize_label)
        targets = make_target(task, labels)
        timestamps = chunk["Timestamp"] if "Timestamp" in chunk.columns else pd.Series([pd.NaT] * len(chunk))

        X = chunk[feat_names].to_numpy(dtype=np.float32, copy=False)

        for i in range(len(chunk)):
            g = str(gid.iloc[i])
            buf[g].append(X[i])
            step_counter[g] += 1

            if len(buf[g]) < window_size:
                continue
            if (step_counter[g] - window_size) % stride != 0:
                continue

            if split_mode == "random":
                assert random_rng is not None
                r = random_rng.random()
                if r < random_train_ratio:
                    split_used = "train"
                elif r < random_train_ratio + random_val_ratio:
                    split_used = "val"
                else:
                    split_used = "test"
            else:
                split_used = split

            if split_used not in writers:
                writers[split_used] = ParquetBatchWriter(out_dir / split_used, stem=csv_path.stem, batch_size=50_000)

            window = np.stack(list(buf[g]), axis=0)  # (W, F)
            row = flatten_window(window, feat_names, window_size)

            row["group_id"] = g
            row["end_timestamp"] = timestamps.iloc[i].isoformat() if pd.notna(timestamps.iloc[i]) else None
            row["label_raw"] = labels.iloc[i]
            row["target"] = targets.iloc[i]

            writers[split_used].add_row(row)
            counts.add(split_used, str(targets.iloc[i]))

            total_sequences += 1
            if max_sequences is not None and total_sequences >= max_sequences:
                break

        if max_sequences is not None and total_sequences >= max_sequences:
            break

    for w in writers.values():
        w.close()

    meta = {
        "file": str(csv_path),
        "task": task,
        "group_key": group_key,
        "window_size": window_size,
        "stride": stride,
        "fillna_value": fillna_value,
        "n_features": n_features,
        "feature_names": feat_names,
        "flattened_feature_cols_count": (n_features * window_size) if (n_features is not None) else None,
        "label_col": label_col_global,
    }
    return counts, meta


# ----------------------------
# Modes (OUTPUT PATH FIXED)
# ----------------------------

def process_mode_day(
    csvs: List[Path],
    out_base: Path,
    task: str,
    chunksize: int,
    window: int,
    stride: int,
    group_key: str,
    fillna_value: float,
    max_sequences: Optional[int],
) -> None:
    # ✅ NUEVA RUTA: datasets/sequence/day/...
    out_root = out_base / "sequence" / "day" / "TrafficLabelling" / task
    safe_mkdir(out_root)

    global_counts = SplitCounts()
    metas = []

    for i, p in enumerate(csvs, start=1):
        day = file_day_bucket(p.name)
        split = split_from_day(day)
        print(f"({i}/{len(csvs)}) [day] {p.name} -> {split}")

        counts, meta = process_file_to_sequences(
            csv_path=p,
            out_dir=out_root,
            task=task,
            split_mode="day",
            split=split,
            chunksize=chunksize,
            window_size=window,
            stride=stride,
            group_key=group_key,
            fillna_value=fillna_value,
            random_rng=None,
            random_train_ratio=0.0,
            random_val_ratio=0.0,
            max_sequences=max_sequences,
        )
        metas.append(meta)

        for sp in ["train", "val", "test"]:
            for k, v in counts.counts[sp].items():
                global_counts.counts[sp][k] = global_counts.counts[sp].get(k, 0) + v

    meta_global = {"task": task, "window": window, "stride": stride, "group_key": group_key, "files": metas}
    (out_root / "sequence_meta.json").write_text(json.dumps(meta_global, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_root / "sequence_stats.json").write_text(json.dumps(global_counts.counts, ensure_ascii=False, indent=2), encoding="utf-8")
    print("✅ day sequences saved to:", out_root)


def process_mode_groupkfold(
    csvs: List[Path],
    out_base: Path,
    task: str,
    chunksize: int,
    window: int,
    stride: int,
    group_key: str,
    fillna_value: float,
    max_sequences: Optional[int],
) -> None:
    # ✅ NUEVA RUTA: datasets/sequence/groupkfold/TrafficLabelling/<task>/fold_k/...
    base = out_base / "sequence" / "groupkfold" / "TrafficLabelling" / task
    safe_mkdir(base)

    n = len(csvs)
    for fold in range(n):
        fold_root = base / f"fold_{fold}"
        safe_mkdir(fold_root)

        test_file = csvs[fold]
        val_file = csvs[(fold + 1) % n]
        train_files = [p for p in csvs if p not in {test_file, val_file}]

        print(f"\n== [groupkfold] fold_{fold} ==")
        print("  test:", test_file.name)
        print("  val :", val_file.name)
        print("  train files:", len(train_files))

        global_counts = SplitCounts()
        metas = []

        def handle(p: Path, split: str) -> None:
            nonlocal global_counts, metas
            counts, meta = process_file_to_sequences(
                csv_path=p,
                out_dir=fold_root,
                task=task,
                split_mode="groupkfold",
                split=split,
                chunksize=chunksize,
                window_size=window,
                stride=stride,
                group_key=group_key,
                fillna_value=fillna_value,
                random_rng=None,
                random_train_ratio=0.0,
                random_val_ratio=0.0,
                max_sequences=max_sequences,
            )
            metas.append(meta)
            for sp in ["train", "val", "test"]:
                for k, v in counts.counts[sp].items():
                    global_counts.counts[sp][k] = global_counts.counts[sp].get(k, 0) + v

        for p in train_files:
            handle(p, "train")
        handle(val_file, "val")
        handle(test_file, "test")

        meta_global = {"task": task, "window": window, "stride": stride, "group_key": group_key, "files": metas}
        (fold_root / "sequence_meta.json").write_text(json.dumps(meta_global, ensure_ascii=False, indent=2), encoding="utf-8")
        (fold_root / "sequence_stats.json").write_text(json.dumps(global_counts.counts, ensure_ascii=False, indent=2), encoding="utf-8")

    print("✅ groupkfold sequences saved to:", base)


def process_mode_random(
    csvs: List[Path],
    out_base: Path,
    task: str,
    chunksize: int,
    window: int,
    stride: int,
    group_key: str,
    fillna_value: float,
    seed: int,
    train_ratio: float,
    val_ratio: float,
    max_sequences: Optional[int],
) -> None:
    # ✅ NUEVA RUTA: datasets/sequence/random/...
    out_root = out_base / "sequence" / "random" / "TrafficLabelling" / task
    safe_mkdir(out_root)

    rng = np.random.default_rng(seed)
    global_counts = SplitCounts()
    metas = []

    for i, p in enumerate(csvs, start=1):
        print(f"({i}/{len(csvs)}) [random] {p.name}")

        counts, meta = process_file_to_sequences(
            csv_path=p,
            out_dir=out_root,
            task=task,
            split_mode="random",
            split="train",
            chunksize=chunksize,
            window_size=window,
            stride=stride,
            group_key=group_key,
            fillna_value=fillna_value,
            random_rng=rng,
            random_train_ratio=train_ratio,
            random_val_ratio=val_ratio,
            max_sequences=max_sequences,
        )
        metas.append(meta)

        for sp in ["train", "val", "test"]:
            for k, v in counts.counts[sp].items():
                global_counts.counts[sp][k] = global_counts.counts[sp].get(k, 0) + v

    meta_global = {"task": task, "window": window, "stride": stride, "group_key": group_key, "seed": seed, "files": metas}
    (out_root / "sequence_meta.json").write_text(json.dumps(meta_global, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_root / "sequence_stats.json").write_text(json.dumps(global_counts.counts, ensure_ascii=False, indent=2), encoding="utf-8")
    print("✅ random sequences saved to:", out_root)


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tl_dir", type=str, default=str(DEFAULT_TL_DIR), help="Input TrafficLabelling folder")
    ap.add_argument("--out_dir", type=str, default=str(DEFAULT_OUT_DIR), help="Output base datasets folder")

    ap.add_argument("--mode", type=str, required=True, choices=["day", "groupkfold", "random"])
    ap.add_argument("--task", type=str, default="binary", choices=["binary", "multiclass", "multiclass_grouped"])

    ap.add_argument("--window", type=int, default=20, help="Sequence length (number of flows)")
    ap.add_argument("--stride", type=int, default=1, help="Emit every stride steps per group")
    ap.add_argument("--group_key", type=str, default="source_ip", choices=["source_ip", "five_tuple", "flow_id"])

    ap.add_argument("--chunksize", type=int, default=200_000)
    ap.add_argument("--fillna", type=float, default=0.0, help="Imputation value for NaNs in features")

    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--train_ratio", type=float, default=0.70)
    ap.add_argument("--val_ratio", type=float, default=0.15)

    ap.add_argument("--max_sequences", type=int, default=None, help="Generate at most N sequences (debug)")

    args = ap.parse_args()
    _ensure_pyarrow()

    tl_dir = resolve_from_root(args.tl_dir)
    out_base = resolve_from_root(args.out_dir)

    if not tl_dir.exists():
        raise SystemExit(f"No existe tl_dir: {tl_dir}")

    csvs = list_csvs(tl_dir)
    if not csvs:
        raise SystemExit(f"No hay CSV en: {tl_dir}")

    if args.mode == "random":
        if not (0.0 < args.train_ratio < 1.0) or not (0.0 <= args.val_ratio < 1.0) or not (args.train_ratio + args.val_ratio < 1.0):
            raise SystemExit("Ratios inválidos para random: requiere 0<train<1, 0<=val<1 y train+val<1.")

    print("== prepare_sequence_dataset ==")
    print("Repo root:", repo_root())
    print("Input TL :", tl_dir)
    print("Output   :", out_base)
    print("Mode     :", args.mode)
    print("Task     :", args.task)
    print("Window   :", args.window, "Stride:", args.stride, "Group:", args.group_key)

    if args.mode == "day":
        process_mode_day(
            csvs, out_base, args.task, args.chunksize, args.window, args.stride, args.group_key, args.fillna, args.max_sequences
        )
    elif args.mode == "groupkfold":
        process_mode_groupkfold(
            csvs, out_base, args.task, args.chunksize, args.window, args.stride, args.group_key, args.fillna, args.max_sequences
        )
    elif args.mode == "random":
        process_mode_random(
            csvs, out_base, args.task, args.chunksize, args.window, args.stride, args.group_key, args.fillna,
            args.seed, args.train_ratio, args.val_ratio, args.max_sequences
        )


if __name__ == "__main__":
    main()