#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

"""
prepare_dataset.py

Genera Parquets desde CIC-IDS2017 para dos fuentes:
- MachineLearningCVE  -> IDS offline
- TrafficLabelling    -> IDS online (incluye meta columnas como IPs/Timestamp)

Soporta 3 modos de split:
--split_mode day
--split_mode groupkfold
--split_mode random

Estructura de salida:
datasets/<split_mode>/<dataset_name>/<pipeline>/<split>/*.parquet
datasets/groupkfold/<dataset_name>/fold_k/<pipeline>/<split>/*.parquet

Pipelines:
- binary
- multiclass
- multiclass_grouped
- anomaly (train_benign / val_mixed / test_mixed)

IMPORTANTE (fix pyarrow):
- Forzamos TODOS los features numéricos a float64 para mantener schema estable entre chunks.
- Eliminamos schema metadata para evitar mismatches.
"""

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

import numpy as np
import pandas as pd

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except Exception:
    pa = None
    pq = None

if TYPE_CHECKING:
    from pyarrow.parquet import ParquetWriter as ParquetWriterType
else:
    ParquetWriterType = Any


# ----------------------------
# Paths
# ----------------------------

def repo_root() -> Path:
    # <root>/src/models/CIC-IDS2017/prepare_dataset.py
    return Path(__file__).resolve().parents[3]


def resolve_from_root(p: str | Path) -> Path:
    p = Path(p).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (repo_root() / p).resolve()


DEFAULT_ML_DIR = Path("src/datasets/CIC-IDS2017/MachineLearningCVE")
DEFAULT_TL_DIR = Path("src/datasets/CIC-IDS2017/TrafficLabelling")
DEFAULT_OUT_DIR = Path("src/models/CIC-IDS2017/datasets")


# ----------------------------
# Dataset specs
# ----------------------------

TL_META_COLS = {
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
}

@dataclass(frozen=True)
class DatasetSpec:
    name: str
    in_dir: Path
    keep_meta: bool


# ----------------------------
# General helpers
# ----------------------------

def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def list_csvs(folder: Path) -> List[Path]:
    return sorted([p for p in folder.rglob("*.csv") if p.is_file()])


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
    # train: Mon/Tue/Wed, val: Thu, test: Fri
    if day in {"Monday", "Tuesday", "Wednesday"}:
        return "train"
    if day == "Thursday":
        return "val"
    if day == "Friday":
        return "test"
    return "train"


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


def _ensure_pyarrow() -> None:
    if pa is None or pq is None:
        raise SystemExit("Falta pyarrow. Instala con: pip install pyarrow")


# ----------------------------
# Preprocess
# ----------------------------

def replace_inf_with_nan(df: pd.DataFrame) -> pd.DataFrame:
    df = df.replace([np.inf, -np.inf], np.nan)

    # también strings tipo "Infinity"
    for c in df.columns:
        if df[c].dtype == object:
            s = df[c].astype(str).str.lower()
            mask = s.isin(["inf", "+inf", "-inf", "infinity", "+infinity", "-infinity"])
            if mask.any():
                df.loc[mask, c] = np.nan
    return df


def drop_bad_labels(df: pd.DataFrame, label_col: str) -> pd.DataFrame:
    """
    Elimina filas con label NaN/vacío/"nan".
    """
    if label_col not in df.columns:
        return df

    raw = df[label_col]
    # NaN reales:
    mask_notna = raw.notna()
    if not mask_notna.all():
        df = df.loc[mask_notna].copy()
        raw = df[label_col]

    labels = raw.astype(str).map(normalize_label)
    bad = (labels == "") | (labels.str.lower() == "nan")
    if bad.any():
        df = df.loc[~bad].copy()
        labels = labels.loc[~bad]

    df[label_col] = labels.values
    return df


def coerce_numeric_features(df: pd.DataFrame, label_col: str, dataset_name: str) -> pd.DataFrame:
    """
    Convierte a numérico TODAS las columnas excepto:
    - Label
    - (TrafficLabelling) meta cols (Flow ID, IPs, Timestamp)
    """
    for c in df.columns:
        if c == label_col:
            continue
        if dataset_name == "TrafficLabelling" and c in TL_META_COLS:
            continue
        df[c] = pd.to_numeric(df[c], errors="coerce")
    return df


def force_stable_numeric_dtypes(df: pd.DataFrame, label_col: str, dataset_name: str) -> pd.DataFrame:
    """
    FIX schema mismatch:
    Fuerza todas las columnas numéricas (features) a float64 para que todos los chunks
    tengan el mismo dtype aunque en unos haya NaN y en otros no.
    """
    exclude = {label_col, "label_raw", "target"}
    if dataset_name == "TrafficLabelling":
        exclude |= TL_META_COLS

    for c in df.columns:
        if c in exclude:
            continue
        if pd.api.types.is_bool_dtype(df[c]) or pd.api.types.is_numeric_dtype(df[c]):
            df[c] = df[c].astype("float64")
    return df


def preprocess_chunk(chunk: pd.DataFrame, dataset_name: str) -> Tuple[pd.DataFrame, str]:
    chunk.columns = [normalize_colname(c) for c in chunk.columns]
    label_col = find_label_col(list(chunk.columns))
    if label_col is None:
        raise RuntimeError("No se encontró columna Label en el chunk.")

    # Normaliza/limpia labels y quita filas malas (MUY importante para TrafficLabelling)
    chunk = drop_bad_labels(chunk, label_col)

    if dataset_name == "TrafficLabelling":
        # Timestamp parse suave
        if "Timestamp" in chunk.columns:
            chunk["Timestamp"] = pd.to_datetime(chunk["Timestamp"], errors="coerce")

        # meta a string (por si vienen raros)
        for mc in ("Flow ID", "Source IP", "Destination IP"):
            if mc in chunk.columns:
                chunk[mc] = chunk[mc].astype(str)

    chunk = replace_inf_with_nan(chunk)
    chunk = coerce_numeric_features(chunk, label_col=label_col, dataset_name=dataset_name)
    chunk = force_stable_numeric_dtypes(chunk, label_col=label_col, dataset_name=dataset_name)

    return chunk, label_col


# ----------------------------
# Targets
# ----------------------------

def make_binary_target(labels: pd.Series) -> pd.Series:
    return labels.map(lambda x: "BENIGN" if x == "BENIGN" else "ATTACK")


def make_multiclass_target(labels: pd.Series) -> pd.Series:
    return labels


def make_grouped_target(labels: pd.Series) -> pd.Series:
    return labels.map(grouped_label)


# ----------------------------
# Stats
# ----------------------------

@dataclass
class Stats:
    rows: int = 0
    benign: int = 0
    attack: int = 0
    label_counts: Dict[str, int] = None

    def __post_init__(self):
        if self.label_counts is None:
            self.label_counts = {}


def add_counts(st: Stats, counts: Dict[str, int], pipeline_name: str) -> None:
    st.rows += sum(counts.values())
    for k, v in counts.items():
        st.label_counts[k] = st.label_counts.get(k, 0) + int(v)

    if pipeline_name == "binary":
        st.benign += counts.get("BENIGN", 0)
        st.attack += counts.get("ATTACK", 0)
    else:
        st.benign += counts.get("BENIGN", 0)
        st.attack += (sum(counts.values()) - counts.get("BENIGN", 0))


def write_stats(base_dir: Path, stats: Dict[str, Dict[str, Stats]]) -> None:
    for pname, splits in stats.items():
        out_stats = base_dir / pname / "stats.json"
        safe_mkdir(out_stats.parent)
        payload = {}
        for split, st in splits.items():
            payload[split] = {
                "rows": st.rows,
                "benign": st.benign,
                "attack": st.attack,
                "label_counts": dict(sorted(st.label_counts.items(), key=lambda x: x[1], reverse=True)),
            }
        out_stats.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


# ----------------------------
# Parquet writing (chunked)
# ----------------------------

def _table_no_meta(df: pd.DataFrame) -> Any:
    # sin metadata de pandas para evitar mismatches
    return pa.Table.from_pandas(df, preserve_index=False).replace_schema_metadata(None)

def write_parquet_wholefile(
    csv_path: Path,
    out_parquet: Path,
    dataset_name: str,
    target_fn: Callable[[pd.Series], pd.Series],
    chunksize: int,
) -> Dict[str, int]:
    """
    1 parquet por CSV. Escribe por chunks y devuelve counts del target.
    """
    _ensure_pyarrow()

    reader = pd.read_csv(
        csv_path,
        chunksize=chunksize,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace",
        on_bad_lines="skip",
    )

    writer: Optional[ParquetWriterType] = None
    schema_cols: Optional[List[str]] = None
    counts: Dict[str, int] = {}

    for chunk in reader:
        chunk, label_col = preprocess_chunk(chunk, dataset_name=dataset_name)
        if chunk.empty:
            continue

        labels = chunk[label_col].astype(str).map(normalize_label)
        chunk["label_raw"] = labels
        chunk["target"] = target_fn(labels)
        chunk = chunk.drop(columns=[label_col], errors="ignore")

        # reindex columnas para que TODOS los chunks tengan el mismo orden
        if schema_cols is None:
            schema_cols = list(chunk.columns)
        else:
            # añade columnas que falten (por seguridad) y reordena
            for c in schema_cols:
                if c not in chunk.columns:
                    chunk[c] = np.nan
            chunk = chunk.reindex(columns=schema_cols)

        vc = chunk["target"].value_counts(dropna=False)
        for k, v in vc.items():
            ks = str(k)
            counts[ks] = counts.get(ks, 0) + int(v)

        table = _table_no_meta(chunk)
        if writer is None:
            safe_mkdir(out_parquet.parent)
            writer = pq.ParquetWriter(out_parquet, table.schema, compression="snappy")
        writer.write_table(table)

    if writer is not None:
        writer.close()

    return counts


def write_anomaly_day_or_group(
    csv_path: Path,
    out_base: Path,
    dataset_name: str,
    split: str,
    chunksize: int,
) -> Dict[str, int]:
    """
    anomaly:
    - train: solo BENIGN -> train_benign
    - val/test: mixto con target binario -> val_mixed / test_mixed
    """
    _ensure_pyarrow()
    stem = csv_path.stem

    if split == "train":
        out_parquet = out_base / "train_benign" / f"{stem}.parquet"
        safe_mkdir(out_parquet.parent)

        reader = pd.read_csv(
            csv_path,
            chunksize=chunksize,
            low_memory=False,
            encoding="utf-8",
            encoding_errors="replace",
            on_bad_lines="skip",
        )

        writer: Optional[ParquetWriterType] = None
        schema_cols: Optional[List[str]] = None
        counts = {"BENIGN": 0}

        for chunk in reader:
            chunk, label_col = preprocess_chunk(chunk, dataset_name=dataset_name)
            if chunk.empty:
                continue

            labels = chunk[label_col].astype(str).map(normalize_label)
            chunk = chunk.loc[labels == "BENIGN"]
            if chunk.empty:
                continue

            chunk["label_raw"] = "BENIGN"
            chunk["target"] = "BENIGN"
            chunk = chunk.drop(columns=[label_col], errors="ignore")

            if schema_cols is None:
                schema_cols = list(chunk.columns)
            else:
                for c in schema_cols:
                    if c not in chunk.columns:
                        chunk[c] = np.nan
                chunk = chunk.reindex(columns=schema_cols)

            table = _table_no_meta(chunk)
            if writer is None:
                writer = pq.ParquetWriter(out_parquet, table.schema, compression="snappy")
            writer.write_table(table)
            counts["BENIGN"] += len(chunk)

        if writer is not None:
            writer.close()

        return counts

    # val/test mixed
    sub = "val_mixed" if split == "val" else "test_mixed"
    out_parquet = out_base / sub / f"{stem}.parquet"
    return write_parquet_wholefile(
        csv_path=csv_path,
        out_parquet=out_parquet,
        dataset_name=dataset_name,
        target_fn=make_binary_target,
        chunksize=chunksize,
    )


# ----------------------------
# RANDOM mode: shared masks for ALL pipelines (consistente)
# ----------------------------

def process_csv_random_all_pipelines(
    csv_path: Path,
    dataset_name: str,
    out_dataset_dir: Path,
    chunksize: int,
    rng: np.random.Generator,
    train_ratio: float,
    val_ratio: float,
) -> Dict[str, Dict[str, Dict[str, int]]]:
    """
    Escribe por CSV y por pipeline usando la MISMA máscara train/val/test para todos.
    """
    _ensure_pyarrow()
    thresholds = (train_ratio, train_ratio + val_ratio)
    stem = csv_path.stem

    pipelines: Dict[str, Callable[[pd.Series], pd.Series]] = {
        "binary": make_binary_target,
        "multiclass": make_multiclass_target,
        "multiclass_grouped": make_grouped_target,
    }

    counts: Dict[str, Dict[str, Dict[str, int]]] = {
        "binary": {"train": {}, "val": {}, "test": {}},
        "multiclass": {"train": {}, "val": {}, "test": {}},
        "multiclass_grouped": {"train": {}, "val": {}, "test": {}},
        "anomaly": {"train": {}, "val": {}, "test": {}},
    }

    # writers por pipeline/split (se crean al primer chunk no-vacío)
    writers: Dict[Tuple[str, str], ParquetWriterType] = {}
    schema_cols: Dict[Tuple[str, str], List[str]] = {}
    writers_anom: Dict[str, ParquetWriterType] = {}
    schema_cols_anom: Dict[str, List[str]] = {}

    def _write_supervised(pname: str, split: str, df: pd.DataFrame) -> None:
        if df.empty:
            return
        out_parquet = out_dataset_dir / pname / split / f"{stem}.parquet"
        safe_mkdir(out_parquet.parent)

        key = (pname, split)
        if key not in schema_cols:
            schema_cols[key] = list(df.columns)
        else:
            for c in schema_cols[key]:
                if c not in df.columns:
                    df[c] = np.nan
            df = df.reindex(columns=schema_cols[key])

        table = _table_no_meta(df)
        if key not in writers:
            writers[key] = pq.ParquetWriter(out_parquet, table.schema, compression="snappy")
        writers[key].write_table(table)

        vc = df["target"].value_counts(dropna=False)
        for k, v in vc.items():
            ks = str(k)
            counts[pname][split][ks] = counts[pname][split].get(ks, 0) + int(v)

    def _write_anom(subdir: str, split_key: str, df: pd.DataFrame) -> None:
        if df.empty:
            return
        out_parquet = out_dataset_dir / "anomaly" / subdir / f"{stem}.parquet"
        safe_mkdir(out_parquet.parent)

        if subdir not in schema_cols_anom:
            schema_cols_anom[subdir] = list(df.columns)
        else:
            for c in schema_cols_anom[subdir]:
                if c not in df.columns:
                    df[c] = np.nan
            df = df.reindex(columns=schema_cols_anom[subdir])

        table = _table_no_meta(df)
        if subdir not in writers_anom:
            writers_anom[subdir] = pq.ParquetWriter(out_parquet, table.schema, compression="snappy")
        writers_anom[subdir].write_table(table)

        vc = df["target"].value_counts(dropna=False)
        for k, v in vc.items():
            ks = str(k)
            counts["anomaly"][split_key][ks] = counts["anomaly"][split_key].get(ks, 0) + int(v)

    reader = pd.read_csv(
        csv_path,
        chunksize=chunksize,
        low_memory=False,
        encoding="utf-8",
        encoding_errors="replace",
        on_bad_lines="skip",
    )

    for chunk in reader:
        chunk, label_col = preprocess_chunk(chunk, dataset_name=dataset_name)
        if chunk.empty:
            continue

        labels = chunk[label_col].astype(str).map(normalize_label)

        r = rng.random(len(chunk))
        m_train = r < thresholds[0]
        m_val = (r >= thresholds[0]) & (r < thresholds[1])
        m_test = r >= thresholds[1]

        # supervised
        for pname, target_fn in pipelines.items():
            base = chunk.copy()
            base["label_raw"] = labels
            base["target"] = target_fn(labels)
            base = base.drop(columns=[label_col], errors="ignore")

            _write_supervised(pname, "train", base.loc[m_train])
            _write_supervised(pname, "val", base.loc[m_val])
            _write_supervised(pname, "test", base.loc[m_test])

        # anomaly
        # train_benign: solo benign de filas que caen en train
        tr = chunk.loc[m_train].copy()
        if not tr.empty:
            tr_labels = labels.loc[m_train]
            tr = tr.loc[tr_labels == "BENIGN"]
            if not tr.empty:
                tr["label_raw"] = "BENIGN"
                tr["target"] = "BENIGN"
                tr = tr.drop(columns=[label_col], errors="ignore")
                _write_anom("train_benign", "train", tr)

        # val/test: mixed con target binario
        for split, mask, subdir in [("val", m_val, "val_mixed"), ("test", m_test, "test_mixed")]:
            ch = chunk.loc[mask].copy()
            if ch.empty:
                continue
            lab = labels.loc[mask]
            ch["label_raw"] = lab
            ch["target"] = make_binary_target(lab)
            ch = ch.drop(columns=[label_col], errors="ignore")
            _write_anom(subdir, split, ch)

    for w in writers.values():
        w.close()
    for w in writers_anom.values():
        w.close()

    return counts


# ----------------------------
# MODE: day / groupkfold / random  (por dataset)
# ----------------------------

def process_mode_day(ds: DatasetSpec, out_mode_dir: Path, chunksize: int) -> None:
    csvs = list_csvs(ds.in_dir)
    if not csvs:
        raise SystemExit(f"[{ds.name}] No hay CSV en: {ds.in_dir}")

    out_dataset_dir = out_mode_dir / ds.name
    safe_mkdir(out_dataset_dir)

    pipelines = {
        "binary": make_binary_target,
        "multiclass": make_multiclass_target,
        "multiclass_grouped": make_grouped_target,
    }

    stats: Dict[str, Dict[str, Stats]] = {p: {"train": Stats(), "val": Stats(), "test": Stats()}
                                          for p in list(pipelines.keys()) + ["anomaly"]}

    for i, csv_path in enumerate(csvs, start=1):
        day = file_day_bucket(csv_path.name)
        split = split_from_day(day)
        print(f"\n({i}/{len(csvs)}) [day][{ds.name}] {csv_path.name} -> {split} (day={day})")

        for pname, target_fn in pipelines.items():
            out_parquet = out_dataset_dir / pname / split / f"{csv_path.stem}.parquet"
            counts = write_parquet_wholefile(csv_path, out_parquet, ds.name, target_fn, chunksize)
            add_counts(stats[pname][split], counts, pname)

        counts_a = write_anomaly_day_or_group(
            csv_path=csv_path,
            out_base=out_dataset_dir / "anomaly",
            dataset_name=ds.name,
            split=split,
            chunksize=chunksize,
        )
        add_counts(stats["anomaly"][split], counts_a, "binary")

    write_stats(out_dataset_dir, stats)


def process_mode_groupkfold(ds: DatasetSpec, out_mode_dir: Path, chunksize: int) -> None:
    csvs = list_csvs(ds.in_dir)
    if not csvs:
        raise SystemExit(f"[{ds.name}] No hay CSV en: {ds.in_dir}")

    n = len(csvs)
    dataset_dir = out_mode_dir / ds.name
    safe_mkdir(dataset_dir)

    pipelines = {
        "binary": make_binary_target,
        "multiclass": make_multiclass_target,
        "multiclass_grouped": make_grouped_target,
    }

    for fold in range(n):
        fold_dir = dataset_dir / f"fold_{fold}"
        safe_mkdir(fold_dir)

        test_file = csvs[fold]
        val_file = csvs[(fold + 1) % n]
        train_files = [p for p in csvs if p not in {test_file, val_file}]

        print(f"\n== [groupkfold][{ds.name}] fold_{fold} ==")
        print(f"  test : {test_file.name}")
        print(f"  val  : {val_file.name}")
        print(f"  train: {len(train_files)} files")

        stats: Dict[str, Dict[str, Stats]] = {p: {"train": Stats(), "val": Stats(), "test": Stats()}
                                              for p in list(pipelines.keys()) + ["anomaly"]}

        def handle(csv_path: Path, split: str) -> None:
            print(f"  - {split}: {csv_path.name}")

            for pname, target_fn in pipelines.items():
                out_parquet = fold_dir / pname / split / f"{csv_path.stem}.parquet"
                counts = write_parquet_wholefile(csv_path, out_parquet, ds.name, target_fn, chunksize)
                add_counts(stats[pname][split], counts, pname)

            counts_a = write_anomaly_day_or_group(
                csv_path=csv_path,
                out_base=fold_dir / "anomaly",
                dataset_name=ds.name,
                split=split,
                chunksize=chunksize,
            )
            add_counts(stats["anomaly"][split], counts_a, "binary")

        for p in train_files:
            handle(p, "train")
        handle(val_file, "val")
        handle(test_file, "test")

        write_stats(fold_dir, stats)


def process_mode_random(ds: DatasetSpec, out_mode_dir: Path, chunksize: int, seed: int, train_ratio: float, val_ratio: float) -> None:
    csvs = list_csvs(ds.in_dir)
    if not csvs:
        raise SystemExit(f"[{ds.name}] No hay CSV en: {ds.in_dir}")

    out_dataset_dir = out_mode_dir / ds.name
    safe_mkdir(out_dataset_dir)

    rng = np.random.default_rng(seed)

    stats: Dict[str, Dict[str, Stats]] = {p: {"train": Stats(), "val": Stats(), "test": Stats()}
                                          for p in ["binary", "multiclass", "multiclass_grouped", "anomaly"]}

    for i, csv_path in enumerate(csvs, start=1):
        print(f"\n({i}/{len(csvs)}) [random][{ds.name}] {csv_path.name}")

        counts = process_csv_random_all_pipelines(
            csv_path=csv_path,
            dataset_name=ds.name,
            out_dataset_dir=out_dataset_dir,
            chunksize=chunksize,
            rng=rng,
            train_ratio=train_ratio,
            val_ratio=val_ratio,
        )

        # acumula stats
        for pname in ["binary", "multiclass", "multiclass_grouped", "anomaly"]:
            for split in ["train", "val", "test"]:
                add_counts(stats[pname][split], counts[pname][split], "binary" if pname == "anomaly" else pname)

    write_stats(out_dataset_dir, stats)


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ml_dir", type=str, default=str(DEFAULT_ML_DIR))
    ap.add_argument("--tl_dir", type=str, default=str(DEFAULT_TL_DIR))
    ap.add_argument("--out_dir", type=str, default=str(DEFAULT_OUT_DIR))

    ap.add_argument("--split_mode", type=str, default="day", choices=["day", "groupkfold", "random"])
    ap.add_argument("--chunksize", type=int, default=250_000)

    # random params
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--train_ratio", type=float, default=0.70)
    ap.add_argument("--val_ratio", type=float, default=0.15)

    ap.add_argument("--datasets", type=str, default="both", choices=["both", "ml", "tl"])

    args = ap.parse_args()
    _ensure_pyarrow()

    ml_dir = resolve_from_root(args.ml_dir)
    tl_dir = resolve_from_root(args.tl_dir)
    out_base = resolve_from_root(args.out_dir)

    out_mode_dir = out_base / args.split_mode
    safe_mkdir(out_mode_dir)

    datasets: List[DatasetSpec] = []
    if args.datasets in {"both", "ml"}:
        datasets.append(DatasetSpec(name="MachineLearningCVE", in_dir=ml_dir, keep_meta=False))
    if args.datasets in {"both", "tl"}:
        datasets.append(DatasetSpec(name="TrafficLabelling", in_dir=tl_dir, keep_meta=True))

    print("== prepare_dataset ==")
    print(f"Repo root : {repo_root()}")
    print(f"Split mode: {args.split_mode}")
    print(f"Out mode  : {out_mode_dir}")
    print(f"Chunksize : {args.chunksize}")
    print(f"Datasets  : {[d.name for d in datasets]}")

    if args.split_mode == "random":
        if not (0.0 < args.train_ratio < 1.0) or not (0.0 <= args.val_ratio < 1.0) or not (args.train_ratio + args.val_ratio < 1.0):
            raise SystemExit("Ratios inválidos para random: requiere 0<train<1, 0<=val<1 y train+val<1.")

    for ds in datasets:
        if not ds.in_dir.exists():
            raise SystemExit(f"[{ds.name}] No existe carpeta: {ds.in_dir}")

        if args.split_mode == "day":
            process_mode_day(ds, out_mode_dir, args.chunksize)
        elif args.split_mode == "groupkfold":
            process_mode_groupkfold(ds, out_mode_dir, args.chunksize)
        elif args.split_mode == "random":
            process_mode_random(ds, out_mode_dir, args.chunksize, args.seed, args.train_ratio, args.val_ratio)

    print("\nListo ✅ Parquets generados en:")
    print(out_mode_dir)
    print("\nEjemplos:")
    print(f"  {out_mode_dir}/MachineLearningCVE/binary/stats.json")
    print(f"  {out_mode_dir}/TrafficLabelling/binary/stats.json")


if __name__ == "__main__":
    main()