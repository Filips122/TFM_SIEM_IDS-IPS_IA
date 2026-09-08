#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Diagnostico persistente: la exactitud 0,26 de la particion oficial de UNSW-NB15
es fuga por la columna `id`, no un cambio de distribucion.

Contexto (R11 y su fe de erratas, 2026-09-08)
---------------------------------------------
La particion oficial (`training-set` -> train, `testing-set` -> val/test 50/50)
daba exactitud 0,2635 con el HGB binario, por debajo de la linea base
mayoritaria del test (0,68). Una cifra por debajo del azar no es un problema de
generalizacion: senala una feature espuria. La particion oficial incluye la
columna `id` entre sus 43 features, y en `training-set` la etiqueta forma
bloques a lo largo de `id` (4 cambios en 82.332 filas), mientras que en
`testing-set` cambia miles de veces. El modelo aprendio "el id dice la clase".

Este script deja el diagnostico en un artefacto reproducible:

  1. bloques de etiqueta a lo largo de `id` en train y en test;
  2. columnas categoricas que llegan 100 % a NaN (proto, service, state) por el
     chequeo `dtype == object` con pandas 3 (cadenas `str`);
  3. el mismo HGB (200 iter., semilla 42) en tres variantes sobre el Parquet
     oficial existente: con `id`, con `id` permutado en test, y sin `id`.

Fichero nuevo; no modifica ningun script existente. No regenera datasets.

Uso:
    python experiment_official_id_leak.py
"""

from __future__ import annotations

import argparse
import glob
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

from train_utils import artifacts_root, now_run_id, repo_root, set_seed

OFFICIAL = Path("src/models/UNSW-NB15/datasets/official/NUSW-NB15/binary")
NON_FEATURES = {"target", "label_raw", "attack_cat", "label"}
CATEGORICAL = ["proto", "service", "state", "srcip", "dstip"]


def load_split(base: Path, split: str) -> pd.DataFrame:
    files = sorted(glob.glob(str(base / split / "*.parquet")))
    if not files:
        raise SystemExit(f"Sin parquet en {base / split}")
    return pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)


def label_changes_along(df: pd.DataFrame, key: str) -> int:
    seq = df.sort_values(key)["target"].to_numpy()
    return int((seq[1:] != seq[:-1]).sum())


def fit_eval(train: pd.DataFrame, test: pd.DataFrame, cols: list[str], seed: int,
             permute_in_test: str | None = None) -> dict:
    X_tr = np.nan_to_num(train[cols].to_numpy(np.float32))
    X_te = test[cols].copy()
    if permute_in_test:
        rng = np.random.default_rng(seed)
        X_te[permute_in_test] = rng.permutation(X_te[permute_in_test].to_numpy())
    X_te = np.nan_to_num(X_te.to_numpy(np.float32))
    y_tr = (train["target"] == "ATTACK").astype(int).to_numpy()
    y_te = (test["target"] == "ATTACK").astype(int).to_numpy()
    t0 = time.time()
    model = HistGradientBoostingClassifier(
        max_iter=200, learning_rate=0.1, max_depth=3, early_stopping=True,
        validation_fraction=0.1, n_iter_no_change=7, tol=1e-4, random_state=seed,
    ).fit(X_tr, y_tr)
    proba = model.predict_proba(X_te)[:, 1]
    pred = (proba >= 0.5).astype(int)
    return {
        "n_features": len(cols),
        "accuracy": float(accuracy_score(y_te, pred)),
        "macro_f1": float(f1_score(y_te, pred, average="macro")),
        "roc_auc": float(roc_auc_score(y_te, proba)),
        "n_iter": int(model.n_iter_),
        "fit_seconds": round(time.time() - t0, 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Fuga por `id` en la particion oficial de UNSW-NB15")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    set_seed(args.seed)

    base = repo_root() / OFFICIAL
    root = artifacts_root("exp_official_id_leak", "official", now_run_id())
    print("== experiment_official_id_leak (UNSW-NB15) ==")
    print(f"datos : {base}\nout   : {root}\n", flush=True)

    train, test = load_split(base, "train"), load_split(base, "test")
    features = [c for c in train.columns if c not in NON_FEATURES and pd.api.types.is_numeric_dtype(train[c])]
    y_te = (test["target"] == "ATTACK").astype(int).to_numpy()

    results = {
        "args": vars(args),
        "datos": {
            "train_rows": int(len(train)), "test_rows": int(len(test)),
            "train_clases": train["target"].value_counts().to_dict(),
            "test_clases": test["target"].value_counts().to_dict(),
            "prevalencia_attack_test": float(y_te.mean()),
            "linea_base_mayoritaria_test": float(max(y_te.mean(), 1 - y_te.mean())),
            "n_features": len(features), "id_en_features": "id" in features,
        },
        "bloques_de_etiqueta_a_lo_largo_de_id": {
            "cambios_train": label_changes_along(train, "id") if "id" in train else None,
            "cambios_test": label_changes_along(test, "id") if "id" in test else None,
            "lectura": "pocos cambios en train = la etiqueta es casi una funcion escalonada de `id`",
        },
        "categoricas_anuladas": {},
        "variantes": {},
    }
    for col in CATEGORICAL:
        if col in train.columns:
            v = pd.to_numeric(train[col], errors="coerce")
            results["categoricas_anuladas"][col] = {
                "nan_ratio_train": float(v.isna().mean()),
                "std_tras_nan_a_0": float(np.nanstd(v.fillna(0))),
            }

    print(f"  {'variante':<28}{'features':>9}{'acc':>9}{'macroF1':>9}{'ROC':>9}{'iters':>7}")
    variants = [
        ("con_id", features, None),
        ("con_id_permutado_en_test", features, "id"),
        ("sin_id", [c for c in features if c != "id"], None),
    ]
    for name, cols, permute in variants:
        if permute and permute not in cols:
            continue
        entry = fit_eval(train, test, cols, args.seed, permute)
        results["variantes"][name] = entry
        print(f"  {name:<28}{entry['n_features']:>9}{entry['accuracy']:>9.4f}{entry['macro_f1']:>9.4f}"
              f"{entry['roc_auc']:>9.4f}{entry['n_iter']:>7}")

    con, sin = results["variantes"]["con_id"], results["variantes"]["sin_id"]
    results["veredicto"] = {
        "fuga_confirmada": bool(sin["accuracy"] - con["accuracy"] > 0.3),
        "delta_accuracy_sin_menos_con": sin["accuracy"] - con["accuracy"],
        "contraste_honesto": ("laxo (random, R11) macro-F1 0,9841 frente a oficial sin `id` "
                              f"macro-F1 {sin['macro_f1']:.4f}; el 0,26 con `id` no es un resultado"),
    }
    print(f"\n  veredicto: fuga por `id` {'CONFIRMADA' if results['veredicto']['fuga_confirmada'] else 'no confirmada'}"
          f"  (acc {con['accuracy']:.4f} -> {sin['accuracy']:.4f} al quitar `id`)")
    (root / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Guardado: {root / 'results.json'}")


if __name__ == "__main__":
    main()
