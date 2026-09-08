#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deteccion de red team en LANL: la metodologia ARGOS contra ground truth real.

Que responde este experimento
-----------------------------
La limitacion central de la linea ARGOS-LAB es que sus etiquetas son
heuristicas. Aqui la etiqueta es un registro de compromisos reales
(`redteam.txt`), independiente por construccion del flujo de eventos. Si las
mismas ideas -- features conductuales causales, particion temporal, metricas de
clase rara con desglose por grupo, lista de caza para el analista -- funcionan
contra verdad de campo, la metodologia queda validada donde de verdad importa.

Tarea: clasificar celdas (maquina origen, hora) como rojas/no-rojas.
Prevalencia esperada ~1e-4: la metrica principal es PR-AUC de la clase roja y,
operativamente, la LISTA DE CAZA -- si un analista revisa las k celdas mas
sospechosas de cada dia, cuantas horas rojas encuentra y a que coste.

Modelos: HGB balanceado (supervisado) e Isolation Forest (no supervisado, como
referencia -- en ARGOS el no supervisado fallo; con ground truth real se puede
medir limpiamente si aqui aporta algo).

Uso:
    python train_lanl_redteam.py
    python train_lanl_redteam.py --train_end 10 --val_end 15
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

DATA = Path(__file__).resolve().parent / "datasets" / "hourly"
ARTIFACTS = Path(__file__).resolve().parent / "artifacts" / "redteam_hourly"


def hunt_list(df: pd.DataFrame, scores: np.ndarray, k_per_day: int) -> Dict[str, Any]:
    """El analista revisa las k celdas mas sospechosas de cada dia."""
    work = df[["day", "red"]].copy()
    work["score"] = scores
    picked = work.sort_values("score", ascending=False).groupby("day").head(k_per_day)
    found = int(picked["red"].sum())
    total_red = int(work["red"].sum())
    return {
        "k_por_dia": k_per_day,
        "celdas_revisadas": int(len(picked)),
        "rojas_encontradas": found,
        "rojas_totales": total_red,
        "recall": found / max(total_red, 1),
        "precision": found / max(len(picked), 1),
    }


def per_day_breakdown(df: pd.DataFrame, scores: np.ndarray) -> Dict[str, Any]:
    """Regla del proyecto: nada agregado sin desglose. Aqui el grupo es el dia
    (solo dias con alguna celda roja son evaluables)."""
    out = {}
    work = df[["day", "red"]].copy()
    work["score"] = scores
    for day, part in work.groupby("day"):
        if part["red"].sum() == 0 or part["red"].sum() == len(part):
            continue
        ap = average_precision_score(part["red"], part["score"])
        base = part["red"].mean()
        out[str(int(day))] = {
            "n": int(len(part)), "rojas": int(part["red"].sum()),
            "pr_auc": float(ap), "base": float(base),
            "lift": float(ap / base) if base > 0 else float("nan"),
        }
    return out


def evaluate(tag: str, df: pd.DataFrame, scores: np.ndarray) -> Dict[str, Any]:
    y = df["red"].to_numpy()
    out: Dict[str, Any] = {"n": int(len(df)), "rojas": int(y.sum()), "prevalencia": float(y.mean())}
    if 0 < y.sum() < len(y):
        out["roc_auc"] = float(roc_auc_score(y, scores))
        out["pr_auc"] = float(average_precision_score(y, scores))
        out["lift"] = out["pr_auc"] / out["prevalencia"]
    out["lista_caza"] = {str(k): hunt_list(df, scores, k) for k in (10, 25, 50)}
    out["por_dia"] = per_day_breakdown(df, scores)
    print(f"\n  [{tag}] n={out['n']:,}  rojas={out['rojas']}  prevalencia={out['prevalencia']:.2e}")
    if "pr_auc" in out:
        print(f"    ROC-AUC={out['roc_auc']:.4f}   PR-AUC={out['pr_auc']:.4f}   "
              f"lift={out['lift']:.0f}x")
    for k, h in out["lista_caza"].items():
        print(f"    caza top-{k}/dia: encuentra {h['rojas_encontradas']}/{h['rojas_totales']} "
              f"(recall {h['recall']:.2f}) revisando {h['celdas_revisadas']:,} celdas "
              f"(precision {h['precision']:.3f})")
    if out["por_dia"]:
        print("    por dia (rojas): " + "  ".join(
            f"d{d}:lift={v['lift']:.0f}x" for d, v in out["por_dia"].items()))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Red team LANL sobre celdas horarias")
    parser.add_argument("--train_end", type=int, default=10, help="train: dia < este")
    parser.add_argument("--val_end", type=int, default=15, help="val: dia < este; test: resto")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    run_dir = ARTIFACTS / time.strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    print("== train_lanl_redteam (CSR-LANL) ==")
    print(f"datos: {DATA}   salida: {run_dir}")

    df = pd.read_parquet(DATA / "cells.parquet")
    features = [c for c in json.loads((DATA / "summary.json").read_text())["features"]]
    print(f"celdas={len(df):,}  rojas={int(df.red.sum())}  features={len(features)}")

    train = df[df.day < args.train_end]
    val = df[(df.day >= args.train_end) & (df.day < args.val_end)]
    test = df[df.day >= args.val_end]
    for name, part in (("train", train), ("val", val), ("test", test)):
        print(f"  {name:<6} celdas={len(part):>9,}  rojas={int(part.red.sum()):>4}  "
              f"dias {int(part.day.min())}-{int(part.day.max())}")
    if min(train.red.sum(), test.red.sum()) == 0:
        raise SystemExit("Particion sin celdas rojas en train o test: ajusta --train_end/--val_end")

    results: Dict[str, Any] = {"args": vars(args), "features": features}

    # ---------------- supervisado -------------------------------------------
    model = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.08, max_depth=6, l2_regularization=1.0,
        early_stopping=True, validation_fraction=0.15, n_iter_no_change=20,
        class_weight="balanced", random_state=args.seed,
    ).fit(train[features], train["red"])
    print("\n  == HGB supervisado (etiquetas reales de red team) ==")
    results["hgb"] = {
        "val": evaluate("val", val, model.predict_proba(val[features])[:, 1]),
        "test": evaluate("test", test, model.predict_proba(test[features])[:, 1]),
    }

    # ---------------- no supervisado (referencia) ---------------------------
    mean = train[features].mean().to_numpy()
    std = train[features].std().replace(0, 1.0).to_numpy()
    z = lambda part: np.clip((part[features].to_numpy() - mean) / std, -8, 8)
    iso = IsolationForest(n_estimators=300, random_state=args.seed, n_jobs=-1).fit(z(train))
    print("\n  == Isolation Forest no supervisado (referencia) ==")
    results["isoforest"] = {
        "test": evaluate("test", test, -iso.score_samples(z(test))),
    }

    # ---------------- sondas univariantes (diagnostico) ---------------------
    y_val = val["red"].to_numpy()
    probes = {}
    if 0 < y_val.sum() < len(y_val):
        for feature in features:
            s = val[feature].to_numpy()
            try:
                auc = roc_auc_score(y_val, s)
            except ValueError:
                continue
            probes[feature] = float(max(auc, 1 - auc))
        top = sorted(probes.items(), key=lambda kv: -kv[1])[:8]
        results["sondas_univariantes_val"] = dict(top)
        print("\n  variables mas informativas (AUC univariante, val): "
              + ", ".join(f"{k}={v:.3f}" for k, v in top))

    (run_dir / "results.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nGuardado: {run_dir}")


if __name__ == "__main__":
    main()
