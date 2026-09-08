#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Umbral adaptativo a la prevalencia: se puede recuperar el recall perdido en
presupuesto fijo sin tocar una sola etiqueta del conjunto de destino?

Problema medido
---------------
En el bloqueo temprano, validacion y test difieren en prevalencia (58 % frente a
85 % de IPs bloqueables). Un umbral fijado para precision 0,99 en validacion
resulta conservador donde hay mas positivos: a K=5 se consigue recall 0,846
cuando el umbral-oraculo sobre test alcanzaria 0,987.

Metodo (correccion de prior shift, sin etiquetas del destino)
-------------------------------------------------------------
  1. Calibrar los scores en validacion (regresion isotonica).
  2. Estimar la prevalencia del destino como la media de los scores calibrados
     sobre el destino SIN etiquetas:  pi_hat = mean(score_calibrado).
  3. De validacion salen las curvas TPR(t) y FPR(t). La precision esperada bajo
     la prevalencia estimada es
         prec(t) = pi_hat*TPR(t) / (pi_hat*TPR(t) + (1-pi_hat)*FPR(t))
  4. Elegir el menor t con prec(t) >= objetivo y aplicarlo al destino.

Todo lo que usa del destino es la distribucion de scores -- observable en
despliegue real sin etiquetar nada.

Validacion: se compara contra la linea base (umbral de validacion directo) y
contra el oraculo (cota superior), sobre el mismo split de test de ARGOS.

Fichero nuevo; no modifica ningun script existente.

Uso:
    python experiment_adaptive_threshold.py
"""

from __future__ import annotations

import argparse
from typing import Any, Dict

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import precision_recall_curve

from experiment_early_blocking import full_label, load_ip_histories, threshold_for_precision
from experiment_early_blocking_v2 import V2_FEATURES, arrival_context, features_v2, oracle_recall
from train_utils import artifacts_root, now_run_id, run_header, save_json, set_seed


def adaptive_threshold(y_val: np.ndarray, s_val_cal: np.ndarray,
                       s_dst_cal: np.ndarray, target: float) -> tuple[float, float]:
    """Umbral corregido por prior shift. Devuelve (umbral, prevalencia_estimada)."""
    pi_hat = float(np.clip(s_dst_cal.mean(), 1e-6, 1 - 1e-6))
    candidates = np.unique(s_val_cal)
    pos = y_val == 1
    n_pos, n_neg = int(pos.sum()), int((~pos).sum())
    best = float(candidates.max())
    for t in candidates:
        tpr = float((s_val_cal[pos] >= t).sum()) / max(n_pos, 1)
        fpr = float((s_val_cal[~pos] >= t).sum()) / max(n_neg, 1)
        denom = pi_hat * tpr + (1 - pi_hat) * fpr
        if denom <= 0:
            continue
        if pi_hat * tpr / denom >= target:
            best = float(t)
            break
    return best, pi_hat


def realized(y: np.ndarray, s: np.ndarray, threshold: float) -> Dict[str, float]:
    blocked = s >= threshold
    tp = int((blocked & (y == 1)).sum())
    fp = int((blocked & (y == 0)).sum())
    return {
        "recall": tp / max(int(y.sum()), 1),
        "precision": tp / max(tp + fp, 1),
        "fp": fp,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Umbral adaptativo a prevalencia (prior shift)")
    parser.add_argument("--budgets", type=int, nargs="+", default=[2, 3, 5])
    parser.add_argument("--target_precision", type=float, default=0.99)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    set_seed(args.seed)

    root = artifacts_root("exp_adaptive_threshold", "date", "ARGOS-LAB", now_run_id())
    run_header("experiment_adaptive_threshold (ARGOS-LAB)",
               metodo="calibracion isotonica + correccion de prior shift",
               objetivo=f"precision >= {args.target_precision:.0%}", out=root)

    histories = load_ip_histories()
    ips = sorted(histories, key=lambda ip: histories[ip][0][0])
    labels = {ip: full_label(histories[ip]) for ip in ips}
    context = arrival_context(histories, ips)
    cut_tr, cut_va = int(len(ips) * 0.70), int(len(ips) * 0.85)
    split = {ip: ("train" if i < cut_tr else "val" if i < cut_va else "test")
             for i, ip in enumerate(ips)}

    results: Dict[str, Any] = {}
    print(f"\n  {'K':>4}{'metodo':>12}{'umbral':>9}{'pi_est':>8}{'recall':>9}"
          f"{'precision':>11}{'FP':>5}")
    for budget in args.budgets:
        frames = {name: [] for name in ("train", "val", "test")}
        for ip in ips:
            row = features_v2(histories[ip], budget, context[ip])
            row["y"] = labels[ip]
            frames[split[ip]].append(row)
        tr = pd.DataFrame(frames["train"]); va = pd.DataFrame(frames["val"]); te = pd.DataFrame(frames["test"])
        y_va, y_te = va["y"].to_numpy(), te["y"].to_numpy()

        model = HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.08, max_depth=5, l2_regularization=1.0,
            early_stopping=True, validation_fraction=0.15, n_iter_no_change=15,
            class_weight="balanced", random_state=args.seed,
        ).fit(tr[V2_FEATURES], tr["y"])
        s_va = model.predict_proba(va[V2_FEATURES])[:, 1]
        s_te = model.predict_proba(te[V2_FEATURES])[:, 1]

        calibrator = IsotonicRegression(out_of_bounds="clip").fit(s_va, y_va)
        c_va, c_te = calibrator.predict(s_va), calibrator.predict(s_te)

        base_thr = threshold_for_precision(y_va, s_va, args.target_precision)
        adaptive_thr, pi_hat = adaptive_threshold(y_va, c_va, c_te, args.target_precision)

        rows = {
            "base (val)": (realized(y_te, s_te, base_thr), base_thr, ""),
            "adaptativo": (realized(y_te, c_te, adaptive_thr), adaptive_thr, f"{pi_hat:.3f}"),
        }
        entry: Dict[str, Any] = {"pi_real_test": float(y_te.mean()), "pi_estimada": pi_hat}
        for name, (metric, threshold, pi_text) in rows.items():
            entry[name] = {**metric, "umbral": threshold}
            print(f"  {budget:>4}{name:>12}{threshold:>9.3f}{pi_text:>8}"
                  f"{metric['recall']:>9.3f}{metric['precision']:>11.3f}{metric['fp']:>5}")
        entry["oraculo_recall"] = oracle_recall(y_te, s_te, args.target_precision)
        print(f"  {'':>4}{'oraculo':>12}{'--':>9}{y_te.mean():>8.3f}"
              f"{entry['oraculo_recall']:>9.3f}{args.target_precision:>11.2f}{'--':>5}")
        results[str(budget)] = entry

    save_json(root / "results.json", {"args": vars(args), **results})
    print(f"\nGuardado: {root}")


if __name__ == "__main__":
    main()
