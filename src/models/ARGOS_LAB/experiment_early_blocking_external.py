#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validacion externa del bloqueo temprano secuencial sobre LAB-ALERTS.

Protocolo de un solo disparo (segundo experimento sobre el conjunto externo)
---------------------------------------------------------------------------
El presupuesto de un-solo-disparo de LAB-ALERTS ya se gasto una vez para el
puntuador de ventanas. Este es un experimento DISTINTO -- unidad IP, politica
secuencial -- y consume su propio disparo: canalizacion congelada en ARGOS-LAB
(modelos, variables, umbrales y semilla identicos a experiment_early_blocking_v2)
y una unica ejecucion cuyo resultado se reporta tal cual. Cualquier iteracion
posterior contra LAB-ALERTS degradaria este conjunto a desarrollo.

Que se cruza
------------
  entrenamiento : IPs de ARGOS-LAB (30 dias), umbrales p99 fijados en su validacion
  evaluacion    : las IPs de LAB-ALERTS (otro entorno, 11 horas), con politica
                  secuencial: bloquear al primer cruce de umbral

La reputacion de subred y el contexto de flota del destino se computan sobre el
PROPIO LAB-ALERTS de forma causal -- observacion sin etiquetas del entorno
destino, disponible en cualquier despliegue real.

Sesgo de censura, declarado
---------------------------
La captura externa dura 11 horas: una IP que habria llegado a cumplir los
criterios mas alla del corte queda etiquetada como no bloqueable. Ese censurado
juega EN CONTRA del modelo (aciertos contados como falsos positivos), de modo
que la precision medida aqui es un suelo, no una estimacion neutra.

Fichero nuevo; no modifica ningun script existente.

Uso:
    python experiment_early_blocking_external.py
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from experiment_early_blocking import full_label, load_ip_histories, threshold_for_precision
from experiment_early_blocking_v2 import V2_FEATURES, arrival_context, features_v2
from train_utils import artifacts_root, now_run_id, repo_root, run_header, save_json, set_seed

LAB_FLAT = Path("src/models/ARGOS_LAB/datasets/crosstest/lab-alerts_flat.jsonl")


def clean(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"", "nan", "none", "null"} else text


def load_histories(path: Path) -> Dict[str, List[tuple]]:
    """Historiales por IP desde un JSONL plano arbitrario (mismo esquema)."""
    histories: Dict[str, List[tuple]] = defaultdict(list)
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = clean(alert.get("src_ip"))
            if not ip:
                continue
            ts_text = clean(alert.get("timestamp")).replace("Z", "+00:00")
            try:
                epoch = datetime.fromisoformat(ts_text).timestamp()
            except ValueError:
                continue
            user = (clean(alert.get("src_user")) or clean(alert.get("dst_user"))).lower()
            histories[ip].append((
                epoch, clean(alert.get("agent_id")), user,
                bool(clean(alert.get("src_port"))), clean(alert.get("window_start")),
            ))
    for ip in histories:
        histories[ip].sort(key=lambda item: item[0])
    return histories


def main() -> None:
    parser = argparse.ArgumentParser(description="Bloqueo temprano secuencial sobre LAB-ALERTS (un disparo)")
    parser.add_argument("--budgets", type=int, nargs="+", default=[1, 2, 3, 5, 10, 20])
    parser.add_argument("--target_precision", type=float, default=0.99)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    set_seed(args.seed)

    root = artifacts_root("exp_early_blocking_external", "date", "ARGOS_a_LAB-ALERTS", now_run_id())
    run_header("experiment_early_blocking_external",
               entrenamiento="IPs de ARGOS-LAB (30 dias)",
               evaluacion="IPs de LAB-ALERTS (11 h, otro entorno)",
               politica="secuencial, umbrales p99 congelados de ARGOS", out=root)

    # ---------------- lado ARGOS: entrenar y fijar umbrales (congelado) -----
    print("  preparando el lado ARGOS (identico a v2) ...", flush=True)
    hist_a = load_ip_histories()
    ips_a = sorted(hist_a, key=lambda ip: hist_a[ip][0][0])
    labels_a = {ip: full_label(hist_a[ip]) for ip in ips_a}
    ctx_a = arrival_context(hist_a, ips_a)
    cut_tr, cut_va = int(len(ips_a) * 0.70), int(len(ips_a) * 0.85)
    split_a = {ip: ("train" if i < cut_tr else "val" if i < cut_va else "test")
               for i, ip in enumerate(ips_a)}

    # ---------------- lado LAB: historiales y contexto propio ---------------
    hist_l = load_histories(repo_root() / LAB_FLAT)
    ips_l = sorted(hist_l, key=lambda ip: hist_l[ip][0][0])
    labels_l = {ip: full_label(hist_l[ip]) for ip in ips_l}
    ctx_l = arrival_context(hist_l, ips_l)
    y_lab = np.array([labels_l[ip] for ip in ips_l])
    overlap = len(set(ips_l) & set(hist_a))
    print(f"  LAB: IPs={len(ips_l):,}  bloqueables (censurado a 11 h)={y_lab.mean():.1%}  "
          f"solapadas con ARGOS={overlap}")

    # ---------------- entrenar por presupuesto y aplicar secuencia ----------
    blocked_at = np.full(len(ips_l), -1, dtype=int)
    per_budget = {}
    for budget in sorted(args.budgets):
        frames = {"train": [], "val": []}
        for ip in ips_a:
            if split_a[ip] == "test":
                continue
            row = features_v2(hist_a[ip], budget, ctx_a[ip])
            row["y"] = labels_a[ip]
            frames[split_a[ip]].append(row)
        tr = pd.DataFrame(frames["train"]); va = pd.DataFrame(frames["val"])
        model = HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.08, max_depth=5, l2_regularization=1.0,
            early_stopping=True, validation_fraction=0.15, n_iter_no_change=15,
            class_weight="balanced", random_state=args.seed,
        ).fit(tr[V2_FEATURES], tr["y"])
        threshold = threshold_for_precision(
            va["y"].to_numpy(), model.predict_proba(va[V2_FEATURES])[:, 1], args.target_precision)

        lab_rows = pd.DataFrame([features_v2(hist_l[ip], budget, ctx_l[ip]) for ip in ips_l])
        scores = model.predict_proba(lab_rows[V2_FEATURES])[:, 1]
        newly = (scores >= threshold) & (blocked_at < 0)
        blocked_at[newly] = budget
        per_budget[str(budget)] = {"umbral_argos": float(threshold),
                                   "bloqueadas_nuevas": int(newly.sum())}

    # ---------------- metrica de la politica --------------------------------
    blocked = blocked_at > 0
    tp = blocked & (y_lab == 1)
    fp = blocked & (y_lab == 0)
    ks = blocked_at[tp]
    prevented = int(sum(max(0, len(hist_l[ip]) - k)
                        for ip, k, good in zip(ips_l, blocked_at, tp) if good))
    future = int(sum(max(0, len(hist_l[ip]) - 1) for ip in ips_l if labels_l[ip]))

    out = {
        "ips_evaluadas": int(len(ips_l)),
        "prevalencia_censurada": float(y_lab.mean()),
        "ips_solapadas_con_argos": overlap,
        "recall": float(tp.sum() / max(int(y_lab.sum()), 1)),
        "precision": float(tp.sum() / max(int(blocked.sum()), 1)),
        "ips_no_bloqueables_cortadas": int(fp.sum()),
        "aviso_mediano_de_bloqueo": float(np.median(ks)) if len(ks) else None,
        "avisos_evitados": prevented,
        "avisos_futuros_totales": future,
        "avisos_evitados_pct": prevented / max(future, 1),
        "reparto_por_K": {str(k): int((ks == k).sum()) for k in sorted(set(ks.tolist()))},
        "por_presupuesto": per_budget,
        "nota_censura": ("Etiquetas censuradas a 11 h: la precision medida es un suelo -- "
                         "parte de los cortes contados como error corresponderian a IPs que "
                         "habrian cumplido criterios tras el fin de la captura."),
    }
    print("\n  == RESULTADO (un disparo, se reporta tal cual) ==")
    print(f"    recall               : {out['recall']:.3f}")
    print(f"    precision (suelo)    : {out['precision']:.3f}")
    print(f"    cortadas 'no bloq.'  : {out['ips_no_bloqueables_cortadas']}")
    print(f"    aviso mediano        : {out['aviso_mediano_de_bloqueo']}")
    print(f"    avisos evitados      : {out['avisos_evitados']:,} ({out['avisos_evitados_pct']:.0%})")
    print(f"    reparto por K        : {out['reparto_por_K']}")

    save_json(root / "results.json", {"args": vars(args), **out})
    print(f"\nGuardado: {root}")


if __name__ == "__main__":
    main()
