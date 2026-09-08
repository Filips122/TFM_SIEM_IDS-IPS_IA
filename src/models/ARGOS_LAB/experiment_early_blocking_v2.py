#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bloqueo temprano v2: politica secuencial + reputacion de subred.

Tres mejoras sobre experiment_early_blocking.py, cada una atacando una perdida
identificada:

1. POLITICA SECUENCIAL. El 82 % de recall a K=5 responde a una pregunta
   artificial ("con exactamente 5 avisos, decide"). En despliegue el sistema
   reevalua con CADA aviso que llega: se bloquea en cuanto el score cruza el
   umbral, sea al segundo aviso o al decimoquinto. La metrica pasa a ser el
   recall acumulado de la politica y el reparto de "en que aviso se bloqueo".

2. REPUTACION CAUSAL DE SUBRED. Las botnets se agrupan en rangos: si una /24 ya
   aporto origenes que llegaron a merecer bloqueo, una IP nueva del mismo rango
   es sospechosa desde su PRIMER aviso. Se computa de forma estrictamente
   causal: al llegar la IP X en el instante t, solo cuentan las IPs de su
   subred llegadas antes de t y que YA habian cumplido los criterios antes de
   t. Tambien se anade contexto de flota (densidad de origenes nuevos en la
   ultima hora).

3. DIAGNOSTICO DE UMBRAL. Validacion y test difieren en prevalencia (58 % frente
   a 85 % de bloqueables), asi que el umbral p99 fijado en validacion resulta
   conservador en test. Se reporta tambien el techo con umbral-oraculo sobre
   test para separar "perdida por transferencia de umbral" de "limite del
   modelo".

Fichero nuevo; no modifica ningun script existente.

Uso:
    python experiment_early_blocking_v2.py
"""

from __future__ import annotations

import argparse
from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score

from experiment_early_blocking import (
    FEATURES as V1_FEATURES,
    early_features,
    full_label,
    load_ip_histories,
    threshold_for_precision,
)
from train_utils import artifacts_root, now_run_id, run_header, save_json, set_seed

MIN_USERS, MIN_AGENTS, MIN_ALERTS, MIN_WINDOWS = 5, 2, 50, 3

SUBNET_FEATURES = [
    "sub24_seen", "sub24_hostile", "sub24_hostile_ratio",
    "sub16_seen", "sub16_hostile", "sub16_hostile_ratio",
    "fleet_new_ips_last_hour",
]
EXTRA_BUDGET_FEATURES = ["std_interarrival", "cv_interarrival"]
V2_FEATURES = V1_FEATURES + EXTRA_BUDGET_FEATURES + SUBNET_FEATURES


def qualify_time(events: List[tuple]) -> float:
    """Instante en que la IP cumple por primera vez los criterios de bloqueo."""
    users: set = set()
    agents: set = set()
    windows: set = set()
    for index, event in enumerate(events, start=1):
        if event[2]:
            users.add(event[2])
        agents.add(event[1])
        windows.add(event[4])
        if len(users) >= MIN_USERS or len(agents) >= MIN_AGENTS:
            return event[0]
        if index >= MIN_ALERTS and len(windows) >= MIN_WINDOWS:
            return event[0]
    return float("inf")


def subnet(ip: str, octets: int) -> str:
    parts = ip.split(".")
    return ".".join(parts[:octets]) if len(parts) == 4 else ip


def arrival_context(histories: Dict[str, List[tuple]], ips: List[str]) -> Dict[str, Dict[str, float]]:
    """Reputacion de subred y contexto de flota EN el instante de llegada de
    cada IP. Estrictamente causal: solo el pasado de otras IPs."""
    qualify = {ip: qualify_time(histories[ip]) for ip in ips}
    arrivals = [(histories[ip][0][0], ip) for ip in ips]      # ya ordenadas
    sub24: Dict[str, List[float]] = {}
    sub16: Dict[str, List[float]] = {}
    recent: List[float] = []
    out: Dict[str, Dict[str, float]] = {}

    for t, ip in arrivals:
        s24, s16 = subnet(ip, 3), subnet(ip, 2)
        prev24 = sub24.get(s24, [])
        prev16 = sub16.get(s16, [])
        recent = [x for x in recent if t - x <= 3600.0]
        h24 = sum(1 for q in prev24 if q <= t)
        h16 = sum(1 for q in prev16 if q <= t)
        out[ip] = {
            "sub24_seen": float(len(prev24)),
            "sub24_hostile": float(h24),
            "sub24_hostile_ratio": h24 / len(prev24) if prev24 else 0.0,
            "sub16_seen": float(len(prev16)),
            "sub16_hostile": float(h16),
            "sub16_hostile_ratio": h16 / len(prev16) if prev16 else 0.0,
            "fleet_new_ips_last_hour": float(len(recent)),
        }
        sub24.setdefault(s24, []).append(qualify[ip])
        sub16.setdefault(s16, []).append(qualify[ip])
        recent.append(t)
    return out


def features_v2(events: List[tuple], budget: int, context: Dict[str, float]) -> Dict[str, float]:
    row = early_features(events, budget)
    seen = events[:budget]
    gaps = np.diff([e[0] for e in seen]) if len(seen) > 1 else np.array([0.0])
    row["std_interarrival"] = float(gaps.std())
    row["cv_interarrival"] = float(gaps.std() / (gaps.mean() + 1e-9))
    row.update(context)
    return row


def oracle_recall(y: np.ndarray, scores: np.ndarray, target: float) -> float:
    precision, recall, _ = precision_recall_curve(y, scores)
    ok = precision[:-1] >= target
    return float(recall[:-1][ok].max()) if ok.any() else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Bloqueo temprano v2: secuencial + subred")
    parser.add_argument("--budgets", type=int, nargs="+", default=[1, 2, 3, 5, 10, 20])
    parser.add_argument("--target_precision", type=float, default=0.99)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    set_seed(args.seed)

    root = artifacts_root("exp_early_blocking_v2", "date", "ARGOS-LAB", now_run_id())
    run_header("experiment_early_blocking_v2 (ARGOS-LAB)",
               mejoras="secuencial + reputacion de subred + diagnostico de umbral",
               presupuestos=args.budgets, out=root)

    print("  cargando historiales y contexto causal ...", flush=True)
    histories = load_ip_histories()
    ips = sorted(histories, key=lambda ip: histories[ip][0][0])
    labels = {ip: full_label(histories[ip]) for ip in ips}
    context = arrival_context(histories, ips)

    cut_tr, cut_va = int(len(ips) * 0.70), int(len(ips) * 0.85)
    split = {ip: ("train" if i < cut_tr else "val" if i < cut_va else "test")
             for i, ip in enumerate(ips)}
    test_ips = [ip for ip in ips if split[ip] == "test"]
    y_test = np.array([labels[ip] for ip in test_ips])
    total_future = {k: int(sum(max(0, len(histories[ip]) - k) for ip in test_ips if labels[ip]))
                    for k in args.budgets}

    results: Dict[str, Any] = {"features_v2": V2_FEATURES, "presupuestos": {}}
    models: Dict[int, Any] = {}
    thresholds: Dict[int, float] = {}
    scores_test: Dict[int, np.ndarray] = {}

    print(f"\n  == por presupuesto: v1 frente a v2 (recall a precision >= "
          f"{args.target_precision:.0%} fijada en validacion) ==")
    print(f"  {'K':>4}{'AUC v1':>9}{'AUC v2':>9}{'recall v1':>11}{'recall v2':>11}"
          f"{'oraculo v2':>12}")
    for budget in args.budgets:
        frames = {name: [] for name in ("train", "val", "test")}
        for ip in ips:
            row = features_v2(histories[ip], budget, context[ip])
            row["y"] = labels[ip]
            frames[split[ip]].append(row)
        tr = pd.DataFrame(frames["train"]); va = pd.DataFrame(frames["val"]); te = pd.DataFrame(frames["test"])

        outcome: Dict[str, Any] = {}
        recalls: Dict[str, float] = {}
        aucs: Dict[str, float] = {}
        for tag, feats in (("v1", V1_FEATURES), ("v2", V2_FEATURES)):
            model = HistGradientBoostingClassifier(
                max_iter=250, learning_rate=0.08, max_depth=5, l2_regularization=1.0,
                early_stopping=True, validation_fraction=0.15, n_iter_no_change=15,
                class_weight="balanced", random_state=args.seed,
            ).fit(tr[feats], tr["y"])
            s_va = model.predict_proba(va[feats])[:, 1]
            s_te = model.predict_proba(te[feats])[:, 1]
            threshold = threshold_for_precision(va["y"].to_numpy(), s_va, args.target_precision)
            blocked = s_te >= threshold
            tp = int(np.sum(blocked & (y_test == 1)))
            fp = int(np.sum(blocked & (y_test == 0)))
            outcome[tag] = {
                "roc_auc": float(roc_auc_score(y_test, s_te)),
                "pr_auc": float(average_precision_score(y_test, s_te)),
                "recall_p99": tp / max(int(y_test.sum()), 1),
                "fp": fp,
                "umbral": threshold,
            }
            recalls[tag] = outcome[tag]["recall_p99"]
            aucs[tag] = outcome[tag]["roc_auc"]
            if tag == "v2":
                models[budget] = (model, V2_FEATURES)
                thresholds[budget] = threshold
                scores_test[budget] = s_te
                outcome["v2"]["recall_oraculo_test"] = oracle_recall(
                    y_test, s_te, args.target_precision)
        results["presupuestos"][str(budget)] = outcome
        print(f"  {budget:>4}{aucs['v1']:>9.4f}{aucs['v2']:>9.4f}"
              f"{recalls['v1']:>11.3f}{recalls['v2']:>11.3f}"
              f"{outcome['v2']['recall_oraculo_test']:>12.3f}")

    # ------------------- politica secuencial ---------------------------------
    print("\n  == politica secuencial: bloquear al primer cruce de umbral ==")
    blocked_at = np.full(len(test_ips), -1, dtype=int)
    for budget in sorted(args.budgets):
        s = scores_test[budget]
        newly = (s >= thresholds[budget]) & (blocked_at < 0)
        blocked_at[newly] = budget
    blocked_mask = blocked_at > 0
    tp_mask = blocked_mask & (y_test == 1)
    fp_mask = blocked_mask & (y_test == 0)
    prevented = int(sum(max(0, len(histories[ip]) - k)
                        for ip, k, good in zip(test_ips, blocked_at, tp_mask) if good))
    future_all = int(sum(max(0, len(histories[ip]) - 1) for ip in test_ips if labels[ip]))
    ks = blocked_at[tp_mask]
    seq = {
        "recall": float(tp_mask.sum() / max(int(y_test.sum()), 1)),
        "precision": float(tp_mask.sum() / max(int(blocked_mask.sum()), 1)),
        "ips_legitimas_cortadas": int(fp_mask.sum()),
        "aviso_mediano_de_bloqueo": float(np.median(ks)) if len(ks) else None,
        "avisos_evitados": prevented,
        "avisos_futuros_totales_desde_1": future_all,
        "avisos_evitados_pct": prevented / max(future_all, 1),
        "reparto_bloqueos_por_K": {str(k): int((ks == k).sum()) for k in sorted(set(ks.tolist()))},
    }
    results["politica_secuencial"] = seq
    print(f"    recall acumulado      : {seq['recall']:.3f}   (v1 a K=5 fijo: 0,820)")
    print(f"    precision             : {seq['precision']:.3f}")
    print(f"    legitimas cortadas    : {seq['ips_legitimas_cortadas']}")
    print(f"    aviso mediano de corte: {seq['aviso_mediano_de_bloqueo']}")
    print(f"    avisos evitados       : {seq['avisos_evitados']:,} "
          f"({seq['avisos_evitados_pct']:.0%} de todo lo posterior al primer aviso)")
    print(f"    reparto por K         : {seq['reparto_bloqueos_por_K']}")

    save_json(root / "results.json", {"args": vars(args), **results})
    print(f"\nGuardado: {root}")


if __name__ == "__main__":
    main()
