#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Experimento: la etiqueta de bloqueo por conducta, transfiere entre hosts?

Contexto. Con la etiqueta debil del motor de reglas, el traslado entre maquinas
colapsa (MCC 0,000 en el servidor web). La etiqueta de bloqueo se definio sobre
la conducta del ORIGEN -- cuentas probadas, amplitud, persistencia -- que es una
propiedad del atacante y no del host, asi que la hipotesis es que un modelo
entrenado en una maquina deberia trasladarse mejor a otra.

Diseno. Solo hay dos agentes con origen de red (000 y 011). Para cada direccion:

    entrenar con el split train del host ORIGEN
    evaluar sobre el split test del host DESTINO       (transferido)
    comparar con: entrenar y evaluar en el DESTINO     (nativo, la referencia)

Se prueba con el regimen `behavioral` (54 variables, incluye magnitudes
absolutas que codifican la huella del host) y con `shape` (29 adimensionales).
La prediccion: `shape` deberia perder menos al cruzar.

Este fichero es un experimento nuevo y no modifica ningun script existente.

Uso:
    python experiment_block_transfer.py
"""

from __future__ import annotations

import argparse
from types import SimpleNamespace
from typing import Any, Dict

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, matthews_corrcoef, roc_auc_score

from feature_spec import resolve_feature_set
from train_block_scorer import fit_model, load_joined, score_binary
from train_utils import artifacts_root, now_run_id, run_header, save_json, set_seed


def evaluate_direction(model, classes, test: pd.DataFrame, feature_names) -> Dict[str, float]:
    y = (test["block_target"] == "BLOCK").astype(int).to_numpy()
    if len(np.unique(y)) < 2:
        return {"error": "una sola clase en destino"}
    s = score_binary(model, test[feature_names].to_numpy(np.float32), classes)
    pred = (s >= 0.5).astype(int)
    allow = 1 - y
    ap = float(average_precision_score(allow, -s))
    base = float(allow.mean())
    return {
        "n_test": int(len(test)),
        "roc_auc": float(roc_auc_score(y, s)),
        "mcc": float(matthews_corrcoef(y, pred)),
        "pr_auc_allow": ap,
        "baseline_allow": base,
        "lift_allow": ap / base if base > 0 else float("nan"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Transferencia entre hosts de la etiqueta de bloqueo")
    parser.add_argument("--split_mode", default="date", choices=["date"])
    parser.add_argument("--dataset", default="ARGOS-LAB")
    parser.add_argument("--seed", type=int, default=42)
    args_cli = parser.parse_args()
    set_seed(args_cli.seed)

    root = artifacts_root("exp_block_transfer", args_cli.split_mode, args_cli.dataset, now_run_id())
    run_header("experiment_block_transfer (ARGOS-LAB)", dataset=args_cli.dataset,
               split_mode=args_cli.split_mode, out=root)

    results: Dict[str, Any] = {}
    for regime in ("behavioral", "shape"):
        feature_names = resolve_feature_set(regime)
        loader_args = SimpleNamespace(split_mode=args_cli.split_mode, dataset=args_cli.dataset,
                                      feature_set=regime)
        train = load_joined("train", loader_args, feature_names)
        test = load_joined("test", loader_args, feature_names)

        # Solo los hosts con origen de red y ambas clases.
        hosts = [h for h in sorted(train["agent_id"].unique())
                 if train[train.agent_id == h]["block_target"].nunique() > 1
                 and len(test[test.agent_id == h]) >= 100]
        print(f"\n### regimen {regime} ({len(feature_names)} variables) — hosts utilizables: {hosts}")
        print(f"  {'origen->destino':>18}{'n_test':>8}{'ROC-AUC':>10}{'MCC':>9}{'lift(ALLOW)':>13}")

        regime_out: Dict[str, Any] = {}
        native: Dict[str, Dict[str, float]] = {}
        for host in hosts:
            tr_h = train[train.agent_id == host]
            te_h = test[test.agent_id == host]
            model = fit_model(tr_h[feature_names].to_numpy(np.float32),
                              tr_h["block_target"].to_numpy(), args_cli.seed)
            native[host] = evaluate_direction(model, model.classes_, te_h, feature_names)
            m = native[host]
            print(f"  {host + ' -> ' + host + ' (nativo)':>18}{m['n_test']:>8}{m['roc_auc']:>10.4f}"
                  f"{m['mcc']:>9.4f}{m['lift_allow']:>12.2f}x")
            regime_out[f"{host}->{host}"] = m

        for src in hosts:
            tr_s = train[train.agent_id == src]
            model = fit_model(tr_s[feature_names].to_numpy(np.float32),
                              tr_s["block_target"].to_numpy(), args_cli.seed)
            for dst in hosts:
                if dst == src:
                    continue
                te_d = test[test.agent_id == dst]
                m = evaluate_direction(model, model.classes_, te_d, feature_names)
                regime_out[f"{src}->{dst}"] = m
                if "error" in m:
                    print(f"  {src + ' -> ' + dst:>18}  {m['error']}")
                    continue
                retained = m["mcc"] / native[dst]["mcc"] if native[dst]["mcc"] else float("nan")
                m["mcc_retenido_vs_nativo"] = retained
                print(f"  {src + ' -> ' + dst:>18}{m['n_test']:>8}{m['roc_auc']:>10.4f}"
                      f"{m['mcc']:>9.4f}{m['lift_allow']:>12.2f}x   "
                      f"(retiene {retained:.0%} del MCC nativo)")
        results[regime] = regime_out

    # --- referencia historica: la etiqueta debil en el mismo cruce ----------
    results["referencia_etiqueta_debil"] = {
        "nota": ("Con la etiqueta del motor de reglas, leave-one-agent-out dio MCC 0,000 "
                 "en el agente 011 (servidor web). Esa es la cifra contra la que se "
                 "compara esta transferencia."),
        "mcc_etiqueta_debil_agente_011": 0.0000,
    }
    save_json(root / "results.json", {"args": vars(args_cli), **results})
    print(f"\nGuardado: {root}")


if __name__ == "__main__":
    main()
