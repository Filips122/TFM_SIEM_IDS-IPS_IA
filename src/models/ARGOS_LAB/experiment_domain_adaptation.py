#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adaptacion de dominio sin etiquetas: mejora la transferencia entre hosts?

Problema. Cada maquina tiene una huella de escala propia (con 54 variables
conductuales se identifica al agente con 99,75 % de exactitud). Un modelo
entrenado en el host A ve, al aplicarse al host B, una distribucion desplazada.

Metodo. Antes de puntuar, cada host reexpresa sus variables en SU propia moneda,
usando solo estadisticas de sus ventanas de entrenamiento -- sin ninguna
etiqueta del host destino:

  raw    sin adaptacion (linea base = experiment_block_transfer)
  zhost  z-score por host: (x - media_host) / desviacion_host
  rank   transformacion de rango por host: ECDF de cada variable estimada en
         las ventanas del propio host; robusta a colas pesadas

Ambas son adaptacion de dominio no supervisada de localizacion-escala. Si la
huella del host es principalmente un desplazamiento de escala, deberian
recuperar parte del hueco entre transferido y nativo.

Ambito. Solo el cruce interno 000 <-> 011. LAB-ALERTS no se toca: su papel de
validacion externa de un solo disparo se conserva, y evaluar variantes contra
el lo degradaria a conjunto de desarrollo.

Fichero nuevo; no modifica ningun script existente.

Uso:
    python experiment_domain_adaptation.py
"""

from __future__ import annotations

import argparse
from types import SimpleNamespace
from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.metrics import matthews_corrcoef, roc_auc_score

from feature_spec import resolve_feature_set
from train_block_scorer import fit_model, load_joined, score_binary
from train_utils import artifacts_root, now_run_id, run_header, save_json, set_seed


class HostTransform:
    """Estadisticas por host, estimadas SOLO en sus ventanas de entrenamiento."""

    def __init__(self, kind: str):
        self.kind = kind
        self.stats: Dict[str, Any] = {}

    def fit(self, df: pd.DataFrame, features: List[str]) -> "HostTransform":
        for host, part in df.groupby("agent_id"):
            X = part[features].to_numpy(np.float64)
            if self.kind == "zhost":
                mean = X.mean(axis=0)
                std = X.std(axis=0)
                std[std < 1e-9] = 1.0
                self.stats[str(host)] = (mean, std)
            elif self.kind == "rank":
                self.stats[str(host)] = [np.sort(X[:, j]) for j in range(X.shape[1])]
        return self

    def transform(self, df: pd.DataFrame, features: List[str]) -> np.ndarray:
        out = np.empty((len(df), len(features)), dtype=np.float32)
        hosts = df["agent_id"].astype(str).to_numpy()
        X = df[features].to_numpy(np.float64)
        for host in np.unique(hosts):
            mask = hosts == host
            stats = self.stats.get(host)
            if stats is None:                       # host sin estadisticas: identidad
                out[mask] = X[mask].astype(np.float32)
                continue
            if self.kind == "zhost":
                mean, std = stats
                out[mask] = np.clip((X[mask] - mean) / std, -8, 8).astype(np.float32)
            else:                                   # rank -> ECDF en [0, 1]
                block = X[mask]
                for j, sorted_col in enumerate(stats):
                    out[mask, j] = (np.searchsorted(sorted_col, block[:, j], side="right")
                                    / max(len(sorted_col), 1))
    	# nota: los hosts destino usan SUS estadisticas; ninguna etiqueta interviene
        return out


def run_pair(train: pd.DataFrame, test: pd.DataFrame, features: List[str],
             src: str, dst: str, kind: str, seed: int) -> Dict[str, float]:
    tr_s = train[train.agent_id == src]
    te_d = test[test.agent_id == dst]
    y = (te_d["block_target"] == "BLOCK").astype(int).to_numpy()
    if te_d.empty or len(np.unique(y)) < 2:
        return {"error": "no evaluable"}

    if kind == "raw":
        X_tr = tr_s[features].to_numpy(np.float32)
        X_te = te_d[features].to_numpy(np.float32)
    else:
        transform = HostTransform(kind).fit(train, features)   # estadisticas por host, split train
        X_tr = transform.transform(tr_s, features)
        X_te = transform.transform(te_d, features)

    model = fit_model(X_tr, tr_s["block_target"].to_numpy(), seed)
    scores = model.predict_proba(X_te)[:, list(map(str, model.classes_)).index("BLOCK")]
    return {
        "roc_auc": float(roc_auc_score(y, scores)),
        "mcc": float(matthews_corrcoef(y, (scores >= 0.5).astype(int))),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Adaptacion de dominio para la transferencia entre hosts")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    set_seed(args.seed)

    root = artifacts_root("exp_domain_adaptation", "date", "ARGOS-LAB", now_run_id())
    run_header("experiment_domain_adaptation (ARGOS-LAB)",
               metodos="raw | zhost | rank", ambito="cruce interno 000 <-> 011",
               nota="LAB-ALERTS intacto para preservar su papel externo", out=root)

    results: Dict[str, Any] = {}
    for regime in ("behavioral", "shape"):
        features = resolve_feature_set(regime)
        loader = SimpleNamespace(split_mode="date", dataset="ARGOS-LAB", feature_set=regime)
        train = load_joined("train", loader, features)
        test = load_joined("test", loader, features)

        print(f"\n### regimen {regime} ({len(features)} variables)")
        print(f"  {'direccion':>12}{'metodo':>8}{'ROC-AUC':>10}{'MCC':>9}{'delta MCC vs raw':>18}")
        regime_out: Dict[str, Any] = {}
        for src, dst in (("000", "011"), ("011", "000")):
            base = None
            for kind in ("raw", "zhost", "rank"):
                m = run_pair(train, test, features, src, dst, kind, args.seed)
                regime_out[f"{src}->{dst}:{kind}"] = m
                if "error" in m:
                    print(f"  {src + '->' + dst:>12}{kind:>8}   {m['error']}")
                    continue
                if kind == "raw":
                    base = m["mcc"]
                delta = "" if kind == "raw" or base is None else f"{m['mcc'] - base:+18.4f}"
                print(f"  {src + '->' + dst:>12}{kind:>8}{m['roc_auc']:>10.4f}{m['mcc']:>9.4f}{delta}")
        results[regime] = regime_out

    save_json(root / "results.json", {"args": vars(args), **results})
    print(f"\nGuardado: {root}")


if __name__ == "__main__":
    main()
