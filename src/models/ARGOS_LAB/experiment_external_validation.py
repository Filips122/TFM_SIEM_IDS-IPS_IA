#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validacion externa: puntuador de bloqueo entrenado en ARGOS-LAB, evaluado en
los hosts de LAB-ALERTS -- un entorno que jamas ha visto.

Protocolo de un solo disparo
----------------------------
La canalizacion se congelo antes de tocar LAB-ALERTS: variables, criterios de
bloqueo e hiperparametros son exactamente los ajustados sobre ARGOS-LAB. Este
script se ejecuta una vez y su resultado se reporta sea cual sea. Iterar contra
el conjunto externo lo convertiria en un conjunto de validacion encubierto.

Que se cruza
------------
  entrenamiento : ARGOS-LAB, split train (31 dias, hosts 000 y 011)
  evaluacion    : LAB-ALERTS completo (11 horas, 9 agentes), convertido por
                  prepare_lab_alerts_crosstest.py, con la MISMA politica de
                  etiqueta de bloqueo por conducta aplicada a ambos entornos

Variables: regimen `shape` sin las geograficas. LAB-ALERTS carece de
enriquecimiento geo (0 % de cobertura frente al 67,6 % de ARGOS), de modo que
esas seis variables serian una constante distinta en cada entorno -- un
desplazamiento de distribucion que no procede de la conducta.

Referencias reportadas junto al cruce:
  - nativo ARGOS  : lo que el mismo modelo logra en sus propios hosts
  - techo LAB     : un modelo entrenado en el propio LAB-ALERTS (70 % inicial
                    de cada host), como cota de lo alcanzable con esos datos

Fichero nuevo; no modifica ningun script existente.

Uso:
    python experiment_external_validation.py
"""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, matthews_corrcoef, roc_auc_score

from feature_spec import FEATURE_SETS
from train_block_scorer import fit_model, load_joined, score_binary
from train_utils import artifacts_root, now_run_id, repo_root, run_header, save_json, set_seed

CROSSTEST = Path("src/models/ARGOS_LAB/datasets/crosstest")

GEO_FEATURES = {"country_entropy_norm", "top_country_share", "geo_missing_ratio",
                "geo_spread", "geo_lat_std", "geo_lon_std"}
SHAPE_NOGEO: List[str] = [f for f in FEATURE_SETS["shape"] if f not in GEO_FEATURES]

MIN_EVAL = 60          # ventanas minimas para evaluar un host externo
MIN_MINORITY = 10      # muestras minimas de la clase minoritaria


def load_lab_windows(feature_names: List[str]) -> pd.DataFrame:
    """Todo LAB-ALERTS-X (train+val+test internos: aqui es solo evaluacion),
    unido a sus etiquetas de bloqueo."""
    base = repo_root() / CROSSTEST / "date" / "LAB-ALERTS-X" / "multiclass"
    parts = []
    for split in ("train", "val", "test"):
        for path in sorted((base / split).glob("*.parquet")):
            parts.append(pd.read_parquet(path))
    df = pd.concat(parts, ignore_index=True)

    labels = pd.read_parquet(repo_root() / CROSSTEST / "block_labels" / "block_labels.parquet")
    df["window_start"] = pd.to_datetime(df["window_start"], utc=True)
    labels["window_start"] = pd.to_datetime(labels["window_start"], utc=True)
    df["agent_id"] = df["agent_id"].astype(str)
    labels["agent_id"] = labels["agent_id"].astype(str)
    merged = df.merge(labels[["window_start", "agent_id", "block_target", "reason"]],
                      on=["window_start", "agent_id"], how="inner")
    missing = [f for f in feature_names if f not in merged.columns]
    if missing:
        raise SystemExit(f"Faltan variables en LAB-ALERTS-X: {missing}")
    return merged


def evaluate(y: np.ndarray, s: np.ndarray) -> Dict[str, float]:
    pred = (s >= 0.5).astype(int)
    out = {
        "roc_auc": float(roc_auc_score(y, s)),
        "mcc": float(matthews_corrcoef(y, pred)),
    }
    # PR-AUC de la clase minoritaria del host, con la direccion adecuada.
    minority = int(y.sum() <= (len(y) - y.sum()))    # 1 si BLOCK es minoritaria
    y_min = (y == minority).astype(int)
    s_min = s if minority == 1 else -s
    ap = float(average_precision_score(y_min, s_min))
    base = float(y_min.mean())
    out["minority"] = "BLOCK" if minority == 1 else "ALLOW"
    out["pr_auc_minority"] = ap
    out["baseline_minority"] = base
    out["lift_minority"] = ap / base if base > 0 else float("nan")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Validacion externa del puntuador de bloqueo")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    set_seed(args.seed)

    root = artifacts_root("exp_external_validation", "date", "ARGOS_a_LAB-ALERTS", now_run_id())
    run_header("experiment_external_validation", entrenamiento="ARGOS-LAB (train)",
               evaluacion="LAB-ALERTS completo", variables=f"shape sin geo ({len(SHAPE_NOGEO)})",
               protocolo="un solo disparo", out=root)

    loader = SimpleNamespace(split_mode="date", dataset="ARGOS-LAB", feature_set="shape")
    argos_train = load_joined("train", loader, SHAPE_NOGEO)
    argos_test = load_joined("test", loader, SHAPE_NOGEO)
    lab = load_lab_windows(SHAPE_NOGEO)
    print(f"  ARGOS train={len(argos_train):,}   LAB eval={len(lab):,} "
          f"({lab['agent_id'].nunique()} agentes)")

    model = fit_model(argos_train[SHAPE_NOGEO].to_numpy(np.float32),
                      argos_train["block_target"].to_numpy(), args.seed)

    results: Dict[str, Any] = {"variables": SHAPE_NOGEO}

    # --- referencia interna: mismos hosts de ARGOS --------------------------
    print("\n  -- referencia: hosts propios de ARGOS " + "-" * 24)
    ref: Dict[str, Any] = {}
    for host, part in argos_test.groupby("agent_id"):
        y = (part["block_target"] == "BLOCK").astype(int).to_numpy()
        if len(part) < MIN_EVAL or min(y.sum(), len(y) - y.sum()) < MIN_MINORITY:
            continue
        m = evaluate(y, score_binary(model, part[SHAPE_NOGEO].to_numpy(np.float32), model.classes_))
        ref[str(host)] = m
        print(f"    {host:<6} n={len(part):<6} ROC-AUC={m['roc_auc']:.4f}  MCC={m['mcc']:.4f}  "
              f"lift({m['minority']})={m['lift_minority']:.2f}x")
    results["referencia_argos"] = ref

    # --- el cruce externo ----------------------------------------------------
    print("\n  == VALIDACION EXTERNA: hosts de LAB-ALERTS " + "=" * 20)
    print(f"  {'host':<8}{'nombre':<24}{'n':>6}{'%BLOCK':>8}{'ROC-AUC':>9}{'MCC':>8}{'lift':>9}")
    names = {"000": "wazuh", "003": "clockworksolutions", "011": "clockworksolutions.es",
             "017": "romero-AWS-WebBus", "018": "server1-principal", "022": "biblioteca",
             "023": "MARCOSPC", "025": "Server-Web-Top-Secret", "026": "Server-Correo"}
    external: Dict[str, Any] = {}
    transfer_mccs = []
    for host, part in sorted(lab.groupby("agent_id"), key=lambda kv: -len(kv[1])):
        host = str(host)
        y = (part["block_target"] == "BLOCK").astype(int).to_numpy()
        tag = " (host tambien en ARGOS)" if host in {"000", "003", "011"} else ""
        if len(part) < MIN_EVAL or min(y.sum(), len(y) - y.sum()) < MIN_MINORITY:
            external[host] = {"n": int(len(part)), "skip": "muestras insuficientes"}
            print(f"  {host:<8}{names.get(host, '?'):<24}{len(part):>6}"
                  f"{y.mean():>8.2f}{'-- muestras insuficientes':>26}")
            continue
        s = score_binary(model, part[SHAPE_NOGEO].to_numpy(np.float32), model.classes_)
        m = evaluate(y, s)
        m["n"] = int(len(part))
        m["host_name"] = names.get(host, "")
        m["nuevo"] = host not in {"000", "003", "011"}
        external[host] = m
        if m["nuevo"]:
            transfer_mccs.append(m["mcc"])
        print(f"  {host:<8}{names.get(host, '?'):<24}{len(part):>6}{y.mean():>8.2f}"
              f"{m['roc_auc']:>9.4f}{m['mcc']:>8.4f}{m['lift_minority']:>8.2f}x{tag}")
    results["externa"] = external

    # --- techo: modelo nativo del propio LAB (70% inicial por host) ----------
    print("\n  -- techo de referencia: modelo nativo de LAB (70/30 temporal) " + "-" * 4)
    ceiling: Dict[str, Any] = {}
    for host, part in lab.groupby("agent_id"):
        host = str(host)
        part = part.sort_values("window_start")
        cut = int(len(part) * 0.7)
        tr_h, te_h = part.iloc[:cut], part.iloc[cut:]
        y_tr = (tr_h["block_target"] == "BLOCK").astype(int).to_numpy()
        y_te = (te_h["block_target"] == "BLOCK").astype(int).to_numpy()
        if (len(te_h) < 40 or tr_h["block_target"].nunique() < 2
                or min(y_te.sum(), len(y_te) - y_te.sum()) < MIN_MINORITY):
            continue
        native = fit_model(tr_h[SHAPE_NOGEO].to_numpy(np.float32),
                           tr_h["block_target"].to_numpy(), args.seed)
        m = evaluate(y_te, score_binary(native, te_h[SHAPE_NOGEO].to_numpy(np.float32), native.classes_))
        ceiling[host] = m
        transferred = external.get(host, {}).get("mcc")
        keep = f"   transferido retiene {transferred / m['mcc']:.0%}" if transferred and m["mcc"] > 0 else ""
        print(f"    {host:<6} n_test={len(te_h):<5} ROC-AUC={m['roc_auc']:.4f}  MCC={m['mcc']:.4f}{keep}")
    results["techo_nativo_lab"] = ceiling

    if transfer_mccs:
        results["resumen"] = {
            "hosts_nuevos_evaluados": len(transfer_mccs),
            "mcc_medio_hosts_nuevos": float(np.mean(transfer_mccs)),
            "referencia_etiqueta_debil_cross_host": 0.0,
        }
        print(f"\n  MCC medio en hosts NUNCA VISTOS de OTRO entorno: "
              f"{np.mean(transfer_mccs):.4f}  (etiqueta debil: 0,000)")

    save_json(root / "results.json", {"args": vars(args), **results})
    print(f"\nGuardado: {root}")


if __name__ == "__main__":
    main()
