#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Construye el paquete de despliegue `deploy/argos_scorer/`.

Entrena y serializa exactamente la configuracion validada en RESULTADOS.md:

  1. Bloqueo temprano (R7-R9): un HGB por presupuesto K, entrenado en el split
     train de IPs y con umbral p99 fijado en validacion -- la configuracion
     cuyas metricas se reportaron (recall 0,990 / precision 0,995).
  2. Puntuador de bloqueo por ventana (R5): HGB behavioral calibrado.
  3. Puntuador de actividad por host (R7 del scorer): calibrado + rechazo,
     guardado como diccionario plano (sin clases propias) para que el paquete
     de despliegue lo cargue sin depender de este repositorio.
  4. Estado inicial en caliente: reputacion de subred, frecuencias de IP y
     lineas base por agente calculadas sobre la captura completa de
     entrenamiento.

Uso:
    python build_deploy_bundle.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier

from experiment_early_blocking import full_label, load_ip_histories, threshold_for_precision
from experiment_early_blocking_v2 import V2_FEATURES, arrival_context, features_v2
from feature_spec import BEHAVIORAL_FEATURES, HOSTILE_FAMILIES
from train_activity_scorer import MIN_CLASS_SUPPORT, MIN_TRAIN_PER_HOST
from train_block_scorer import fit_model, load_joined
from train_utils import repo_root, set_seed

DEPLOY = Path("deploy/argos_scorer")
BUDGETS = [1, 2, 3, 5, 10, 20]
TARGET_PRECISION = 0.99
SEED = 42


def main() -> None:
    set_seed(SEED)
    root = repo_root()
    models_dir = root / DEPLOY / "models"
    state_dir = root / DEPLOY / "state"
    models_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    config: dict = {"seed": SEED, "fuente": "ARGOS-LAB 30 dias", "version": "1.0"}

    # ======================================================================
    # 1) Bloqueo temprano
    # ======================================================================
    print("== 1/4 bloqueo temprano ==", flush=True)
    histories = load_ip_histories()
    ips = sorted(histories, key=lambda ip: histories[ip][0][0])
    labels = {ip: full_label(histories[ip]) for ip in ips}
    context = arrival_context(histories, ips)
    cut_tr, cut_va = int(len(ips) * 0.70), int(len(ips) * 0.85)
    split = {ip: ("train" if i < cut_tr else "val" if i < cut_va else "test")
             for i, ip in enumerate(ips)}

    thresholds = {}
    for budget in BUDGETS:
        frames = {"train": [], "val": []}
        for ip in ips:
            part = split[ip]
            if part == "test":
                continue
            row = features_v2(histories[ip], budget, context[ip])
            row["y"] = labels[ip]
            frames[part].append(row)
        tr = pd.DataFrame(frames["train"]); va = pd.DataFrame(frames["val"])
        model = HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.08, max_depth=5, l2_regularization=1.0,
            early_stopping=True, validation_fraction=0.15, n_iter_no_change=15,
            class_weight="balanced", random_state=SEED,
        ).fit(tr[V2_FEATURES], tr["y"])
        threshold = threshold_for_precision(
            va["y"].to_numpy(), model.predict_proba(va[V2_FEATURES])[:, 1], TARGET_PRECISION)
        joblib.dump(model, models_dir / f"early_block_K{budget}.joblib")
        thresholds[str(budget)] = float(threshold)
        print(f"   K={budget:<3} umbral={threshold:.4f}")
    config["early_block"] = {
        "budgets": BUDGETS, "thresholds": thresholds, "features": V2_FEATURES,
        "target_precision": TARGET_PRECISION,
        "validado": "recall 0,990 / precision 0,995 interno; 0,994 externo (R7-R8)",
    }

    # ======================================================================
    # 2) Puntuador de bloqueo por ventana
    # ======================================================================
    print("== 2/4 bloqueo por ventana ==", flush=True)
    loader = SimpleNamespace(split_mode="date", dataset="ARGOS-LAB", feature_set="behavioral")
    wtrain = load_joined("train", loader, BEHAVIORAL_FEATURES)
    wmodel = fit_model(wtrain[BEHAVIORAL_FEATURES].to_numpy(np.float32),
                       wtrain["block_target"].to_numpy(), SEED)
    joblib.dump(wmodel, models_dir / "window_block.joblib")
    config["window_block"] = {
        "features": BEHAVIORAL_FEATURES,
        "classes": list(map(str, wmodel.classes_)),
        "validado": "lift 43,5x/20,0x por host; transferencia 65-104% (R5)",
    }

    # ======================================================================
    # 3) Puntuador de actividad por host (diccionario plano, sin clases propias)
    # ======================================================================
    print("== 3/4 actividad por host ==", flush=True)
    from data_loader import load_split

    def frame(split_name):
        part = load_split(split_mode="date", dataset="ARGOS-LAB", pipeline="multiclass",
                          split=split_name, feature_set="behavioral")
        df = part.meta.copy()
        for index, name in enumerate(part.feature_names):
            df[name] = part.X[:, index]
        df["target"] = part.y.astype(str)
        return df

    atrain, aval = frame("train"), frame("val")

    def fit_calibrated(part):
        counts = part["target"].value_counts()
        keep = counts[counts >= MIN_CLASS_SUPPORT].index
        usable = part[part["target"].isin(keep)]
        if len(usable) < MIN_TRAIN_PER_HOST or len(keep) < 2:
            return None
        base = HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.08, max_depth=6, l2_regularization=1.0,
            early_stopping=True, validation_fraction=0.15, n_iter_no_change=15,
            class_weight="balanced", random_state=SEED)
        cv = int(min(3, usable["target"].value_counts().min()))
        model = (CalibratedClassifierCV(base, method="isotonic", cv=cv) if cv >= 2 else base)
        model.fit(usable[BEHAVIORAL_FEATURES], usable["target"])
        return model

    bundle = {"hosts": {}, "global": None}
    gmodel = fit_calibrated(atrain)
    proba = gmodel.predict_proba(aval[BEHAVIORAL_FEATURES])
    bundle["global"] = {"model": gmodel, "classes": list(map(str, gmodel.classes_)),
                        "reject": float(np.quantile(proba.max(axis=1), 0.25))}
    for host, part in atrain.groupby("agent_id"):
        model = fit_calibrated(part)
        if model is None:
            continue
        va_h = aval[aval.agent_id == host]
        reject = (float(np.quantile(model.predict_proba(va_h[BEHAVIORAL_FEATURES]).max(axis=1), 0.25))
                  if len(va_h) else bundle["global"]["reject"])
        bundle["hosts"][str(host)] = {"model": model,
                                      "classes": list(map(str, model.classes_)),
                                      "reject": reject}
        print(f"   host {host}: {len(model.classes_ if hasattr(model,'classes_') else [])} clases, umbral rechazo {reject:.3f}")
    joblib.dump(bundle, models_dir / "activity_scorer.joblib")
    config["activity"] = {
        "features": BEHAVIORAL_FEATURES,
        "hostile_families": sorted(HOSTILE_FAMILIES),
        "reject_quantile": 0.25,
        "validado": "attack_score por agente: lift 46x en el host raro (seccion 2.7 del README del modulo)",
    }

    # ======================================================================
    # 4) Estado inicial (arranque en caliente)
    # ======================================================================
    print("== 4/4 estado inicial ==", flush=True)
    sys.path.insert(0, str(root / DEPLOY))
    from argos_scorer.features import LiveState, subnet

    state = LiveState()
    qualify = {ip: labels[ip] for ip in ips}
    for ip in ips:                                       # reputacion final de la captura
        for octets, table in ((3, state.sub24), (2, state.sub16)):
            key = subnet(ip, octets)
            entry = table.setdefault(key, [0, 0])
            entry[0] += 1
            entry[1] += qualify[ip]
        state.ip_freq[ip] = len(histories[ip])
        for event in histories[ip]:
            if event[2]:
                state.seen_users[event[2]] = state.seen_users.get(event[2], 0) + 1
    (state_dir / "live_state.json").write_text(state.to_json(), encoding="utf-8")
    print(f"   subredes /24: {len(state.sub24):,}  ips: {len(state.ip_freq):,}")

    (models_dir / "config.json").write_text(
        json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    total_mb = sum(f.stat().st_size for f in models_dir.glob("*")) / 1e6
    print(f"\nPaquete en {root / DEPLOY}  (modelos: {total_mb:.1f} MB)")


if __name__ == "__main__":
    main()
