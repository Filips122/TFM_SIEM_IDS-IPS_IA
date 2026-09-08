#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Entrena y AUDITA el puntuador sobre la etiqueta de bloqueo por conducta.

La etiqueta la produce `build_block_labels.py` a partir de hechos observados del
origen -- cuentas probadas, maquinas alcanzadas, persistencia -- sin que
intervenga ningun campo del motor de reglas de Wazuh.

Eso rompe la circularidad de la etiqueta original, pero **introduce un riesgo
nuevo**: las variables de ventana incluyen cantidades emparentadas con los
criterios de bloqueo (`unique_src_user`, `users_per_src_ip`, `new_src_ip_ratio`).
Si una sola de ellas reconstruye la etiqueta, se habra cambiado una
circularidad por otra.

Por eso este script audita antes de entrenar, con la misma metodologia de sondas
de una variable que se aplico a la etiqueta debil, y desglosa toda metrica por
agente -- la salvaguarda que expuso el fallo del autoencoder.

Uso:
    python train_block_scorer.py
    python train_block_scorer.py --feature_set shape
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, f1_score, matthews_corrcoef, roc_auc_score

from data_loader import EmptySplitError, load_split
from feature_spec import resolve_feature_set
from reporting import per_group_metrics, print_per_group
from train_utils import artifacts_root, now_run_id, run_header, save_json, set_seed

BLOCK_LABELS = Path("src/models/ARGOS_LAB/datasets/block_labels/block_labels.parquet")

# Variables emparentadas con los criterios de bloqueo. No se eliminan: se
# auditan, y se ofrece un regimen sin ellas para comparar.
KIN_FEATURES = [
    "unique_src_user", "users_per_src_ip", "src_user_entropy", "src_user_entropy_norm",
    "top_src_user_share", "new_src_user_ratio", "new_src_user_count",
    "unique_src_ip", "new_src_ip_ratio", "new_src_ip_count",
    "mean_src_ip_seen_before", "max_src_ip_seen_before", "repeat_src_ip_ratio",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_joined(split: str, args, feature_names: List[str]) -> pd.DataFrame:
    """Ventanas + variables + etiqueta de bloqueo, unidas por (instante, agente)."""
    part = load_split(split_mode=args.split_mode, dataset=args.dataset, pipeline="multiclass",
                      split=split, feature_set=args.feature_set)
    df = part.meta.copy()
    for index, name in enumerate(part.feature_names):
        df[name] = part.X[:, index]
    df["activity"] = part.y.astype(str)

    labels = pd.read_parquet(repo_root() / BLOCK_LABELS)
    df["window_start"] = pd.to_datetime(df["window_start"], utc=True)
    labels["window_start"] = pd.to_datetime(labels["window_start"], utc=True)
    df["agent_id"] = df["agent_id"].astype(str)
    labels["agent_id"] = labels["agent_id"].astype(str)

    merged = df.merge(
        labels[["window_start", "agent_id", "block_target", "block_ratio", "reason"]],
        on=["window_start", "agent_id"], how="inner",
    )
    return merged


def fit_model(X: np.ndarray, y: np.ndarray, seed: int, calibrate: bool = True):
    base = HistGradientBoostingClassifier(
        max_iter=250, learning_rate=0.08, max_depth=6, l2_regularization=1.0,
        early_stopping=True, validation_fraction=0.15, n_iter_no_change=15,
        class_weight="balanced", random_state=seed,
    )
    counts = pd.Series(y).value_counts()
    if not calibrate or len(counts) < 2 or counts.min() < 3:
        base.fit(X, y)
        return base
    model = CalibratedClassifierCV(base, method="isotonic", cv=min(3, int(counts.min())))
    model.fit(X, y)
    return model


def score_binary(model, X: np.ndarray, classes) -> np.ndarray:
    proba = model.predict_proba(X)
    idx = list(map(str, classes)).index("BLOCK")
    return proba[:, idx]


def audit(train: pd.DataFrame, test: pd.DataFrame, feature_names: List[str], seed: int) -> Dict[str, Any]:
    """Sondas de una variable sobre la etiqueta nueva."""
    ytr = train["block_target"].to_numpy()
    yte = (test["block_target"] == "BLOCK").astype(int).to_numpy()
    out: Dict[str, Any] = {}
    print("\n  -- auditoria: puede una sola variable reconstruir la etiqueta? " + "-" * 6)
    probes = [f for f in KIN_FEATURES if f in feature_names][:8]
    probes += [f for f in ("alert_count", "burstiness_index", "root_user_ratio") if f in feature_names]
    for name in probes:
        model = fit_model(train[[name]].to_numpy(np.float32), ytr, seed, calibrate=False)
        s = score_binary(model, test[[name]].to_numpy(np.float32), model.classes_)
        auc = roc_auc_score(yte, s) if len(np.unique(yte)) > 1 else float("nan")
        out[name] = float(auc)
        flag = "  <-- reconstruye" if auc >= 0.98 else ""
        print(f"    {name:<26} ROC-AUC={auc:.4f}{flag}")
    return out


def evaluate(model, df: pd.DataFrame, feature_names: List[str], classes, tag: str) -> Dict[str, Any]:
    X = df[feature_names].to_numpy(np.float32)
    y = (df["block_target"] == "BLOCK").astype(int).to_numpy()
    s = score_binary(model, X, classes)
    pred = (s >= 0.5).astype(int)

    metrics: Dict[str, Any] = {
        "n": int(len(df)),
        "block_rate": float(y.mean()),
        "macro_f1": float(f1_score(y, pred, average="macro", zero_division=0)),
        "mcc": float(matthews_corrcoef(y, pred)) if len(np.unique(y)) > 1 else float("nan"),
    }
    if len(np.unique(y)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y, s))
        # La clase rara es ALLOW: se puntua invirtiendo el score.
        metrics["pr_auc_allow"] = float(average_precision_score(1 - y, -s))
        metrics["pr_auc_allow_baseline"] = float((1 - y).mean())
        metrics["lift_allow"] = metrics["pr_auc_allow"] / metrics["pr_auc_allow_baseline"]

    print(f"\n  [{tag}] n={metrics['n']:,}  BLOCK={metrics['block_rate']:.4f}  "
          f"macro-F1={metrics['macro_f1']:.4f}  MCC={metrics['mcc']:.4f}  "
          f"ROC-AUC={metrics.get('roc_auc', float('nan')):.4f}")

    report = per_group_metrics(y, pred, df["agent_id"].to_numpy(), ["ALLOW", "BLOCK"], scores=s)
    print_per_group(report, f"{tag}: por agente")
    metrics["per_agent"] = report

    # Desglose por motivo de bloqueo: que conducta reconoce el modelo.
    blocked = df[df["block_target"] == "BLOCK"]
    if not blocked.empty and "reason" in blocked:
        s_blocked = s[(df["block_target"] == "BLOCK").to_numpy()]
        by_reason = {}
        for reason in sorted(set(blocked["reason"])):
            mask = (blocked["reason"] == reason).to_numpy()
            if mask.sum() >= 20:
                by_reason[str(reason)] = {"n": int(mask.sum()), "recall": float((s_blocked[mask] >= 0.5).mean())}
        metrics["por_motivo"] = by_reason
        if by_reason:
            print(f"    recall por motivo: " + "  ".join(
                f"{k}={v['recall']:.3f} (n={v['n']})" for k, v in by_reason.items()))
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Puntuador sobre etiqueta de bloqueo conductual")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    parser.add_argument("--dataset", default="ARGOS-LAB")
    parser.add_argument("--feature_set", default="behavioral",
                        choices=["full", "nosignature", "behavioral", "shape"])
    parser.add_argument("--drop_kin", action="store_true",
                        help="excluye las variables emparentadas con los criterios de bloqueo")
    parser.add_argument("--per_host", action="store_true", default=True)
    parser.add_argument("--global_only", dest="per_host", action="store_false")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    set_seed(args.seed)
    feature_names = resolve_feature_set(args.feature_set)
    if args.drop_kin:
        removed = [f for f in feature_names if f in KIN_FEATURES]
        feature_names = [f for f in feature_names if f not in KIN_FEATURES]
        print(f"  variables emparentadas retiradas: {len(removed)}")

    root = artifacts_root("block_scorer", args.split_mode,
                          f"{args.dataset}__{args.feature_set}{'__nokin' if args.drop_kin else ''}",
                          now_run_id())
    run_header("train_block_scorer (ARGOS-LAB)", dataset=args.dataset, split_mode=args.split_mode,
               feature_set=args.feature_set, sin_emparentadas=args.drop_kin,
               por_host=args.per_host, out=root)

    try:
        train = load_joined("train", args, feature_names)
        val = load_joined("val", args, feature_names)
        test = load_joined("test", args, feature_names)
    except (FileNotFoundError, EmptySplitError) as exc:
        raise SystemExit(f"No se pudo cargar: {exc}. Ejecuta antes build_block_labels.py")

    if train.empty or test.empty:
        raise SystemExit("La union con las etiquetas de bloqueo quedo vacia")
    print(f"  train={len(train):,}  val={len(val):,}  test={len(test):,}  "
          f"variables={len(feature_names)}")
    print(f"  BLOCK en train={float((train.block_target == 'BLOCK').mean()):.4f}  "
          f"test={float((test.block_target == 'BLOCK').mean()):.4f}")

    audit_result = audit(train, val, feature_names, args.seed)

    Xtr = train[feature_names].to_numpy(np.float32)
    ytr = train["block_target"].to_numpy()
    model = fit_model(Xtr, ytr, args.seed)
    metrics = {
        "val": evaluate(model, val, feature_names, model.classes_, "val"),
        "test": evaluate(model, test, feature_names, model.classes_, "test"),
    }

    per_host: Dict[str, Any] = {}
    if args.per_host:
        print("\n  == modelos por host " + "=" * 40)
        for host, part in train.groupby("agent_id"):
            te_h = test[test["agent_id"] == host]
            if len(part) < 200 or len(te_h) < 50 or part["block_target"].nunique() < 2:
                continue
            m = fit_model(part[feature_names].to_numpy(np.float32), part["block_target"].to_numpy(), args.seed)
            y = (te_h["block_target"] == "BLOCK").astype(int).to_numpy()
            if len(np.unique(y)) < 2:
                continue
            s = score_binary(m, te_h[feature_names].to_numpy(np.float32), m.classes_)
            entry = {
                "n_train": int(len(part)), "n_test": int(len(te_h)),
                "roc_auc": float(roc_auc_score(y, s)),
                "mcc": float(matthews_corrcoef(y, (s >= 0.5).astype(int))),
                "pr_auc_allow": float(average_precision_score(1 - y, -s)),
                "baseline_allow": float((1 - y).mean()),
            }
            entry["lift_allow"] = entry["pr_auc_allow"] / entry["baseline_allow"] if entry["baseline_allow"] else float("nan")
            per_host[str(host)] = entry
            print(f"    agente {host}: n_test={entry['n_test']:<6} ROC-AUC={entry['roc_auc']:.4f}  "
                  f"MCC={entry['mcc']:.4f}  lift(ALLOW)={entry['lift_allow']:.2f}x")

    joblib.dump(model, root / "model.joblib")
    save_json(root / "results.json", {
        "args": vars(args), "auditoria_una_variable": audit_result,
        "per_host": per_host, **metrics,
    })
    print(f"\nGuardado: {root}")


if __name__ == "__main__":
    main()
