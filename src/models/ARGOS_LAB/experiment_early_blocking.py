#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bloqueo temprano: predecir si una IP merecera bloqueo ANTES de que complete
su conducta.

Cambio de unidad
----------------
Los puntuadores anteriores clasifican ventanas (minuto x agente). Pero la accion
operativa -- bloquear -- se aplica a una IP, no a un minuto. Este experimento
puntua directamente la IP, y lo hace pronto: con solo sus primeros K avisos.

Es la diferencia entre un IDS y un IPS. El puntuador de ventanas dice "esta
ocurriendo un ataque"; este dice "este origen acabara mereciendo bloqueo,
cortalo ya" -- y cada acierto temprano evita todos los avisos que esa IP habria
generado despues.

Construccion
------------
  unidad     : direccion IP de origen (4.792 en el corpus)
  features   : SOLO lo observado en sus primeros K avisos (K = presupuesto de
               observacion): cuantas cuentas probo, cuantas maquinas toco,
               cadencia, objetivo de cuentas privilegiadas...
  etiqueta   : su historial COMPLETO cumple los criterios de bloqueo de
               `build_block_labels.py` (>=5 usuarios, >=2 agentes, o >=50
               intentos en >=3 ventanas)?
  particion  : temporal por primera aparicion de la IP -- train = IPs surgidas
               en el primer 70 % de la captura, test = en el 30 % final. Sin
               solapamiento de IPs entre particiones.

El umbral operativo se fija sobre una porcion de validacion buscando precision
>= 0,99: bloquear a un usuario legitimo cuesta mas que dejar pasar unos avisos,
asi que el mando se pone en precision, no en F1.

Metrica final ademas del ROC-AUC: **avisos evitados** -- de todo lo que las IPs
de test generaron tras su aviso K, que fraccion habria suprimido el bloqueo
temprano, y a cuantos origenes legitimos habria cortado por error.

Fichero nuevo; no modifica ningun script existente.

Uso:
    python experiment_early_blocking.py
    python experiment_early_blocking.py --budgets 1 3 5 10
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, matthews_corrcoef, precision_recall_curve, roc_auc_score

from feature_spec import SYSTEM_USERS
from train_utils import artifacts_root, now_run_id, repo_root, run_header, save_json, set_seed

RAW = Path("src/models/ARGOS_LAB/argos-alerts_30d.jsonl")

# Mismos criterios que build_block_labels.py -- la etiqueta debe ser identica.
MIN_USERS, MIN_AGENTS, MIN_ALERTS, MIN_WINDOWS = 5, 2, 50, 3

FEATURES = [
    "n_alerts", "n_users", "n_agents", "n_windows", "span_seconds",
    "mean_interarrival", "min_interarrival", "alerts_per_user",
    "users_per_alert", "root_ratio", "system_user_ratio", "port_present_ratio",
    "alerts_first_minute",
]


def clean(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"", "nan", "none", "null"} else text


def load_ip_histories() -> Dict[str, List[tuple]]:
    """Una pasada: por IP, sus avisos ordenados (epoch, agente, usuario, puerto)."""
    histories: Dict[str, List[tuple]] = defaultdict(list)
    src = repo_root() / RAW
    with src.open(encoding="utf-8", errors="replace") as handle:
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
                epoch,
                clean(alert.get("agent_id")),
                user,
                bool(clean(alert.get("src_port"))),
                clean(alert.get("window_start")),
            ))
    for ip in histories:
        histories[ip].sort(key=lambda item: item[0])
    return histories


def full_label(events: List[tuple]) -> int:
    users = {e[2] for e in events if e[2]}
    agents = {e[1] for e in events}
    windows = {e[4] for e in events}
    if len(users) >= MIN_USERS or len(agents) >= MIN_AGENTS:
        return 1
    if len(events) >= MIN_ALERTS and len(windows) >= MIN_WINDOWS:
        return 1
    return 0


def early_features(events: List[tuple], budget: int) -> Dict[str, float]:
    """Variables construidas SOLO con los primeros `budget` avisos."""
    seen = events[:budget]
    n = len(seen)
    times = [e[0] for e in seen]
    users = [e[2] for e in seen if e[2]]
    uniq_users = len(set(users))
    uniq_agents = len({e[1] for e in seen})
    uniq_windows = len({e[4] for e in seen})
    span = times[-1] - times[0] if n > 1 else 0.0
    gaps = np.diff(times) if n > 1 else np.array([0.0])
    first_minute = sum(1 for t in times if t - times[0] <= 60.0)
    return {
        "n_alerts": float(n),
        "n_users": float(uniq_users),
        "n_agents": float(uniq_agents),
        "n_windows": float(uniq_windows),
        "span_seconds": float(span),
        "mean_interarrival": float(gaps.mean()),
        "min_interarrival": float(gaps.min()),
        "alerts_per_user": float(n / max(uniq_users, 1)),
        "users_per_alert": float(uniq_users / n) if n else 0.0,
        "root_ratio": float(sum(u == "root" for u in users) / max(len(users), 1)),
        "system_user_ratio": float(sum(u in SYSTEM_USERS for u in users) / max(len(users), 1)),
        "port_present_ratio": float(sum(e[3] for e in seen) / n) if n else 0.0,
        "alerts_first_minute": float(first_minute),
    }


def threshold_for_precision(y: np.ndarray, scores: np.ndarray, target: float) -> float:
    precision, recall, thresholds = precision_recall_curve(y, scores)
    ok = np.where(precision[:-1] >= target)[0]
    if len(ok) == 0:
        return float(np.max(scores))          # inalcanzable: no bloquear nada
    return float(thresholds[ok[0]])


def main() -> None:
    parser = argparse.ArgumentParser(description="Bloqueo temprano de IPs por conducta inicial")
    parser.add_argument("--budgets", type=int, nargs="+", default=[1, 2, 3, 5, 10, 20],
                        help="presupuestos de observacion (primeros K avisos)")
    parser.add_argument("--train_frac", type=float, default=0.70)
    parser.add_argument("--val_frac", type=float, default=0.15)
    parser.add_argument("--target_precision", type=float, default=0.99)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    set_seed(args.seed)

    root = artifacts_root("exp_early_blocking", "date", "ARGOS-LAB", now_run_id())
    run_header("experiment_early_blocking (ARGOS-LAB)", unidad="direccion IP",
               presupuestos=args.budgets, precision_objetivo=args.target_precision, out=root)

    print("  cargando historiales por IP ...", flush=True)
    histories = load_ip_histories()
    ips = sorted(histories, key=lambda ip: histories[ip][0][0])   # por primera aparicion
    labels = {ip: full_label(histories[ip]) for ip in ips}
    n_pos = sum(labels.values())
    print(f"  IPs={len(ips):,}   bloqueables al final={n_pos:,} ({n_pos / len(ips):.1%})")

    cut_tr = int(len(ips) * args.train_frac)
    cut_va = int(len(ips) * (args.train_frac + args.val_frac))
    split = {ip: ("train" if i < cut_tr else "val" if i < cut_va else "test")
             for i, ip in enumerate(ips)}
    for name in ("train", "val", "test"):
        subset = [ip for ip in ips if split[ip] == name]
        rate = np.mean([labels[ip] for ip in subset])
        print(f"  {name:<6} IPs={len(subset):,}  bloqueables={rate:.1%}")

    results: Dict[str, Any] = {"criterios": {"min_users": MIN_USERS, "min_agents": MIN_AGENTS,
                                             "min_alerts": MIN_ALERTS, "min_windows": MIN_WINDOWS},
                               "presupuestos": {}}
    print(f"\n  {'K':>4}{'ROC-AUC':>9}{'PR-AUC':>8}{'MCC@.5':>8}{'umbral':>8}"
          f"{'recall@p99':>11}{'IPs legit cortadas':>20}{'avisos evitados':>17}")

    for budget in args.budgets:
        frames = {name: [] for name in ("train", "val", "test")}
        meta_test = []
        for ip in ips:
            row = early_features(histories[ip], budget)
            row["y"] = labels[ip]
            frames[split[ip]].append(row)
            if split[ip] == "test":
                meta_test.append({"ip": ip, "total": len(histories[ip]),
                                  "restantes": max(0, len(histories[ip]) - budget)})
        tr = pd.DataFrame(frames["train"]); va = pd.DataFrame(frames["val"]); te = pd.DataFrame(frames["test"])
        meta = pd.DataFrame(meta_test)

        model = HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.08, max_depth=5, l2_regularization=1.0,
            early_stopping=True, validation_fraction=0.15, n_iter_no_change=15,
            class_weight="balanced", random_state=args.seed,
        ).fit(tr[FEATURES], tr["y"])

        s_va = model.predict_proba(va[FEATURES])[:, 1]
        s_te = model.predict_proba(te[FEATURES])[:, 1]
        y_va, y_te = va["y"].to_numpy(), te["y"].to_numpy()

        # umbral: precision objetivo sobre validacion, aplicado una vez a test
        threshold = threshold_for_precision(y_va, s_va, args.target_precision)
        blocked = s_te >= threshold
        tp = int(np.sum(blocked & (y_te == 1)))
        fp = int(np.sum(blocked & (y_te == 0)))
        precision_te = tp / max(tp + fp, 1)
        recall_te = tp / max(int(y_te.sum()), 1)

        # avisos evitados: todo lo que las IPs correctamente bloqueadas
        # habrian generado despues de su aviso K
        prevented = int(meta.loc[blocked & (y_te == 1), "restantes"].sum())
        total_future = int(meta.loc[y_te == 1, "restantes"].sum())
        prevented_pct = prevented / max(total_future, 1)

        entry = {
            "roc_auc": float(roc_auc_score(y_te, s_te)),
            "pr_auc": float(average_precision_score(y_te, s_te)),
            "mcc_05": float(matthews_corrcoef(y_te, (s_te >= 0.5).astype(int))),
            "umbral_p99_val": threshold,
            "precision_test": float(precision_te),
            "recall_test": float(recall_te),
            "ips_bloqueadas": int(blocked.sum()),
            "ips_legitimas_cortadas": fp,
            "avisos_evitados": prevented,
            "avisos_futuros_totales": total_future,
            "avisos_evitados_pct": float(prevented_pct),
        }
        results["presupuestos"][str(budget)] = entry
        print(f"  {budget:>4}{entry['roc_auc']:>9.4f}{entry['pr_auc']:>8.4f}"
              f"{entry['mcc_05']:>8.4f}{threshold:>8.3f}{recall_te:>11.3f}"
              f"{fp:>20}{prevented:>12,} ({prevented_pct:.0%})")

    save_json(root / "results.json", {"args": vars(args), **results})
    print(f"\n  Lectura: con precision >= {args.target_precision:.0%} fijada en validacion, "
          "'avisos evitados' es el volumen de ataque que el bloqueo temprano habria suprimido.")
    print(f"Guardado: {root}")


if __name__ == "__main__":
    main()
