#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GRU sobre la secuencia de avisos de una IP: mejora el bloqueo temprano?

Motivacion
----------
El HGB tabular resume los primeros K avisos en agregados (nº usuarios, cadencia
media...). Una red recurrente ve la SECUENCIA: el orden de los cambios de
usuario, la aceleracion de la rampa, el patron de huecos. El margen restante
esta en K=1-3 (AUC 0,83-0,96), y es la ultima oportunidad del deep learning en
este trabajo -- hasta ahora no ha aportado ventaja medible en ninguna tarea.

Entrada por evento (7 dims): log1p(hueco), usuario-nuevo, es-root,
es-cuenta-de-sistema, trae-puerto, agente-nuevo, ventana-nueva. Contexto
estatico de subred/flota (7 dims causales) concatenado al estado final.

Comparacion en identicas condiciones (mismo split, misma semilla, mismo
protocolo de umbral p99 en validacion): GRU vs HGB v2 vs ensamblado por rangos.
Veredicto que se busca: aporta el GRU ranking (AUC) o recall a p99 que el
tabular no tenga?

Fichero nuevo; no modifica ningun script existente.

Uso:
    python experiment_early_blocking_gru.py
"""

from __future__ import annotations

import argparse
from typing import Any, Dict, List

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from scipy.stats import rankdata
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score

from experiment_early_blocking import full_label, load_ip_histories, threshold_for_precision
from experiment_early_blocking_v2 import SUBNET_FEATURES, V2_FEATURES, arrival_context, features_v2
from feature_spec import SYSTEM_USERS
from train_utils import artifacts_root, get_device, now_run_id, run_header, save_json, set_seed

EVENT_DIM = 7


def event_tensor(events: List[tuple], budget: int) -> tuple[np.ndarray, int]:
    """Secuencia (budget, 7) con relleno a cero; devuelve tambien la longitud valida."""
    out = np.zeros((budget, EVENT_DIM), dtype=np.float32)
    seen_users: set = set()
    seen_agents: set = set()
    prev_t = None
    prev_w = None
    n = min(len(events), budget)
    for i in range(n):
        t, agent, user, has_port, window = events[i]
        gap = 0.0 if prev_t is None else max(t - prev_t, 0.0)
        out[i] = (
            np.log1p(gap),
            float(bool(user) and user not in seen_users),
            float(user == "root"),
            float(user in SYSTEM_USERS),
            float(has_port),
            float(agent not in seen_agents),
            float(window != prev_w),
        )
        if user:
            seen_users.add(user)
        seen_agents.add(agent)
        prev_t, prev_w = t, window
    return out, n


class SeqBlocker(nn.Module):
    def __init__(self, hidden: int = 48, ctx_dim: int = len(SUBNET_FEATURES)):
        super().__init__()
        self.gru = nn.GRU(EVENT_DIM, hidden, batch_first=True)
        self.head = nn.Sequential(
            nn.Linear(hidden + ctx_dim, 32), nn.ReLU(), nn.Dropout(0.2), nn.Linear(32, 1),
        )

    def forward(self, x: torch.Tensor, lengths: torch.Tensor, ctx: torch.Tensor) -> torch.Tensor:
        output, _ = self.gru(x)
        idx = (lengths - 1).clamp(min=0).view(-1, 1, 1).expand(-1, 1, output.size(2))
        last = output.gather(1, idx).squeeze(1)
        return self.head(torch.cat([last, ctx], dim=1)).squeeze(1)


def train_gru(Xtr, Ltr, Ctr, ytr, Xva, Lva, Cva, yva, device, seed, epochs=60, patience=8):
    torch.manual_seed(seed)
    model = SeqBlocker().to(device)
    pos_weight = torch.tensor([(len(ytr) - ytr.sum()) / max(ytr.sum(), 1)], device=device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    tensors = lambda X, L, C, y: (torch.from_numpy(X).to(device), torch.from_numpy(L).to(device),
                                  torch.from_numpy(C).to(device), torch.from_numpy(y).float().to(device))
    Xt, Lt, Ct, yt = tensors(Xtr, Ltr, Ctr, ytr)
    Xv, Lv, Cv, yv = tensors(Xva, Lva, Cva, yva)
    best_auc, best_state, bad = -1.0, None, 0
    for _ in range(epochs):
        model.train()
        perm = torch.randperm(len(Xt), device=device)
        for start in range(0, len(Xt), 256):
            sel = perm[start:start + 256]
            optimizer.zero_grad(set_to_none=True)
            loss = criterion(model(Xt[sel], Lt[sel], Ct[sel]), yt[sel])
            loss.backward()
            optimizer.step()
        model.eval()
        with torch.no_grad():
            s_va = torch.sigmoid(model(Xv, Lv, Cv)).cpu().numpy()
        auc = roc_auc_score(yva, s_va) if len(np.unique(yva)) > 1 else 0.5
        if auc > best_auc + 1e-4:
            best_auc, bad = auc, 0
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= patience:
                break
    if best_state is not None:
        model.load_state_dict(best_state)
    return model


def main() -> None:
    parser = argparse.ArgumentParser(description="GRU secuencial para bloqueo temprano")
    parser.add_argument("--budgets", type=int, nargs="+", default=[2, 3, 5, 10])
    parser.add_argument("--target_precision", type=float, default=0.99)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    set_seed(args.seed)
    device = get_device()

    root = artifacts_root("exp_early_blocking_gru", "date", "ARGOS-LAB", now_run_id())
    run_header("experiment_early_blocking_gru (ARGOS-LAB)",
               comparacion="GRU vs HGB v2 vs ensamblado, mismas condiciones",
               dispositivo=str(device), out=root)

    histories = load_ip_histories()
    ips = sorted(histories, key=lambda ip: histories[ip][0][0])
    labels = {ip: full_label(histories[ip]) for ip in ips}
    context = arrival_context(histories, ips)
    cut_tr, cut_va = int(len(ips) * 0.70), int(len(ips) * 0.85)
    split = {ip: ("train" if i < cut_tr else "val" if i < cut_va else "test")
             for i, ip in enumerate(ips)}

    results: Dict[str, Any] = {}
    print(f"\n  {'K':>4}{'AUC HGB':>9}{'AUC GRU':>9}{'AUC ens.':>9}"
          f"{'rec HGB':>9}{'rec GRU':>9}{'rec ens.':>9}")
    for budget in args.budgets:
        data: Dict[str, Dict[str, list]] = {s: {"seq": [], "len": [], "ctx": [], "tab": [], "y": []}
                                            for s in ("train", "val", "test")}
        for ip in ips:
            part = split[ip]
            seq, length = event_tensor(histories[ip], budget)
            data[part]["seq"].append(seq)
            data[part]["len"].append(length)
            data[part]["ctx"].append([context[ip][f] for f in SUBNET_FEATURES])
            data[part]["tab"].append(features_v2(histories[ip], budget, context[ip]))
            data[part]["y"].append(labels[ip])
        packs = {}
        for name, block in data.items():
            packs[name] = (
                np.stack(block["seq"]), np.array(block["len"], dtype=np.int64),
                np.array(block["ctx"], dtype=np.float32),
                pd.DataFrame(block["tab"]), np.array(block["y"], dtype=np.int64),
            )
        (Xtr, Ltr, Ctr, Ttr, ytr) = packs["train"]
        (Xva, Lva, Cva, Tva, yva) = packs["val"]
        (Xte, Lte, Cte, Tte, yte) = packs["test"]

        # normalizar contexto con estadisticas de train
        mean, std = Ctr.mean(0), Ctr.std(0)
        std[std < 1e-6] = 1.0
        Ctr, Cva, Cte = [(c - mean) / std for c in (Ctr, Cva, Cte)]

        hgb = HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.08, max_depth=5, l2_regularization=1.0,
            early_stopping=True, validation_fraction=0.15, n_iter_no_change=15,
            class_weight="balanced", random_state=args.seed,
        ).fit(Ttr[V2_FEATURES], ytr)
        s_hgb_va = hgb.predict_proba(Tva[V2_FEATURES])[:, 1]
        s_hgb_te = hgb.predict_proba(Tte[V2_FEATURES])[:, 1]

        gru = train_gru(Xtr, Ltr, Ctr, ytr, Xva, Lva, Cva, yva, device, args.seed)
        gru.eval()
        with torch.no_grad():
            s_gru_va = torch.sigmoid(gru(torch.from_numpy(Xva).to(device),
                                         torch.from_numpy(Lva).to(device),
                                         torch.from_numpy(Cva).to(device))).cpu().numpy()
            s_gru_te = torch.sigmoid(gru(torch.from_numpy(Xte).to(device),
                                         torch.from_numpy(Lte).to(device),
                                         torch.from_numpy(Cte).to(device))).cpu().numpy()

        # ensamblado por rangos (media de rangos normalizados)
        ens_va = (rankdata(s_hgb_va) + rankdata(s_gru_va)) / (2 * len(s_hgb_va))
        ens_te = (rankdata(s_hgb_te) + rankdata(s_gru_te)) / (2 * len(s_hgb_te))

        entry: Dict[str, Any] = {}
        line = f"  {budget:>4}"
        for tag, (s_va, s_te) in (("hgb", (s_hgb_va, s_hgb_te)),
                                  ("gru", (s_gru_va, s_gru_te)),
                                  ("ens", (ens_va, ens_te))):
            threshold = threshold_for_precision(yva, s_va, args.target_precision)
            blocked = s_te >= threshold
            tp = int(np.sum(blocked & (yte == 1)))
            fp = int(np.sum(blocked & (yte == 0)))
            entry[tag] = {
                "roc_auc": float(roc_auc_score(yte, s_te)),
                "recall_p99": tp / max(int(yte.sum()), 1),
                "precision": tp / max(tp + fp, 1),
                "fp": fp,
            }
        for tag in ("hgb", "gru", "ens"):
            line += f"{entry[tag]['roc_auc']:>9.4f}"
        for tag in ("hgb", "gru", "ens"):
            line += f"{entry[tag]['recall_p99']:>9.3f}"
        print(line)
        results[str(budget)] = entry

    aucs_gru = [results[str(k)]["gru"]["roc_auc"] for k in args.budgets]
    aucs_hgb = [results[str(k)]["hgb"]["roc_auc"] for k in args.budgets]
    verdict = ("GRU_mejora" if np.mean(aucs_gru) > np.mean(aucs_hgb) + 0.005
               else "sin_ventaja_clara" if np.mean(aucs_gru) > np.mean(aucs_hgb) - 0.005
               else "GRU_peor")
    results["veredicto"] = verdict
    print(f"\n  veredicto: {verdict}  (AUC medio GRU {np.mean(aucs_gru):.4f} "
          f"vs HGB {np.mean(aucs_hgb):.4f})")
    save_json(root / "results.json", {"args": vars(args), **results})
    print(f"Guardado: {root}")


if __name__ == "__main__":
    main()
