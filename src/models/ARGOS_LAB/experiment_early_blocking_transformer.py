#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Transformer (atencion) sobre la secuencia de avisos de una IP: bloqueo temprano.

Pregunta
--------
R10 cerro el veredicto DL con un GRU que empato con el HGB (AUC 0,9702 vs
0,9703). Un modelo de atencion tiene otro sesgo inductivo: en vez de comprimir
la secuencia en un estado recurrente, cada aviso puede mirar a todos los demas
y al contexto de subred. Se pregunta si eso aporta ranking (AUC), recall a
precision >= 0,99 o algo en la politica secuencial que el tabular no tenga --
y se mide con varias semillas para distinguir mejora de ruido.

Que ve el modelo (y que NO)
---------------------------
Fichas por aviso identicas a las del GRU (7 dims): log1p(hueco), usuario-nuevo,
es-root, es-cuenta-de-sistema, trae-puerto, agente-nuevo, ventana-nueva.
Variante `rich` (+3, misma informacion, otra forma): log1p(usuarios acumulados),
log1p(agentes acumulados), log1p(tiempo desde el primer aviso). El contexto
causal de subred/flota (7 dims) entra como ficha inicial (CLS), que ademas hace
de lector de la secuencia.

Excluido a proposito -- y por que:
  * rule_*, mitre_*, decoder, program, location: entradas del motor que genero
    la etiqueta debil (R1: una columna -> ROC-AUC 0,999). Circular.
  * identidad de la IP o de la subred como token/embedding: las IPs de test son
    disjuntas de train; memorizarlas no generaliza.
  * identidad del agente como embedding: huella del host (R2, 99,75 %). Solo
    entra "es un agente nuevo para esta IP".
  * cadena del usuario como vocabulario: 13.211 usuarios distintos; solo entran
    las categorias root / cuenta-de-sistema / nuevo-para-esta-IP.
  * hora y dia: confundidos con el cron de Trivy en esta captura.
  * geo: no se usa en el bloqueo temprano (memorizaria los paises de la botnet
    del mes).
  * nada del futuro: cada muestra usa solo los primeros K avisos; la etiqueta
    es el historial completo, como en R7.

Dos formas del transformer: un modelo por K (comparable uno a uno con HGB y
GRU) y UN modelo compartido entrenado sobre todos los prefijos (candidato
natural a despliegue: un solo peso, seis umbrales). Se mide ademas la politica
secuencial (R7), la media de probabilidades HGB+Transformer y las politicas
HGB AND Transformer / HGB OR Transformer, con desglose por agente del primer
aviso.

Fichero nuevo; no modifica ningun script existente.

Uso:
    python experiment_early_blocking_transformer.py
    python experiment_early_blocking_transformer.py --seeds 42 --budgets 2 3 5
"""

from __future__ import annotations

import argparse
import time
from typing import Any, Callable, Dict, List, Sequence, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score

from experiment_early_blocking import full_label, load_ip_histories, threshold_for_precision
from experiment_early_blocking_gru import EVENT_DIM, event_tensor, train_gru
from experiment_early_blocking_v2 import SUBNET_FEATURES, V2_FEATURES, arrival_context, features_v2
from feature_spec import SYSTEM_USERS
from train_utils import artifacts_root, get_device, now_run_id, run_header, save_json, set_seed

BASE_TOKEN_NAMES = ["log_gap", "user_new", "is_root", "is_system_user", "has_port", "agent_new", "window_new"]
RICH_TOKEN_NAMES = ["log_users_so_far", "log_agents_so_far", "log_since_first"]
DEFAULT_BUDGETS = [1, 2, 3, 5, 10, 20]

HYPER = dict(d=32, heads=4, layers=2, ff=64, dropout=0.1)
TRAIN = dict(epochs=80, patience=10, lr=2e-3, batch=256, weight_decay=1e-4)


# ===========================================================================
# Fichas por aviso (causales: la ficha i solo depende de los avisos <= i)
# ===========================================================================
def token_names(rich: bool) -> List[str]:
    return BASE_TOKEN_NAMES + (RICH_TOKEN_NAMES if rich else [])


def event_tokens(events: Sequence[tuple], budget: int, rich: bool) -> Tuple[np.ndarray, int]:
    """Secuencia (budget, dim) con relleno a cero; devuelve tambien la longitud."""
    dim = len(token_names(rich))
    out = np.zeros((budget, dim), dtype=np.float32)
    seen_users: set = set()
    seen_agents: set = set()
    prev_t = prev_w = None
    n = min(len(events), budget)
    t0 = events[0][0] if events else 0.0
    for i in range(n):
        t, agent, user, has_port, window = events[i]
        gap = 0.0 if prev_t is None else max(t - prev_t, 0.0)
        base = (
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
        if rich:
            out[i] = base + (np.log1p(len(seen_users)), np.log1p(len(seen_agents)), np.log1p(max(t - t0, 0.0)))
        else:
            out[i] = base
        prev_t, prev_w = t, window
    return out, n


def build_tokens(histories, ips: List[str], max_budget: int, rich: bool):
    dim = len(token_names(rich))
    X = np.zeros((len(ips), max_budget, dim), dtype=np.float32)
    L = np.zeros(len(ips), dtype=np.int64)
    for i, ip in enumerate(ips):
        X[i], L[i] = event_tokens(histories[ip], max_budget, rich)
    return X, L


def masked_stats(X: np.ndarray, L: np.ndarray):
    valid = np.arange(X.shape[1])[None, :] < L[:, None]
    flat = X[valid]
    mean, std = flat.mean(0), flat.std(0)
    std[std < 1e-6] = 1.0
    return mean.astype(np.float32), std.astype(np.float32)


def apply_norm(X: np.ndarray, L: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    Z = (X - mean) / std
    valid = np.arange(X.shape[1])[None, :] < L[:, None]
    Z[~valid] = 0.0
    return Z.astype(np.float32)


# ===========================================================================
# Modelo de atencion
# ===========================================================================
class EncoderBlock(nn.Module):
    """Bloque pre-LN: x + MHA(LN(x)); x + FFN(LN(x)). ReLU en la FFN para que el
    port a numpy del paquete de despliegue sea exacto y sin dependencias."""

    def __init__(self, d: int, heads: int, ff: int, dropout: float):
        super().__init__()
        self.ln1 = nn.LayerNorm(d)
        self.attn = nn.MultiheadAttention(d, heads, dropout=dropout, batch_first=True)
        self.ln2 = nn.LayerNorm(d)
        self.ff = nn.Sequential(nn.Linear(d, ff), nn.ReLU(), nn.Dropout(dropout), nn.Linear(ff, d))
        self.drop = nn.Dropout(dropout)

    def forward(self, x, pad_mask, need_weights=False):
        h = self.ln1(x)
        a, w = self.attn(h, h, h, key_padding_mask=pad_mask, need_weights=need_weights,
                         average_attn_weights=True)
        x = x + self.drop(a)
        x = x + self.drop(self.ff(self.ln2(x)))
        return x, w


class AttentionBlocker(nn.Module):
    """Ficha 0 = contexto de subred (CLS); fichas 1..n = avisos. Posicion aprendida.
    La salida se lee en la ficha 0 tras los bloques."""

    def __init__(self, token_dim: int, ctx_dim: int, max_len: int, d: int, heads: int,
                 layers: int, ff: int, dropout: float):
        super().__init__()
        self.tok = nn.Linear(token_dim, d)
        self.ctx = nn.Linear(ctx_dim, d)
        self.pos = nn.Embedding(max_len + 1, d)
        self.blocks = nn.ModuleList([EncoderBlock(d, heads, ff, dropout) for _ in range(layers)])
        self.ln_out = nn.LayerNorm(d)
        self.head = nn.Linear(d, 1)

    def forward(self, x, lengths, ctx, need_weights=False):
        B, T, _ = x.shape
        pos = torch.arange(T + 1, device=x.device)
        h = torch.cat([self.ctx(ctx).unsqueeze(1), self.tok(x)], dim=1) + self.pos(pos).unsqueeze(0)
        pad = torch.arange(T, device=x.device).unsqueeze(0) >= lengths.unsqueeze(1)
        pad = torch.cat([torch.zeros(B, 1, dtype=torch.bool, device=x.device), pad], dim=1)
        weights = None
        for block in self.blocks:
            h, weights = block(h, pad, need_weights)
        return self.head(self.ln_out(h[:, 0])).squeeze(1), weights


def n_params(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters())


@torch.no_grad()
def predict(model: AttentionBlocker, X: np.ndarray, L: np.ndarray, C: np.ndarray, device,
            batch: int = 4096) -> np.ndarray:
    model.eval()
    out = []
    for s in range(0, len(X), batch):
        xb = torch.from_numpy(X[s:s + batch]).to(device)
        lb = torch.from_numpy(L[s:s + batch]).to(device)
        cb = torch.from_numpy(C[s:s + batch]).to(device)
        logits, _ = model(xb, lb, cb)
        out.append(torch.sigmoid(logits).cpu().numpy())
    return np.concatenate(out) if out else np.zeros(0, dtype=np.float32)


def fit_attention(model: AttentionBlocker, X: np.ndarray, L: np.ndarray, C: np.ndarray, y: np.ndarray,
                  val_metric: Callable[[AttentionBlocker], float], device, seed: int,
                  epochs: int, patience: int, lr: float, batch: int, weight_decay: float) -> Dict[str, Any]:
    torch.manual_seed(seed)
    model.to(device)
    Xt, Lt = torch.from_numpy(X).to(device), torch.from_numpy(L).to(device)
    Ct, yt = torch.from_numpy(C).to(device), torch.from_numpy(y).float().to(device)
    pos_weight = torch.tensor([(len(y) - y.sum()) / max(y.sum(), 1)], device=device, dtype=torch.float32)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    best, best_state, bad, history = -1.0, None, 0, []
    for epoch in range(epochs):
        model.train()
        perm = torch.randperm(len(Xt), device=device)
        for s in range(0, len(Xt), batch):
            sel = perm[s:s + batch]
            optimizer.zero_grad(set_to_none=True)
            logits, _ = model(Xt[sel], Lt[sel], Ct[sel])
            loss = criterion(logits, yt[sel])
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
        metric = val_metric(model)
        history.append(metric)
        if metric > best + 1e-4:
            best, bad = metric, 0
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= patience:
                break
    if best_state is not None:
        model.load_state_dict(best_state)
    return {"best_val": best, "epochs_run": len(history)}


def safe_auc(y: np.ndarray, s: np.ndarray) -> float:
    return float(roc_auc_score(y, s)) if len(np.unique(y)) > 1 else 0.5


# ===========================================================================
# Conjunto de datos compartido por todos los modelos
# ===========================================================================
def build_dataset(budgets: List[int], rich: bool) -> Dict[str, Any]:
    histories = load_ip_histories()
    ips = sorted(histories, key=lambda ip: histories[ip][0][0])
    labels = np.array([full_label(histories[ip]) for ip in ips], dtype=np.int64)
    context = arrival_context(histories, ips)
    cut_tr, cut_va = int(len(ips) * 0.70), int(len(ips) * 0.85)
    part = np.array(["train"] * cut_tr + ["val"] * (cut_va - cut_tr) + ["test"] * (len(ips) - cut_va))
    max_budget = max(budgets)

    X, L = build_tokens(histories, ips, max_budget, rich)
    # comprobacion: las 7 primeras dims coinciden exactamente con las del GRU (R10)
    for ip in ips[:50]:
        ref, n_ref = event_tensor(histories[ip], max_budget)
        mine, n_mine = event_tokens(histories[ip], max_budget, rich)
        assert n_ref == n_mine and np.allclose(ref, mine[:, :EVENT_DIM]), "tokens base != GRU"

    C = np.array([[context[ip][f] for f in SUBNET_FEATURES] for ip in ips], dtype=np.float32)
    tr = part == "train"
    tok_mean, tok_std = masked_stats(X[tr], L[tr])
    ctx_mean, ctx_std = C[tr].mean(0), C[tr].std(0)
    ctx_std[ctx_std < 1e-6] = 1.0
    Xn = apply_norm(X, L, tok_mean, tok_std)
    Cn = ((C - ctx_mean) / ctx_std).astype(np.float32)

    tab = {k: pd.DataFrame([features_v2(histories[ip], k, context[ip]) for ip in ips]) for k in budgets}
    return {
        "histories": histories, "ips": ips, "y": labels, "part": part, "budgets": budgets,
        "X_raw": X, "X": Xn,
        "X_gru": apply_norm(X[:, :, :EVENT_DIM], L, np.zeros(EVENT_DIM, np.float32), np.ones(EVENT_DIM, np.float32)),
        "L": L, "C": Cn, "tab": tab, "rich": rich,
        "norm": {"token_mean": tok_mean.tolist(), "token_std": tok_std.tolist(),
                 "ctx_mean": ctx_mean.astype(float).tolist(), "ctx_std": ctx_std.astype(float).tolist()},
        "first_agent": np.array([histories[ip][0][1] for ip in ips]),
        "lens": np.array([len(histories[ip]) for ip in ips]),
    }


def slice_k(X: np.ndarray, L: np.ndarray, k: int):
    return np.ascontiguousarray(X[:, :k]), np.minimum(L, k)


def new_model(data: Dict[str, Any], hyper: Dict[str, Any]) -> AttentionBlocker:
    return AttentionBlocker(token_dim=data["X"].shape[2], ctx_dim=data["C"].shape[1],
                            max_len=max(data["budgets"]), **hyper)


def fit_shared(data: Dict[str, Any], seed: int, device, hyper=HYPER, train=TRAIN) -> Tuple[AttentionBlocker, Dict]:
    """UN modelo sobre todos los prefijos {min(len, K)} del train (sin duplicar
    longitudes). Metrica de parada: media de AUC por K en validacion."""
    tr, va = data["part"] == "train", data["part"] == "val"
    idx_tr = np.where(tr)[0]
    rows, effs = [], []
    for i in idx_tr:
        for eff in sorted({int(min(data["L"][i], k)) for k in data["budgets"]}):
            rows.append(i); effs.append(eff)
    rows, effs = np.array(rows), np.array(effs, dtype=np.int64)
    Xs, Cs, ys = data["X"][rows], data["C"][rows], data["y"][rows]
    Xv, Cv, yv, Lv = data["X"][va], data["C"][va], data["y"][va], data["L"][va]

    def val_metric(model):
        aucs = []
        for k in data["budgets"]:
            xk, lk = slice_k(Xv, Lv, k)
            aucs.append(safe_auc(yv, predict(model, xk, lk, Cv, device)))
        return float(np.mean(aucs))

    model = new_model(data, hyper)
    info = fit_attention(model, Xs, effs, Cs, ys, val_metric, device, seed, **train)
    info["train_samples"] = int(len(rows))
    return model, info


def fit_per_k(data: Dict[str, Any], k: int, seed: int, device, hyper=HYPER, train=TRAIN) -> AttentionBlocker:
    tr, va = data["part"] == "train", data["part"] == "val"
    Xk, Lk = slice_k(data["X"], data["L"], k)
    Xv, Lv, Cv, yv = Xk[va], Lk[va], data["C"][va], data["y"][va]
    model = new_model(data, hyper)
    fit_attention(model, Xk[tr], Lk[tr], data["C"][tr], data["y"][tr],
                  lambda m: safe_auc(yv, predict(m, Xv, Lv, Cv, device)), device, seed, **train)
    return model


def fit_hgb(data: Dict[str, Any], k: int, seed: int) -> HistGradientBoostingClassifier:
    tr = data["part"] == "train"
    return HistGradientBoostingClassifier(
        max_iter=250, learning_rate=0.08, max_depth=5, l2_regularization=1.0,
        early_stopping=True, validation_fraction=0.15, n_iter_no_change=15,
        class_weight="balanced", random_state=seed,
    ).fit(data["tab"][k].loc[tr, V2_FEATURES], data["y"][tr])


# ===========================================================================
# Evaluacion: por K, politica secuencial, combinaciones
# ===========================================================================
def eval_k(y_va, s_va, y_te, s_te, target: float) -> Dict[str, float]:
    thr = threshold_for_precision(y_va, s_va, target)
    blocked = s_te >= thr
    tp = int(np.sum(blocked & (y_te == 1))); fp = int(np.sum(blocked & (y_te == 0)))
    return {"roc_auc": safe_auc(y_te, s_te), "recall_p99": tp / max(int(y_te.sum()), 1),
            "precision": tp / max(tp + fp, 1), "fp": fp, "umbral": float(thr)}


def sequential_policy(decide: Dict[int, np.ndarray], y: np.ndarray, lens: np.ndarray,
                      groups: np.ndarray | None = None) -> Dict[str, Any]:
    """`decide[K]` = mascara booleana 'bloquearia en K'. Bloqueo al primer K."""
    budgets = sorted(decide)
    blocked_at = np.full(len(y), -1, dtype=int)
    for k in budgets:
        newly = decide[k] & (blocked_at < 0)
        blocked_at[newly] = k
    blocked = blocked_at > 0
    tp_mask, fp_mask = blocked & (y == 1), blocked & (y == 0)
    prevented = int(np.sum(np.maximum(0, lens[tp_mask] - blocked_at[tp_mask])))
    future_all = int(np.sum(np.maximum(0, lens[y == 1] - 1)))
    ks = blocked_at[tp_mask]
    out = {
        "recall": float(tp_mask.sum() / max(int(y.sum()), 1)),
        "precision": float(tp_mask.sum() / max(int(blocked.sum()), 1)),
        "ips_legitimas_cortadas": int(fp_mask.sum()),
        "aviso_mediano_de_bloqueo": float(np.median(ks)) if len(ks) else None,
        "avisos_evitados_pct": prevented / max(future_all, 1),
        "reparto_bloqueos_por_K": {str(k): int((ks == k).sum()) for k in sorted(set(ks.tolist()))},
    }
    if groups is not None:
        out["por_agente_primer_aviso"] = {}
        for g in sorted(set(groups.tolist())):
            m = groups == g
            out["por_agente_primer_aviso"][str(g)] = {
                "ips": int(m.sum()), "bloqueables": int(y[m].sum()),
                "recall": float((tp_mask & m).sum() / max(int(y[m].sum()), 1)),
                "precision": float((tp_mask & m).sum() / max(int((blocked & m).sum()), 1)),
                "fp": int((fp_mask & m).sum()),
            }
    return out


def mean_std(values: List[float]) -> Dict[str, float]:
    arr = np.array(values, dtype=float)
    return {"mean": float(arr.mean()), "std": float(arr.std()), "n": int(len(arr))}


def attention_examples(model: AttentionBlocker, data: Dict[str, Any], k: int, device, n_show: int = 4) -> List[Dict]:
    te = np.where(data["part"] == "test")[0]
    Xk, Lk = slice_k(data["X"], data["L"], k)
    long_enough = te[Lk[te] >= k]
    scores = predict(model, Xk[long_enough], Lk[long_enough], data["C"][long_enough], device)
    order = long_enough[np.argsort(-scores)]
    pos = [i for i in order if data["y"][i] == 1][: n_show - 1]
    neg = [i for i in order if data["y"][i] == 0][:1]
    out = []
    model.eval()
    with torch.no_grad():
        for i in pos + neg:
            xb = torch.from_numpy(Xk[i:i + 1]).to(device)
            lb = torch.from_numpy(Lk[i:i + 1]).to(device)
            cb = torch.from_numpy(data["C"][i:i + 1]).to(device)
            logit, w = model(xb, lb, cb, need_weights=True)
            att = w[0, 0, 1:1 + int(Lk[i])].cpu().numpy()
            raw = data["X_raw"][i, :int(Lk[i]), :EVENT_DIM]
            out.append({
                "ip": data["ips"][i], "y": int(data["y"][i]), "score": float(torch.sigmoid(logit).item()),
                "atencion_cls_por_aviso": [round(float(a), 3) for a in att],
                "avisos_mas_atendidos": [int(j + 1) for j in np.argsort(-att)[:3]],
                "flags_por_aviso": [{"pos": j + 1, "gap_s": round(float(np.expm1(raw[j, 0])), 1),
                                     "user_new": int(raw[j, 1]), "root": int(raw[j, 2]),
                                     "system": int(raw[j, 3]), "agent_new": int(raw[j, 5]),
                                     "window_new": int(raw[j, 6])} for j in range(len(att))],
            })
    return out


# ===========================================================================
def main() -> None:
    parser = argparse.ArgumentParser(description="Transformer secuencial para bloqueo temprano")
    parser.add_argument("--budgets", type=int, nargs="+", default=DEFAULT_BUDGETS)
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    parser.add_argument("--target_precision", type=float, default=0.99)
    parser.add_argument("--token_set", choices=["base", "rich"], default="rich")
    parser.add_argument("--no_gru", action="store_true", help="omitir la referencia GRU (R10)")
    args = parser.parse_args()
    set_seed(args.seeds[0])
    device = get_device()

    root = artifacts_root("exp_early_blocking_transformer", "date", f"ARGOS-LAB__{args.token_set}", now_run_id())
    run_header("experiment_early_blocking_transformer (ARGOS-LAB)",
               comparacion="HGB v2 vs GRU vs Transformer (por K y compartido), mismas condiciones",
               semillas=args.seeds, fichas=args.token_set, dispositivo=str(device), out=root)

    t0 = time.time()
    print("  construyendo conjunto (historiales, contexto causal, fichas, tabular) ...", flush=True)
    data = build_dataset(args.budgets, rich=(args.token_set == "rich"))
    y, part, lens = data["y"], data["part"], data["lens"]
    va, te = part == "val", part == "test"
    y_va, y_te = y[va], y[te]
    groups_te = data["first_agent"][te]
    print(f"  IPs={len(y):,} (train {int((part == 'train').sum()):,} / val {int(va.sum()):,} / test {int(te.sum()):,})"
          f"  bloqueables test={y_te.mean():.1%}  fichas={data['X'].shape[2]} dims  [{time.time() - t0:.0f}s]")
    print(f"  transformer: {n_params(new_model(data, HYPER)):,} parametros  {HYPER}")

    model_tags = ["hgb", "tr_k", "tr_shared"] + ([] if args.no_gru else ["gru"])
    scores: Dict[str, Dict[int, Dict[int, Dict[str, np.ndarray]]]] = {m: {} for m in model_tags}   # tag->seed->K->{va,te}
    per_k: Dict[str, Dict[int, List[Dict]]] = {m: {k: [] for k in args.budgets} for m in model_tags}
    shared_models: Dict[int, AttentionBlocker] = {}
    fit_info: Dict[str, Any] = {}

    for seed in args.seeds:
        print(f"\n  == semilla {seed} ==", flush=True)
        t_seed = time.time()
        for tag in model_tags:
            scores[tag][seed] = {}
        # --- compartido: un entrenamiento para todos los K
        shared, info = fit_shared(data, seed, device)
        shared_models[seed] = shared
        fit_info[f"tr_shared_seed{seed}"] = info
        for k in args.budgets:
            Xk, Lk = slice_k(data["X"], data["L"], k)
            scores["tr_shared"][seed][k] = {
                "va": predict(shared, Xk[va], Lk[va], data["C"][va], device),
                "te": predict(shared, Xk[te], Lk[te], data["C"][te], device),
            }
            # --- por K
            mk = fit_per_k(data, k, seed, device)
            scores["tr_k"][seed][k] = {
                "va": predict(mk, Xk[va], Lk[va], data["C"][va], device),
                "te": predict(mk, Xk[te], Lk[te], data["C"][te], device),
            }
            hgb = fit_hgb(data, k, seed)
            T = data["tab"][k]
            scores["hgb"][seed][k] = {
                "va": hgb.predict_proba(T.loc[va, V2_FEATURES])[:, 1],
                "te": hgb.predict_proba(T.loc[te, V2_FEATURES])[:, 1],
            }
            if not args.no_gru:
                Xg, Lg = slice_k(data["X_gru"], data["L"], k)
                trm = part == "train"
                gru = train_gru(Xg[trm], Lg[trm], data["C"][trm], y[trm], Xg[va], Lg[va], data["C"][va], y_va,
                                device, seed)
                gru.eval()
                with torch.no_grad():
                    def f(m):
                        return torch.sigmoid(gru(torch.from_numpy(Xg[m]).to(device), torch.from_numpy(Lg[m]).to(device),
                                                 torch.from_numpy(data["C"][m]).to(device))).cpu().numpy()
                    scores["gru"][seed][k] = {"va": f(va), "te": f(te)}
            for tag in model_tags:
                s = scores[tag][seed][k]
                per_k[tag][k].append(eval_k(y_va, s["va"], y_te, s["te"], args.target_precision))
        print(f"     hecho en {time.time() - t_seed:.0f}s", flush=True)

    # ------------------------------------------------------------------ por K
    results: Dict[str, Any] = {"args": vars(args), "hyper": HYPER, "train": TRAIN, "norm": data["norm"],
                               "token_names": token_names(data["rich"]), "ctx_features": SUBNET_FEATURES,
                               "fit_info": fit_info, "por_K": {}, "secuencial": {}, "combinaciones": {}}
    print(f"\n  == ROC-AUC en test por K (media ± desv. sobre {len(args.seeds)} semillas) ==")
    header = f"  {'K':>4}" + "".join(f"{t:>18}" for t in model_tags)
    print(header)
    for k in args.budgets:
        line = f"  {k:>4}"
        results["por_K"][str(k)] = {}
        for tag in model_tags:
            aucs = [e["roc_auc"] for e in per_k[tag][k]]
            recs = [e["recall_p99"] for e in per_k[tag][k]]
            fps = [e["fp"] for e in per_k[tag][k]]
            results["por_K"][str(k)][tag] = {"roc_auc": mean_std(aucs), "recall_p99": mean_std(recs),
                                              "fp": mean_std(fps), "umbral_seed0": per_k[tag][k][0]["umbral"]}
            line += f"  {np.mean(aucs):.4f}±{np.std(aucs):.4f}"
        print(line)
    print(f"\n  == recall a precision >= {args.target_precision:.0%} (umbral de validacion) por K ==")
    print(header)
    for k in args.budgets:
        line = f"  {k:>4}"
        for tag in model_tags:
            r = results["por_K"][str(k)][tag]["recall_p99"]
            line += f"  {r['mean']:.3f}±{r['std']:.3f}     "
        print(line)

    # ------------------------------------------------------- politica secuencial
    print("\n  == politica secuencial: bloquear al primer cruce de umbral (media sobre semillas) ==")
    print(f"  {'modelo':<14}{'recall':>8}{'precision':>11}{'FP':>5}{'mediana K':>11}{'evitado':>9}")
    seq_by_tag: Dict[str, Dict[int, Dict]] = {}
    thresholds: Dict[str, Dict[int, Dict[int, float]]] = {}
    for tag in model_tags:
        seq_by_tag[tag] = {}; thresholds[tag] = {}
        for seed in args.seeds:
            thresholds[tag][seed] = {k: threshold_for_precision(y_va, scores[tag][seed][k]["va"], args.target_precision)
                                     for k in args.budgets}
            decide = {k: scores[tag][seed][k]["te"] >= thresholds[tag][seed][k] for k in args.budgets}
            seq_by_tag[tag][seed] = sequential_policy(decide, y_te, lens[te], groups_te)
        agg = {m: mean_std([seq_by_tag[tag][s][m] for s in args.seeds])
               for m in ("recall", "precision", "ips_legitimas_cortadas", "avisos_evitados_pct")}
        results["secuencial"][tag] = {"media": agg, "por_semilla": {str(s): seq_by_tag[tag][s] for s in args.seeds}}
        med = [seq_by_tag[tag][s]["aviso_mediano_de_bloqueo"] for s in args.seeds]
        print(f"  {tag:<14}{agg['recall']['mean']:>8.3f}{agg['precision']['mean']:>11.3f}"
              f"{agg['ips_legitimas_cortadas']['mean']:>5.1f}{np.mean(med):>11.1f}"
              f"{agg['avisos_evitados_pct']['mean']:>9.1%}")

    # ------------------------------------------------ combinaciones HGB + transformer
    print("\n  == combinaciones HGB + Transformer compartido (media sobre semillas) ==")
    combos: Dict[str, Dict[int, Dict]] = {"ens_media": {}, "hgb_AND_tr": {}, "hgb_OR_tr": {}}
    for seed in args.seeds:
        s_h, s_t = scores["hgb"][seed], scores["tr_shared"][seed]
        ens_thr = {k: threshold_for_precision(y_va, 0.5 * (s_h[k]["va"] + s_t[k]["va"]), args.target_precision)
                   for k in args.budgets}
        d_ens = {k: 0.5 * (s_h[k]["te"] + s_t[k]["te"]) >= ens_thr[k] for k in args.budgets}
        d_h = {k: s_h[k]["te"] >= thresholds["hgb"][seed][k] for k in args.budgets}
        d_t = {k: s_t[k]["te"] >= thresholds["tr_shared"][seed][k] for k in args.budgets}
        combos["ens_media"][seed] = sequential_policy(d_ens, y_te, lens[te], groups_te)
        combos["hgb_AND_tr"][seed] = sequential_policy({k: d_h[k] & d_t[k] for k in args.budgets}, y_te, lens[te], groups_te)
        combos["hgb_OR_tr"][seed] = sequential_policy({k: d_h[k] | d_t[k] for k in args.budgets}, y_te, lens[te], groups_te)
    print(f"  {'politica':<14}{'recall':>8}{'precision':>11}{'FP':>5}{'mediana K':>11}{'evitado':>9}")
    for name, per_seed in combos.items():
        agg = {m: mean_std([per_seed[s][m] for s in args.seeds])
               for m in ("recall", "precision", "ips_legitimas_cortadas", "avisos_evitados_pct")}
        med = [per_seed[s]["aviso_mediano_de_bloqueo"] for s in args.seeds]
        results["combinaciones"][name] = {"media": agg, "por_semilla": {str(s): per_seed[s] for s in args.seeds}}
        print(f"  {name:<14}{agg['recall']['mean']:>8.3f}{agg['precision']['mean']:>11.3f}"
              f"{agg['ips_legitimas_cortadas']['mean']:>5.1f}{np.mean(med):>11.1f}"
              f"{agg['avisos_evitados_pct']['mean']:>9.1%}")

    # -------------------------------------------- desglose por agente del 1er aviso
    print(f"\n  == desglose por agente del primer aviso (politica secuencial, semilla {args.seeds[0]}) ==")
    print(f"  {'agente':<8}{'IPs':>6}{'bloq.':>7}" + "".join(f"{t + ' rec/FP':>18}" for t in model_tags))
    s0 = args.seeds[0]
    for g, meta in seq_by_tag["hgb"][s0]["por_agente_primer_aviso"].items():
        line = f"  {g:<8}{meta['ips']:>6}{meta['bloqueables']:>7}"
        for tag in model_tags:
            e = seq_by_tag[tag][s0]["por_agente_primer_aviso"][g]
            line += f"{e['recall']:>13.3f} /{e['fp']:>3}"
        print(line)

    # ---------------------------------------------------- atencion: que avisos pesan
    k_show = 10 if 10 in args.budgets else max(args.budgets)
    examples = attention_examples(shared_models[s0], data, k_show, device)
    results["ejemplos_atencion_K%d" % k_show] = examples
    print(f"\n  == atencion de la ficha de contexto sobre los avisos (compartido, K={k_show}, semilla {s0}) ==")
    for ex in examples:
        print(f"  {ex['ip']:<16} y={ex['y']} score={ex['score']:.3f}  avisos mas atendidos: {ex['avisos_mas_atendidos']}  "
              f"pesos: {ex['atencion_cls_por_aviso']}")

    # ------------------------------------------------------------------ veredicto
    def mean_auc(tag):
        return float(np.mean([results["por_K"][str(k)][tag]["roc_auc"]["mean"] for k in args.budgets]))
    m_hgb, m_shared, m_k = mean_auc("hgb"), mean_auc("tr_shared"), mean_auc("tr_k")
    best_tr = max(m_shared, m_k)
    verdict = ("transformer_mejora" if best_tr > m_hgb + 0.005
               else "sin_ventaja_clara" if best_tr > m_hgb - 0.005 else "transformer_peor")
    rec_h = results["secuencial"]["hgb"]["media"]["recall"]["mean"]
    rec_t = results["secuencial"]["tr_shared"]["media"]["recall"]["mean"]
    results["veredicto"] = {"auc_medio_hgb": m_hgb, "auc_medio_tr_shared": m_shared, "auc_medio_tr_k": m_k,
                            "recall_secuencial_hgb": rec_h, "recall_secuencial_tr_shared": rec_t,
                            "veredicto": verdict, "tiempo_total_s": time.time() - t0}
    if not args.no_gru:
        results["veredicto"]["auc_medio_gru"] = mean_auc("gru")
    print(f"\n  veredicto: {verdict}  (AUC medio por K: HGB {m_hgb:.4f} · TR compartido {m_shared:.4f} · "
          f"TR por K {m_k:.4f}" + (f" · GRU {mean_auc('gru'):.4f}" if not args.no_gru else "") + ")")
    print(f"  recall secuencial: HGB {rec_h:.3f} · TR compartido {rec_t:.3f}")

    # checkpoint del compartido (semilla principal) para el paquete de despliegue
    ckpt = {"state_dict": {k: v.cpu() for k, v in shared_models[s0].state_dict().items()},
            "hyper": HYPER, "norm": data["norm"], "token_set": args.token_set,
            "token_names": token_names(data["rich"]), "ctx_features": SUBNET_FEATURES,
            "budgets": args.budgets, "thresholds": {str(k): float(v) for k, v in thresholds["tr_shared"][s0].items()},
            "seed": s0}
    torch.save(ckpt, root / f"attention_shared_seed{s0}.pt")
    save_json(root / "results.json", results)
    print(f"\nGuardado: {root}  [{time.time() - t0:.0f}s]")


if __name__ == "__main__":
    main()
