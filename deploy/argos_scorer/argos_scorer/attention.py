# -*- coding: utf-8 -*-
"""Bloqueo temprano con modelo de ATENCION (Transformer) — inferencia en numpy puro.

Cuarto servicio del paquete. Misma unidad, misma etiqueta, misma politica
secuencial y mismos umbrales a precision >= 0,99 que `EarlyBlockScorer`, pero
el modelo no ve agregados: ve la SECUENCIA de los primeros K avisos de la IP
(una ficha por aviso) y el contexto causal de subred como ficha inicial. Igual
que en el HGB hay un modelo por presupuesto K; todos viajan en un unico `.npz`.

Por que en numpy y no en torch: el paquete no arrastra 200 MB de dependencia
por modelos de 18.000 parametros. El forward (2 bloques pre-LN, 4 cabezas,
d=32) se reimplementa aqui en ~60 lineas y `build_deploy_attention.py`
verifica en cada construccion que reproduce a torch (max |diff| < 1e-4).

Que ve cada ficha (y que NO, mismos vetos que el resto del paquete):
  log1p(hueco), usuario-nuevo, es-root, es-cuenta-de-sistema, trae-puerto,
  agente-nuevo, ventana-nueva [+ log1p(usuarios acumulados), log1p(agentes
  acumulados), log1p(tiempo desde el primer aviso) en el juego `rich`].
  Nada de rule_*/mitre_*/decoder (circular), ni identidad de IP/agente/usuario
  (memorizacion, huella de host), ni hora (cron), ni geo.

Extra que el HGB no puede dar: la ATENCION de la ficha de contexto sobre los
avisos dice que avisos pesaron en la decision (`evidence.avisos_decisivos`).
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from .features import SYSTEM_USERS, LiveState, early_ip_features, ip_event

BASE_TOKEN_NAMES = ["log_gap", "user_new", "is_root", "is_system_user", "has_port", "agent_new", "window_new"]
RICH_TOKEN_NAMES = ["log_users_so_far", "log_agents_so_far", "log_since_first"]


# ===========================================================================
# Fichas por aviso (identicas a experiment_early_blocking_transformer.event_tokens)
# ===========================================================================
def event_tokens(events: Sequence[Dict[str, Any]], budget: int, rich: bool) -> np.ndarray:
    """(n, dim) con n = min(len(events), budget). Causal: la ficha i solo usa
    los avisos <= i. `events` son los dicts que produce `ip_event`."""
    n = min(len(events), budget)
    dim = len(BASE_TOKEN_NAMES) + (len(RICH_TOKEN_NAMES) if rich else 0)
    out = np.zeros((n, dim), dtype=np.float32)
    seen_users: set = set()
    seen_agents: set = set()
    prev_t = prev_w = None
    t0 = events[0]["t"] if events else 0.0
    for i in range(n):
        e = events[i]
        t, agent, user, has_port, window = e["t"], e["agent"], e["user"], e["has_port"], e["window"]
        gap = 0.0 if prev_t is None else max(t - prev_t, 0.0)
        row = [
            math.log1p(gap),
            float(bool(user) and user not in seen_users),
            float(user == "root"),
            float(user in SYSTEM_USERS),
            float(has_port),
            float(agent not in seen_agents),
            float(window != prev_w),
        ]
        if user:
            seen_users.add(user)
        seen_agents.add(agent)
        if rich:
            row += [math.log1p(len(seen_users)), math.log1p(len(seen_agents)), math.log1p(max(t - t0, 0.0))]
        out[i] = row
        prev_t, prev_w = t, window
    return out


# ===========================================================================
# Forward del transformer en numpy
# ===========================================================================
def _layer_norm(x: np.ndarray, w: np.ndarray, b: np.ndarray, eps: float = 1e-5) -> np.ndarray:
    mean = x.mean(-1, keepdims=True)
    var = ((x - mean) ** 2).mean(-1, keepdims=True)
    return (x - mean) / np.sqrt(var + eps) * w + b


def _softmax(x: np.ndarray) -> np.ndarray:
    z = x - x.max(-1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(-1, keepdims=True)


class NumpyAttention:
    """Pesos de `AttentionBlocker` (torch) ejecutados con numpy. Una muestra por
    llamada: en despliegue se puntua una IP a la vez y no hay relleno."""

    def __init__(self, weights: Dict[str, np.ndarray], hyper: Dict[str, Any], norm: Dict[str, List[float]]):
        self.w = weights
        self.d, self.heads, self.layers = int(hyper["d"]), int(hyper["heads"]), int(hyper["layers"])
        self.max_len = int(self.w["pos.weight"].shape[0]) - 1
        self.tok_mean = np.asarray(norm["token_mean"], dtype=np.float32)
        self.tok_std = np.asarray(norm["token_std"], dtype=np.float32)
        self.ctx_mean = np.asarray(norm["ctx_mean"], dtype=np.float32)
        self.ctx_std = np.asarray(norm["ctx_std"], dtype=np.float32)

    @staticmethod
    def load_all(npz_path: str | Path, hyper: Dict[str, Any], norm: Dict[str, List[float]]) -> Dict[int, "NumpyAttention"]:
        """Un `.npz` con claves `K{k}__<param con '__' por '.'>` -> {k: modelo}."""
        groups: Dict[int, Dict[str, np.ndarray]] = {}
        with np.load(Path(npz_path)) as z:
            for key in z.files:
                prefix, name = key.split("__", 1)
                groups.setdefault(int(prefix[1:]), {})[name.replace("__", ".")] = z[key].astype(np.float32)
        return {k: NumpyAttention(w, hyper, norm) for k, w in sorted(groups.items())}

    def _linear(self, x: np.ndarray, name: str) -> np.ndarray:
        return x @ self.w[f"{name}.weight"].T + self.w[f"{name}.bias"]

    def _mha(self, x: np.ndarray, prefix: str) -> Tuple[np.ndarray, np.ndarray]:
        T, d = x.shape
        H, dh = self.heads, d // self.heads
        qkv = x @ self.w[f"{prefix}.in_proj_weight"].T + self.w[f"{prefix}.in_proj_bias"]
        q, k, v = (m.reshape(T, H, dh).transpose(1, 0, 2) for m in (qkv[:, :d], qkv[:, d:2 * d], qkv[:, 2 * d:]))
        att = _softmax(q @ k.transpose(0, 2, 1) / math.sqrt(dh))          # (H, T, T)
        out = (att @ v).transpose(1, 0, 2).reshape(T, d)
        return self._linear(out, f"{prefix}.out_proj"), att.mean(0)         # media de cabezas = torch

    def forward(self, tokens_raw: np.ndarray, ctx_raw: np.ndarray) -> Tuple[float, np.ndarray]:
        """Devuelve (score, atencion de la ficha de contexto sobre cada aviso)."""
        n = tokens_raw.shape[0]
        if n > self.max_len:
            raise ValueError(f"secuencia de {n} avisos; el modelo admite {self.max_len}")
        x = (tokens_raw.astype(np.float32) - self.tok_mean) / self.tok_std
        c = (np.asarray(ctx_raw, dtype=np.float32) - self.ctx_mean) / self.ctx_std
        h = np.concatenate([self._linear(c[None, :], "ctx"), self._linear(x, "tok")], axis=0)
        h = h + self.w["pos.weight"][: n + 1]
        att_last = None
        for i in range(self.layers):
            p = f"blocks.{i}"
            a, att_last = self._mha(_layer_norm(h, self.w[f"{p}.ln1.weight"], self.w[f"{p}.ln1.bias"]), f"{p}.attn")
            h = h + a
            f = _layer_norm(h, self.w[f"{p}.ln2.weight"], self.w[f"{p}.ln2.bias"])
            f = np.maximum(self._linear(f, f"{p}.ff.0"), 0.0)
            h = h + self._linear(f, f"{p}.ff.3")
        logit = float(self._linear(_layer_norm(h[0:1], self.w["ln_out.weight"], self.w["ln_out.bias"]), "head")[0, 0])
        return 1.0 / (1.0 + math.exp(-logit)), att_last[0, 1:]


# ===========================================================================
# Servicio: bloqueo temprano por atencion (misma interfaz que EarlyBlockScorer)
# ===========================================================================
def _attention_evidence(row: Dict[str, float], n: int, att: np.ndarray) -> Dict[str, Any]:
    top = [int(j + 1) for j in np.argsort(-att)[:3]]
    return {
        "usuarios_probados": int(row["n_users"]),
        "maquinas_alcanzadas": int(row["n_agents"]),
        "avisos": n,
        "reputacion_subred_24": round(float(row.get("sub24_hostile_ratio", 0.0)), 3),
        "avisos_decisivos": top,
        "atencion_por_aviso": [round(float(a), 3) for a in att],
    }


class AttentionBlockScorer:
    """Streaming: `ingest(alerta)` -> None o veredicto BLOCK. Reevalua en los
    presupuestos K configurados (un modelo por K) y bloquea al primer cruce del
    umbral de ese K."""

    def __init__(self, nets: Dict[int, NumpyAttention], thresholds: Dict[int, float],
                 rich: bool, ctx_features: List[str], state: LiveState):
        self.nets = nets
        self.thresholds = {k: thresholds[k] for k in nets if k in thresholds}
        self.budgets = sorted(self.thresholds)
        self.rich = rich
        self.ctx_features = ctx_features
        self.state = state
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.blocked: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def load(cls, models_dir: str | Path, state_path: str | Path | None = None,
             state: LiveState | None = None) -> "AttentionBlockScorer":
        models_dir = Path(models_dir)
        config = json.loads((models_dir / "config.json").read_text(encoding="utf-8"))
        section = config["attention_block"]
        nets = NumpyAttention.load_all(models_dir / section["weights_file"], section["hyper"], section["norm"])
        if state is None:
            if state_path is None:
                state_path = models_dir.parent / "state" / "live_state.json"
            state = (LiveState.from_json(Path(state_path).read_text(encoding="utf-8"))
                     if Path(state_path).exists() else LiveState())
        return cls(nets, {int(k): float(v) for k, v in section["thresholds"].items()},
                   section["token_set"] == "rich", section["ctx_features"], state)

    def score_events(self, events: List[Dict[str, Any]], context: Dict[str, float], k: int) -> Tuple[float, np.ndarray]:
        """Puntua (sin efectos) los primeros k eventos de un perfil ya normalizado por
        `ip_event`, con su contexto de subred: (score, atencion por aviso). Pensado para
        que un proceso que YA mantiene los perfiles (p. ej. el sidecar) pida una segunda
        opinion sin crear otro perfil ni tocar el estado vivo."""
        tokens = event_tokens(events, k, self.rich)
        ctx = np.array([context[f] for f in self.ctx_features], dtype=np.float32)
        return self.nets[k].forward(tokens, ctx)

    def ingest(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event = ip_event(alert)
        if event is None:
            return None
        ip = event["ip"]
        if ip in self.blocked:
            return None
        profile = self.profiles.get(ip)
        if profile is None:
            context = self.state.subnet_context(ip, event["t"])
            self.state.register_arrival(ip, event["t"])
            profile = self.profiles[ip] = {"events": [], "context": context}
        profile["events"].append(event)
        n = len(profile["events"])
        if n not in self.thresholds:
            return None
        score, att = self.score_events(profile["events"], profile["context"], n)
        if score < self.thresholds[n]:
            return None
        self.state.register_hostile(ip)
        row = early_ip_features(profile["events"], profile["context"])
        verdict = {
            "action": "BLOCK", "model": "attention", "ip": ip, "score": round(score, 4),
            "decided_at_alert": n, "threshold": self.thresholds[n],
            "evidence": _attention_evidence(row, n, att),
        }
        self.blocked[ip] = verdict
        return verdict

    def score_ip(self, ip: str) -> Optional[float]:
        profile = self.profiles.get(ip)
        if not profile:
            return None
        n = len(profile["events"])
        budget = max((k for k in self.thresholds if k <= n), default=None)
        if budget is None:
            return None
        return self.score_events(profile["events"], profile["context"], budget)[0]

    def save_state(self, path: str | Path) -> None:
        Path(path).write_text(self.state.to_json(), encoding="utf-8")


# ===========================================================================
# Consenso HGB + atencion sobre un unico estado y un unico perfil por IP
# ===========================================================================
class ConsensusBlockScorer:
    """Ejecuta los dos modelos sobre el mismo perfil de IP y aplica una politica:
      - "or"  : bloquea si cualquiera cruza su umbral (mas recall, algo menos de precision)
      - "and" : bloquea solo si ambos cruzan (mas precision, menos recall)
    Solo decide en los presupuestos K comunes a ambos modelos. Un solo
    `LiveState`: la reputacion de subred se actualiza una vez por IP. Las cifras
    medidas de cada politica estan en el README (seccion 2.4)."""

    def __init__(self, hgb_models: Dict[int, Any], hgb_thresholds: Dict[int, float], hgb_features: List[str],
                 attention: AttentionBlockScorer, mode: str = "or"):
        if mode not in {"or", "and"}:
            raise ValueError("mode debe ser 'or' o 'and'")
        self.hgb_models, self.hgb_thresholds, self.hgb_features = hgb_models, hgb_thresholds, hgb_features
        self.att = attention
        self.state = attention.state
        self.mode = mode
        self.budgets = sorted(set(hgb_models) & set(attention.thresholds))
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.blocked: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def load(cls, models_dir: str | Path, mode: str = "or",
             state_path: str | Path | None = None) -> "ConsensusBlockScorer":
        from .scorer import EarlyBlockScorer  # import tardio: evita ciclo
        hgb = EarlyBlockScorer.load(models_dir, state_path)
        att = AttentionBlockScorer.load(models_dir, state=hgb.state)
        return cls(hgb.models, hgb.thresholds, hgb.feature_order, att, mode)

    def _hgb_score(self, row: Dict[str, float], n: int) -> float:
        import pandas as pd
        frame = pd.DataFrame([[float(row.get(name, 0.0)) for name in self.hgb_features]], columns=self.hgb_features)
        return float(self.hgb_models[n].predict_proba(frame)[0, 1])

    def ingest(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event = ip_event(alert)
        if event is None:
            return None
        ip = event["ip"]
        if ip in self.blocked:
            return None
        profile = self.profiles.get(ip)
        if profile is None:
            context = self.state.subnet_context(ip, event["t"])
            self.state.register_arrival(ip, event["t"])
            profile = self.profiles[ip] = {"events": [], "context": context}
        profile["events"].append(event)
        n = len(profile["events"])
        if n not in self.budgets:
            return None
        row = early_ip_features(profile["events"], profile["context"])
        s_hgb = self._hgb_score(row, n)
        s_att, att = self.att.score_events(profile["events"], profile["context"], n)
        fire_hgb, fire_att = s_hgb >= self.hgb_thresholds[n], s_att >= self.att.thresholds[n]
        fired = (fire_hgb or fire_att) if self.mode == "or" else (fire_hgb and fire_att)
        if not fired:
            return None
        self.state.register_hostile(ip)
        verdict = {
            "action": "BLOCK", "model": f"consensus_{self.mode}", "ip": ip,
            "score": round(max(s_hgb, s_att) if self.mode == "or" else min(s_hgb, s_att), 4),
            "scores": {"hgb": round(s_hgb, 4), "attention": round(s_att, 4)},
            "fired": [m for m, f in (("hgb", fire_hgb), ("attention", fire_att)) if f],
            "decided_at_alert": n,
            "thresholds": {"hgb": self.hgb_thresholds[n], "attention": self.att.thresholds[n]},
            "evidence": _attention_evidence(row, n, att),
        }
        self.blocked[ip] = verdict
        return verdict

    def save_state(self, path: str | Path) -> None:
        Path(path).write_text(self.state.to_json(), encoding="utf-8")
