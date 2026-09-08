# -*- coding: utf-8 -*-
"""Construccion de variables en vivo para los puntuadores ARGOS.

Autocontenido: no depende de nada del repositorio de investigacion. Las listas
de variables y su ORDEN llegan desde `models/config.json`, exportado por el
mismo script que entreno los modelos, de modo que entrenamiento e inferencia no
pueden desalinearse.

Dos familias:

  - Variables de IP (bloqueo temprano): lo que hizo una direccion en sus
    primeros K avisos, mas la reputacion causal de su subred al llegar.
  - Variables de ventana (minuto x agente): agregados conductuales de las
    alertas de una ventana, con novedad y linea base por agente mantenidas en
    `LiveState` (equivalente en linea del preparador offline).

Toda la novedad es causal: el estado solo contiene pasado.
"""

from __future__ import annotations

import json
import math
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

EPS = 1e-9

SYSTEM_USERS = {
    "root", "admin", "administrator", "ubuntu", "debian", "centos", "oracle",
    "postgres", "mysql", "www-data", "test", "guest", "user", "deploy", "git",
    "ftp", "nagios", "jenkins", "docker", "pi", "operator", "support",
}


def clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"", "nan", "none", "null"} else text


def parse_epoch(value: Any) -> Optional[float]:
    text = clean(value)
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return None


def subnet(ip: str, octets: int) -> str:
    parts = ip.split(".")
    return ".".join(parts[:octets]) if len(parts) == 4 else ip


def shannon(counts: Dict[str, int]) -> tuple:
    total = sum(counts.values())
    if total <= 0:
        return 0.0, 0.0, 0.0
    entropy, top = 0.0, 0
    for v in counts.values():
        p = v / total
        entropy -= p * math.log(p + EPS)
        top = max(top, v)
    k = len(counts)
    return entropy, (entropy / math.log(k) if k > 1 else 0.0), top / total


# ===========================================================================
# Estado vivo compartido (serializable a JSON para sobrevivir reinicios)
# ===========================================================================
@dataclass
class LiveState:
    """Memoria causal del despliegue: reputacion de subred, perfiles de IP,
    linea base por agente y novedad global. Se exporta con estado inicial
    calculado sobre la captura de entrenamiento (arranque en caliente)."""

    # reputacion de subred: subred -> [ips_vistas, ips_hostiles]
    sub24: Dict[str, List[int]] = field(default_factory=dict)
    sub16: Dict[str, List[int]] = field(default_factory=dict)
    # llegadas recientes de IPs nuevas (epochs) para densidad de flota
    recent_arrivals: List[float] = field(default_factory=list)
    # novedad global (para variables de ventana)
    ip_freq: Dict[str, int] = field(default_factory=dict)
    seen_users: Dict[str, int] = field(default_factory=dict)
    # linea base por agente: agente -> lista [(n, uniq_ip)] de ultimas ventanas
    agent_hist: Dict[str, List[List[float]]] = field(default_factory=dict)
    agent_prev_ts: Dict[str, float] = field(default_factory=dict)
    agent_index: Dict[str, int] = field(default_factory=dict)
    roll: int = 15

    # ---- reputacion ----
    def subnet_context(self, ip: str, now: float) -> Dict[str, float]:
        s24 = self.sub24.get(subnet(ip, 3), [0, 0])
        s16 = self.sub16.get(subnet(ip, 2), [0, 0])
        self.recent_arrivals = [t for t in self.recent_arrivals if now - t <= 3600.0]
        return {
            "sub24_seen": float(s24[0]),
            "sub24_hostile": float(s24[1]),
            "sub24_hostile_ratio": s24[1] / s24[0] if s24[0] else 0.0,
            "sub16_seen": float(s16[0]),
            "sub16_hostile": float(s16[1]),
            "sub16_hostile_ratio": s16[1] / s16[0] if s16[0] else 0.0,
            "fleet_new_ips_last_hour": float(len(self.recent_arrivals)),
        }

    def register_arrival(self, ip: str, now: float) -> None:
        for octets, table in ((3, self.sub24), (2, self.sub16)):
            key = subnet(ip, octets)
            table.setdefault(key, [0, 0])[0] += 1
        self.recent_arrivals.append(now)

    def register_hostile(self, ip: str) -> None:
        for octets, table in ((3, self.sub24), (2, self.sub16)):
            table.setdefault(subnet(ip, octets), [0, 0])[1] += 1

    # ---- persistencia ----
    def to_json(self) -> str:
        return json.dumps({
            "sub24": self.sub24, "sub16": self.sub16,
            "recent_arrivals": self.recent_arrivals[-500:],
            "ip_freq": self.ip_freq, "seen_users": self.seen_users,
            "agent_hist": self.agent_hist, "agent_prev_ts": self.agent_prev_ts,
            "agent_index": self.agent_index, "roll": self.roll,
        })

    @classmethod
    def from_json(cls, text: str) -> "LiveState":
        data = json.loads(text)
        state = cls()
        for key, value in data.items():
            setattr(state, key, value)
        return state


# ===========================================================================
# Variables de IP (bloqueo temprano)
# ===========================================================================
def ip_event(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normaliza una alerta Wazuh (esquema plano ARGOS) a un evento de IP.
    Devuelve None si la alerta no tiene origen de red."""
    ip = clean(alert.get("src_ip"))
    if not ip:
        return None
    epoch = parse_epoch(alert.get("timestamp"))
    if epoch is None:
        return None
    user = (clean(alert.get("src_user")) or clean(alert.get("dst_user"))).lower()
    window = clean(alert.get("window_start")) or str(int(epoch // 60))
    return {
        "ip": ip, "t": epoch, "agent": clean(alert.get("agent_id")) or "?",
        "user": user, "has_port": bool(clean(alert.get("src_port"))),
        "window": window,
    }


def early_ip_features(events: List[Dict[str, Any]], context: Dict[str, float]) -> Dict[str, float]:
    """Las variables v2 del bloqueo temprano, sobre los eventos vistos."""
    n = len(events)
    times = [e["t"] for e in events]
    users = [e["user"] for e in events if e["user"]]
    uniq_users = len(set(users))
    uniq_agents = len({e["agent"] for e in events})
    uniq_windows = len({e["window"] for e in events})
    span = times[-1] - times[0] if n > 1 else 0.0
    gaps = [times[i + 1] - times[i] for i in range(n - 1)] or [0.0]
    mean_gap = sum(gaps) / len(gaps)
    var_gap = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
    std_gap = math.sqrt(var_gap)
    first_minute = sum(1 for t in times if t - times[0] <= 60.0)
    row = {
        "n_alerts": float(n),
        "n_users": float(uniq_users),
        "n_agents": float(uniq_agents),
        "n_windows": float(uniq_windows),
        "span_seconds": float(span),
        "mean_interarrival": float(mean_gap),
        "min_interarrival": float(min(gaps)),
        "alerts_per_user": float(n / max(uniq_users, 1)),
        "users_per_alert": float(uniq_users / n) if n else 0.0,
        "root_ratio": float(sum(u == "root" for u in users) / max(len(users), 1)),
        "system_user_ratio": float(sum(u in SYSTEM_USERS for u in users) / max(len(users), 1)),
        "port_present_ratio": float(sum(e["has_port"] for e in events) / n) if n else 0.0,
        "alerts_first_minute": float(first_minute),
        "std_interarrival": float(std_gap),
        "cv_interarrival": float(std_gap / (mean_gap + EPS)),
    }
    row.update(context)
    return row


# ===========================================================================
# Variables de ventana (minuto x agente) — version en linea
# ===========================================================================
def window_features(alerts: List[Dict[str, Any]], agent_id: str, state: LiveState) -> Dict[str, float]:
    """Agrega las alertas de UNA ventana de un agente a las 54 variables
    conductuales, actualizando el estado causal (novedad, linea base).

    Equivalente en linea del preparador offline: mismas definiciones; las
    variables de novedad/linea base usan exclusivamente el estado previo.
    """
    n = len(alerts)
    if n == 0:
        raise ValueError("ventana vacia")

    times = sorted(t for t in (parse_epoch(a.get("timestamp")) for a in alerts) if t is not None)
    span = times[-1] - times[0] if len(times) > 1 else 0.0
    gaps = [times[i + 1] - times[i] for i in range(len(times) - 1)] or [0.0]
    mean_ia = sum(gaps) / len(gaps)
    std_ia = math.sqrt(sum((g - mean_ia) ** 2 for g in gaps) / len(gaps))

    src_ip: Dict[str, int] = {}
    src_user: Dict[str, int] = {}
    src_port: Dict[str, int] = {}
    dst_user: Dict[str, int] = {}
    country: Dict[str, int] = {}
    cities = set()
    lat, lon = [], []
    ip_present = port_present = dstu_present = 0
    root_hits = system_hits = user_hits = 0

    for alert in alerts:
        ip = clean(alert.get("src_ip")); user = clean(alert.get("src_user"))
        port = clean(alert.get("src_port")); du = clean(alert.get("dst_user"))
        for key, table in ((ip, src_ip), (user, src_user), (port, src_port), (du, dst_user)):
            if key:
                table[key] = table.get(key, 0) + 1
        ip_present += bool(ip); port_present += bool(port); dstu_present += bool(du)
        account = (user or du).lower()
        if account:
            user_hits += 1
            root_hits += account == "root"
            system_hits += account in SYSTEM_USERS
        c = clean(alert.get("geo_country"))
        if c:
            country[c] = country.get(c, 0) + 1
        city = clean(alert.get("geo_city"))
        if city:
            cities.add(city)
        la, lo = alert.get("geo_lat"), alert.get("geo_lon")
        if isinstance(la, (int, float)) and isinstance(lo, (int, float)):
            lat.append(float(la)); lon.append(float(lo))

    ip_ent, ip_ent_n, ip_top = shannon(src_ip)
    us_ent, us_ent_n, us_top = shannon(src_user)
    _, port_ent_n, _ = shannon(src_port)
    _, co_ent_n, co_top = shannon(country)

    def _std(vals):
        if not vals:
            return 0.0
        m = sum(vals) / len(vals)
        return math.sqrt(sum((v - m) ** 2 for v in vals) / len(vals))

    lat_std, lon_std = _std(lat), _std(lon)
    uniq_ip = len(src_ip)

    # ---- novedad causal (estado global) ----
    new_ips = [ip for ip in src_ip if ip not in state.ip_freq]
    new_users = [u for u in src_user if u not in state.seen_users]
    prior = [state.ip_freq.get(ip, 0) for ip in src_ip]
    mean_seen = sum(prior) / len(prior) if prior else 0.0
    max_seen = float(max(prior)) if prior else 0.0
    for ip, c in src_ip.items():
        state.ip_freq[ip] = state.ip_freq.get(ip, 0) + c
    for u in src_user:
        state.seen_users[u] = state.seen_users.get(u, 0) + 1

    # ---- linea base por agente (causal) ----
    hist = state.agent_hist.setdefault(agent_id, [])
    counts = [h[0] for h in hist]; iphist = [h[1] for h in hist]
    lag1 = counts[-1] if counts else 0.0
    lag2 = counts[-2] if len(counts) > 1 else 0.0
    roll_mean = sum(counts) / len(counts) if counts else 0.0
    roll_std = _std(counts)
    count_z = (n - roll_mean) / roll_std if roll_std > 0 else 0.0
    ipm = sum(iphist) / len(iphist) if iphist else 0.0
    ips_ = _std(iphist)
    ip_z = (uniq_ip - ipm) / ips_ if ips_ > 0 else 0.0
    prev = state.agent_prev_ts.get(agent_id)
    gap = times[0] - prev if prev is not None else 0.0
    state.agent_prev_ts[agent_id] = times[-1]
    idx = state.agent_index.get(agent_id, 0)
    state.agent_index[agent_id] = idx + 1
    hist.append([float(n), float(uniq_ip)])
    if len(hist) > state.roll:
        del hist[0]

    return {
        "alert_count": float(n), "log_alert_count": math.log1p(n),
        "span_seconds": span, "alerts_per_second": n / max(span, 1.0),
        "mean_interarrival": mean_ia, "std_interarrival": std_ia,
        "min_interarrival": float(min(gaps)),
        "burstiness_index": std_ia / (mean_ia + EPS),
        "unique_src_ip": float(uniq_ip), "unique_src_user": float(len(src_user)),
        "unique_dst_user": float(len(dst_user)), "unique_src_port": float(len(src_port)),
        "src_ip_entropy": ip_ent, "src_ip_entropy_norm": ip_ent_n, "top_src_ip_share": ip_top,
        "src_user_entropy": us_ent, "src_user_entropy_norm": us_ent_n, "top_src_user_share": us_top,
        "src_port_entropy_norm": port_ent_n,
        "alerts_per_src_ip": n / max(uniq_ip, 1), "users_per_src_ip": len(src_user) / max(uniq_ip, 1),
        "ports_per_src_ip": len(src_port) / max(uniq_ip, 1),
        "alerts_per_src_user": n / max(len(src_user), 1),
        "src_ip_present_ratio": ip_present / n, "src_port_present_ratio": port_present / n,
        "dst_user_present_ratio": dstu_present / n,
        "unique_country": float(len(country)), "unique_city": float(len(cities)),
        "country_entropy_norm": co_ent_n, "top_country_share": co_top,
        "geo_missing_ratio": (n - len(lat)) / n,
        "geo_lat_mean": sum(lat) / len(lat) if lat else 0.0,
        "geo_lon_mean": sum(lon) / len(lon) if lon else 0.0,
        "geo_lat_std": lat_std, "geo_lon_std": lon_std,
        "geo_spread": math.sqrt(lat_std ** 2 + lon_std ** 2),
        "new_src_ip_count": float(len(new_ips)), "new_src_ip_ratio": len(new_ips) / max(uniq_ip, 1),
        "repeat_src_ip_ratio": (uniq_ip - len(new_ips)) / max(uniq_ip, 1),
        "new_src_user_count": float(len(new_users)),
        "new_src_user_ratio": len(new_users) / max(len(src_user), 1),
        "mean_src_ip_seen_before": mean_seen, "max_src_ip_seen_before": max_seen,
        "root_user_ratio": root_hits / max(user_hits, 1),
        "system_user_ratio": system_hits / max(user_hits, 1),
        "agent_gap_seconds": gap, "agent_count_lag1": lag1, "agent_count_lag2": lag2,
        "agent_count_roll_mean": roll_mean, "agent_count_roll_std": roll_std,
        "agent_count_z": count_z, "agent_uniqip_roll_mean": ipm, "agent_uniqip_z": ip_z,
        "agent_window_index": float(idx),
    }
