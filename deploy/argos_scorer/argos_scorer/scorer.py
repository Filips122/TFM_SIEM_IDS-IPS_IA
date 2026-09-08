# -*- coding: utf-8 -*-
"""Puntuadores ARGOS listos para produccion.

Tres servicios sobre los modelos entrenados en el TFM (todas las cifras estan
justificadas en el README de este paquete):

  EarlyBlockScorer   EL PRINCIPAL. Streaming: se le pasan alertas una a una y
                     decide bloquear una IP en cuanto hay evidencia suficiente
                     (validado: recall 0,990 / precision 0,995 interno;
                     0,994 externo; mediana de corte al 5o aviso).

  WindowBlockScorer  Puntua una ventana (minuto x agente) completa: P(BLOCK).

  ActivityScorer     Clasifica la familia de actividad de una ventana por
                     host, con score de ataque calibrado y rechazo de
                     actividad desconocida.

Uso minimo:

    from argos_scorer.scorer import EarlyBlockScorer
    scorer = EarlyBlockScorer.load("models")     # carpeta models/ del paquete
    verdict = scorer.ingest(alert_dict)          # por cada alerta Wazuh
    if verdict and verdict["action"] == "BLOCK":
        firewall_drop(verdict["ip"])             # tu integracion
"""

from __future__ import annotations

import json
import warnings

# Algunos modelos se ajustaron con matrices sin nombres y otros con DataFrame;
# sklearn avisa de la mezcla aunque el ORDEN de columnas (que es lo que importa
# y viene de config.json) sea identico. Cosmetico: se silencia solo ese aviso.
warnings.filterwarnings("ignore", message=".*feature names.*", category=UserWarning)
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

from .features import (
    LiveState,
    clean,
    early_ip_features,
    ip_event,
    window_features,
)


def _vector(row: Dict[str, float], order: List[str]) -> "pd.DataFrame":
    return pd.DataFrame([[float(row.get(name, 0.0)) for name in order]], columns=order)


def _load_state(models_dir: Path, state: "LiveState | None") -> LiveState:
    """Estado caliente por defecto: sin el, las variables de novedad ven todo
    como nuevo y el puntuador de ventanas trabaja fuera de su distribucion."""
    if state is not None:
        return state
    path = models_dir.parent / "state" / "live_state.json"
    return LiveState.from_json(path.read_text(encoding="utf-8")) if path.exists() else LiveState()


# ===========================================================================
# 1) Bloqueo temprano por IP — politica secuencial
# ===========================================================================
class EarlyBlockScorer:
    """Decide bloquear una direccion con sus primeros avisos.

    Politica secuencial validada: se reevalua en cada presupuesto K
    (1,2,3,5,10,20 avisos) y se bloquea al primer cruce del umbral de ese K
    (umbrales fijados a precision >= 0,99 en validacion). Mas alla del ultimo
    presupuesto la IP queda con su veredicto (el 99,5 % de las bloqueables ya
    cayo antes).
    """

    def __init__(self, models: Dict[int, Any], thresholds: Dict[int, float],
                 feature_order: List[str], state: LiveState):
        self.models = models
        self.thresholds = thresholds
        self.feature_order = feature_order
        self.state = state
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.blocked: Dict[str, Dict[str, Any]] = {}

    # ---- carga ----
    @classmethod
    def load(cls, models_dir: str | Path, state_path: str | Path | None = None) -> "EarlyBlockScorer":
        models_dir = Path(models_dir)
        config = json.loads((models_dir / "config.json").read_text(encoding="utf-8"))
        budgets = config["early_block"]["budgets"]
        models = {int(k): joblib.load(models_dir / f"early_block_K{k}.joblib") for k in budgets}
        thresholds = {int(k): float(v) for k, v in config["early_block"]["thresholds"].items()}
        if state_path is None:
            state_path = models_dir.parent / "state" / "live_state.json"
        state = (LiveState.from_json(Path(state_path).read_text(encoding="utf-8"))
                 if Path(state_path).exists() else LiveState())
        return cls(models, thresholds, config["early_block"]["features"], state)

    # ---- streaming ----
    def ingest(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Procesa una alerta. Devuelve un veredicto cuando hay decision nueva
        (BLOCK) o None. Las alertas sin origen de red se ignoran."""
        event = ip_event(alert)
        if event is None:
            return None
        ip = event["ip"]
        if ip in self.blocked:
            return None                                  # ya decidido

        profile = self.profiles.get(ip)
        if profile is None:
            context = self.state.subnet_context(ip, event["t"])
            self.state.register_arrival(ip, event["t"])
            profile = self.profiles[ip] = {"events": [], "context": context}
        profile["events"].append(event)
        n = len(profile["events"])
        if n not in self.models:
            return None

        row = early_ip_features(profile["events"], profile["context"])
        score = float(self.models[n].predict_proba(_vector(row, self.feature_order))[0, 1])
        if score < self.thresholds[n]:
            return None

        self.state.register_hostile(ip)                  # alimenta la reputacion de subred
        verdict = {
            "action": "BLOCK",
            "ip": ip,
            "score": round(score, 4),
            "decided_at_alert": n,
            "threshold": self.thresholds[n],
            "evidence": {
                "usuarios_probados": int(row["n_users"]),
                "maquinas_alcanzadas": int(row["n_agents"]),
                "avisos": n,
                "reputacion_subred_24": round(row.get("sub24_hostile_ratio", 0.0), 3),
            },
        }
        self.blocked[ip] = verdict
        return verdict

    def score_ip(self, ip: str) -> Optional[float]:
        """Score actual de una IP con su mejor presupuesto disponible."""
        profile = self.profiles.get(ip)
        if not profile:
            return None
        n = len(profile["events"])
        budget = max((k for k in self.models if k <= n), default=None)
        if budget is None:
            return None
        row = early_ip_features(profile["events"][:budget], profile["context"])
        return float(self.models[budget].predict_proba(_vector(row, self.feature_order))[0, 1])

    def save_state(self, path: str | Path) -> None:
        Path(path).write_text(self.state.to_json(), encoding="utf-8")


# ===========================================================================
# 2) Puntuador de bloqueo por ventana
# ===========================================================================
class WindowBlockScorer:
    """P(BLOCK) para una ventana (minuto x agente) de alertas."""

    def __init__(self, model: Any, feature_order: List[str], classes: List[str], state: LiveState):
        self.model = model
        self.feature_order = feature_order
        self.block_index = classes.index("BLOCK")
        self.state = state

    @classmethod
    def load(cls, models_dir: str | Path, state: LiveState | None = None) -> "WindowBlockScorer":
        models_dir = Path(models_dir)
        config = json.loads((models_dir / "config.json").read_text(encoding="utf-8"))
        model = joblib.load(models_dir / "window_block.joblib")
        return cls(model, config["window_block"]["features"],
                   config["window_block"]["classes"], _load_state(models_dir, state))

    def score(self, alerts: List[Dict[str, Any]], agent_id: str) -> Dict[str, Any]:
        row = window_features(alerts, agent_id, self.state)
        proba = self.model.predict_proba(_vector(row, self.feature_order))[0]
        return {"block_score": round(float(proba[self.block_index]), 4),
                "n_alerts": len(alerts), "agent_id": agent_id}


# ===========================================================================
# 3) Clasificador de actividad por host con rechazo
# ===========================================================================
class ActivityScorer:
    """Familia de actividad + score de ataque calibrado + rechazo OOD.

    Un modelo por host conocido y reserva global (medido: los modelos NO
    transfieren entre hosts con esta etiqueta; un host nuevo debe acumular
    historial y reentrenarse -- mientras tanto la reserva global es orientativa).
    """

    def __init__(self, bundle: Dict[str, Any], feature_order: List[str],
                 hostile: List[str], state: LiveState):
        self.hosts = bundle["hosts"]                # host -> {model, classes, reject}
        self.fallback = bundle["global"]
        self.feature_order = feature_order
        self.hostile = set(hostile)
        self.state = state

    @classmethod
    def load(cls, models_dir: str | Path, state: LiveState | None = None) -> "ActivityScorer":
        models_dir = Path(models_dir)
        config = json.loads((models_dir / "config.json").read_text(encoding="utf-8"))
        bundle = joblib.load(models_dir / "activity_scorer.joblib")
        return cls(bundle, config["activity"]["features"],
                   config["activity"]["hostile_families"], _load_state(models_dir, state))

    def score(self, alerts: List[Dict[str, Any]], agent_id: str) -> Dict[str, Any]:
        row = window_features(alerts, agent_id, self.state)
        entry = self.hosts.get(str(agent_id), self.fallback)
        proba = entry["model"].predict_proba(_vector(row, self.feature_order))[0]
        classes = entry["classes"]
        hostile_mass = float(sum(p for p, c in zip(proba, classes) if c in self.hostile))
        best = int(np.argmax(proba))
        return {
            "attack_score": round(hostile_mass, 4),
            "family": classes[best],
            "confidence": round(float(proba[best]), 4),
            # tope 0,99: la calibracion isotonica satura en 1,0 y un umbral de
            # cuantil igual a 1,0 marcaria como desconocida casi toda ventana.
            "is_unknown": bool(proba[best] < min(entry["reject"], 0.99)),
            "model_used": "propio" if str(agent_id) in self.hosts else "global",
        }
