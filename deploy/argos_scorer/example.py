#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ejemplo completo de los tres puntuadores sobre alertas reales.

Ejecutar desde esta carpeta:
    python example.py
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from argos_scorer import ActivityScorer, EarlyBlockScorer, LiveState, WindowBlockScorer

HERE = Path(__file__).resolve().parent


def main() -> None:
    alerts = [json.loads(line) for line in
              (HERE / "sample_alerts.jsonl").read_text(encoding="utf-8").splitlines() if line]
    print(f"alertas de muestra: {len(alerts)}\n")

    # =====================================================================
    # 1) BLOQUEO TEMPRANO (streaming) — el servicio principal
    # =====================================================================
    print("== 1) EarlyBlockScorer: alerta a alerta ==")
    early = EarlyBlockScorer.load(HERE / "models")
    verdicts = []
    for alert in alerts:
        verdict = early.ingest(alert)
        if verdict:
            verdicts.append(verdict)
            if len(verdicts) <= 5:
                print(f"  BLOCK {verdict['ip']:<16} score={verdict['score']:.3f} "
                      f"al aviso #{verdict['decided_at_alert']}  "
                      f"(usuarios={verdict['evidence']['usuarios_probados']}, "
                      f"rep.subred={verdict['evidence']['reputacion_subred_24']})")
    print(f"  ... total: {len(verdicts)} IPs bloqueadas de "
          f"{len(early.profiles)} vistas con origen de red")
    early.save_state(HERE / "state" / "live_state.json")   # persistir aprendizaje

    # =====================================================================
    # 2) PUNTUADOR DE VENTANA — P(BLOCK) de un minuto de un agente
    # =====================================================================
    print("\n== 2) WindowBlockScorer: por ventana (minuto x agente) ==")
    window = WindowBlockScorer.load(HERE / "models")       # carga estado caliente
    grouped = defaultdict(list)
    for alert in alerts:
        grouped[(alert.get("window_start"), alert.get("agent_id"))].append(alert)
    shown = 0
    for (window_start, agent_id), group in grouped.items():
        if not any(a.get("src_ip") for a in group):
            continue                                       # sin origen de red no hay decision
        result = window.score(group, str(agent_id))
        if shown < 4:
            print(f"  {window_start} agente {agent_id}: "
                  f"P(BLOCK)={result['block_score']:.3f}  ({result['n_alerts']} alertas)")
        shown += 1
    print(f"  ... {shown} ventanas puntuadas")

    # =====================================================================
    # 3) ACTIVIDAD POR HOST — familia + score de ataque + rechazo
    # =====================================================================
    print("\n== 3) ActivityScorer: familia de actividad con rechazo ==")
    activity = ActivityScorer.load(HERE / "models")        # estado caliente
    shown = 0
    for (window_start, agent_id), group in grouped.items():
        result = activity.score(group, str(agent_id))
        if shown < 4:
            unknown = "  [DESCONOCIDA -> revisar]" if result["is_unknown"] else ""
            print(f"  {window_start} agente {agent_id}: {result['family']:<16} "
                  f"attack_score={result['attack_score']:.3f} "
                  f"conf={result['confidence']:.3f} ({result['model_used']}){unknown}")
        shown += 1
    print(f"  ... {shown} ventanas clasificadas")

    print("\nIntegracion web: instancia los scorers UNA vez al arrancar, llama a "
          "early.ingest(alerta) por cada alerta entrante y persiste el estado "
          "periodicamente con early.save_state(...).")


if __name__ == "__main__":
    main()
