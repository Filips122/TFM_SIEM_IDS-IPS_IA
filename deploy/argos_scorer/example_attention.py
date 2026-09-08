#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Demo del puntuador de ATENCION y del consenso HGB+atencion sobre alertas reales.

Ejecutar desde esta carpeta (requiere que `models/attention_block.npz` exista;
se genera con `build_deploy_attention.py` en el repositorio de investigacion):
    python example_attention.py
"""

from __future__ import annotations

import json
from pathlib import Path

from argos_scorer import AttentionBlockScorer, ConsensusBlockScorer, EarlyBlockScorer

HERE = Path(__file__).resolve().parent


def run(name, scorer, alerts):
    verdicts = []
    for alert in alerts:
        verdict = scorer.ingest(alert)
        if verdict:
            verdicts.append(verdict)
    print(f"== {name}: {len(verdicts)} IPs bloqueadas de {len(scorer.profiles)} vistas ==")
    for v in verdicts[:4]:
        ev = v["evidence"]
        extra = f"  avisos decisivos={ev['avisos_decisivos']}" if "avisos_decisivos" in ev else ""
        fired = f"  disparo={v['fired']}" if "fired" in v else ""
        print(f"  BLOCK {v['ip']:<16} score={v['score']:.3f} al aviso #{v['decided_at_alert']}"
              f"  (usuarios={ev['usuarios_probados']}, maquinas={ev['maquinas_alcanzadas']}){extra}{fired}")
    return {v["ip"] for v in verdicts}


def main() -> None:
    alerts = [json.loads(line) for line in
              (HERE / "sample_alerts.jsonl").read_text(encoding="utf-8").splitlines() if line]
    print(f"alertas de muestra: {len(alerts)}\n")

    # Cada puntuador con su propia copia del estado caliente (no se persiste en la demo).
    hgb = run("EarlyBlockScorer (HGB, el principal)", EarlyBlockScorer.load(HERE / "models"), alerts)
    att = run("AttentionBlockScorer (Transformer, numpy)", AttentionBlockScorer.load(HERE / "models"), alerts)
    both = run("ConsensusBlockScorer mode='or'", ConsensusBlockScorer.load(HERE / "models", mode="or"), alerts)
    strict = run("ConsensusBlockScorer mode='and'", ConsensusBlockScorer.load(HERE / "models", mode="and"), alerts)

    print("\nacuerdo entre HGB y atencion:")
    print(f"  ambos bloquean : {len(hgb & att)}")
    print(f"  solo HGB       : {len(hgb - att)}")
    print(f"  solo atencion  : {len(att - hgb)}")
    print(f"  OR = {len(both)}  AND = {len(strict)}")
    print("\nLos scores de la demo son ilustrativos (alertas del periodo de entrenamiento). "
          "Las garantias medidas estan en el README, seccion 2.4.")


if __name__ == "__main__":
    main()
