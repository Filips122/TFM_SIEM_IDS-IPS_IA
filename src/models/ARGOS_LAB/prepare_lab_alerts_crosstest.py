#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adaptador: alertas Wazuh crudas de LAB-ALERTS -> esquema plano de ARGOS-LAB.

Proposito
---------
LAB-ALERTS procede de un segundo entorno (11 horas, 9 agentes, incluidos hosts
Windows y un servidor web) en el formato anidado nativo de Wazuh. Este adaptador
lo convierte al esquema plano que consume `prepare_dataset.py`, de modo que toda
la canalizacion de ARGOS-LAB -- ventanas, variables, etiquetas de bloqueo por
conducta -- se le aplique sin cambios.

El objetivo es el experimento de validacion externa: un modelo de bloqueo
entrenado en ARGOS-LAB, evaluado sobre hosts que jamas ha visto, de otro
entorno, con la MISMA politica de etiquetado aplicada a ambos lados. Si las
politicas difirieran, el cruce mediria el desacuerdo entre dos etiquetadores,
no deteccion.

Diferencias del origen que el adaptador absorbe:

  - formato anidado (`rule.groups`, `agent.id`, `data.srcip`) -> plano
  - sin `window_start` precalculado -> se deriva del timestamp (suelo de 1 min, UTC)
  - sin enriquecimiento geografico -> campos geo vacios (por eso el experimento
    de cruce usa un regimen sin variables geograficas)
  - sin `weak_label` -> se aplica la politica de ARGOS-LAB (documentada abajo);
    la etiqueta de bloqueo por conducta NO depende de ella

Este fichero es nuevo y no modifica ningun script existente.

Uso:
    python prepare_lab_alerts_crosstest.py
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_IN = Path("out/LAB-ALERTS/alerts.json")
DEFAULT_OUT = Path("src/models/ARGOS_LAB/datasets/crosstest/lab-alerts_flat.jsonl")

# Politica de etiqueta debil de ARGOS-LAB (manifest: lab_alerts_weak_label_v1),
# reproducida sobre los grupos de regla. Solo se usa para poblar el campo
# `weak_label` que `prepare_dataset.py` espera; el experimento de bloqueo no la
# consulta.
ATTACK_GROUPS = {"authentication_failed", "authentication_failures", "invalid_login",
                 "access_control", "attack", "recon", "web_scan", "rootcheck"}
POSTURE_GROUPS = {"trivy", "sca", "vulnerability-detector", "syscheck", "syscheck_registry"}
OPERATIONAL_GROUPS = {"local", "systemd", "docker", "docker-error", "dpkg", "ossec",
                      "config_changed", "wazuh", "agent_flooding", "windows_system"}


def clean(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"", "nan", "none", "null"} else text


def weak_label(groups: set[str], level: int) -> str:
    if groups & ATTACK_GROUPS:
        return "ATTACK"
    if groups & POSTURE_GROUPS:
        return "BENIGN"
    if groups & OPERATIONAL_GROUPS:
        return "BENIGN"
    if level >= 8:
        return "ATTACK"
    if level <= 4:
        return "BENIGN"
    return "UNKNOWN"


def main() -> None:
    parser = argparse.ArgumentParser(description="LAB-ALERTS crudo -> esquema plano ARGOS-LAB")
    parser.add_argument("--in_file", default=str(DEFAULT_IN))
    parser.add_argument("--out_file", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[3]
    src = (repo / args.in_file).resolve()
    dst = (repo / args.out_file).resolve()
    dst.parent.mkdir(parents=True, exist_ok=True)
    if not src.exists():
        raise SystemExit(f"No existe: {src}")

    print("== prepare_lab_alerts_crosstest ==")
    print(f"Entrada : {src}")
    print(f"Salida  : {dst}")

    n = bad = no_ts = 0
    agents: dict[str, int] = {}
    labels: dict[str, int] = {}
    with src.open(encoding="utf-8", errors="replace") as fin, \
         dst.open("w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue

            ts_text = clean(raw.get("timestamp"))
            try:
                ts = datetime.fromisoformat(ts_text.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                no_ts += 1
                continue
            window = ts.replace(second=0, microsecond=0)

            rule = raw.get("rule") or {}
            agent = raw.get("agent") or {}
            decoder = raw.get("decoder") or {}
            predecoder = raw.get("predecoder") or {}
            data = raw.get("data") or {}
            if not isinstance(data, dict):
                data = {}
            mitre = rule.get("mitre") or {}
            groups = [clean(g) for g in (rule.get("groups") or []) if clean(g)]
            group_set = {g.lower() for g in groups}
            try:
                level = int(float(rule.get("level") or 0))
            except (TypeError, ValueError):
                level = 0
            label = weak_label(group_set, level)

            flat = {
                "alert_id": clean(raw.get("id")),
                "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "window_start": window.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "rule_id": clean(rule.get("id")),
                "rule_level": level,
                "rule_description": clean(rule.get("description")),
                "rule_firedtimes": int(rule.get("firedtimes") or 1),
                "rule_groups": groups,
                "mitre_tactics": [clean(t) for t in (mitre.get("tactic") or []) if clean(t)],
                "mitre_techniques": [clean(t) for t in (mitre.get("technique") or []) if clean(t)],
                "agent_id": clean(agent.get("id")) or "Unknown",
                "agent_name": clean(agent.get("name")),
                "agent_ip": clean(agent.get("ip")),
                "src_ip": clean(data.get("srcip")),
                "src_port": clean(data.get("srcport")),
                "src_user": clean(data.get("srcuser")),
                "dst_user": clean(data.get("dstuser")),
                "dst_port": "",
                "decoder_name": clean(decoder.get("name")),
                "program_name": clean(predecoder.get("program_name")),
                "location": clean(raw.get("location")),
                "full_log": "",
                "geo_country": "",
                "geo_city": "",
                "geo_lat": None,
                "geo_lon": None,
                "has_src_ip": 1 if clean(data.get("srcip")) else 0,
                "has_src_port": 1 if clean(data.get("srcport")) else 0,
                "is_simulated": 0,
                "weak_label": label,
                "weak_label_reason": "argos_policy_reapplied",
                "taxonomy_label": "OtherAlert",
            }
            fout.write(json.dumps(flat, ensure_ascii=False) + "\n")
            n += 1
            agents[flat["agent_id"]] = agents.get(flat["agent_id"], 0) + 1
            labels[label] = labels.get(label, 0) + 1

    print(f"Convertidas : {n:,}  (json invalido {bad}, sin timestamp {no_ts})")
    print(f"Agentes     : {dict(sorted(agents.items(), key=lambda kv: -kv[1]))}")
    print(f"Etiquetas   : {labels}")
    print("\nSiguientes pasos:")
    print("  python prepare_dataset.py --in_file src/models/ARGOS_LAB/datasets/crosstest/lab-alerts_flat.jsonl \\")
    print("      --out_dir src/models/ARGOS_LAB/datasets/crosstest --dataset LAB-ALERTS-X --split_mode date")
    print("  python build_block_labels.py --in_file src/models/ARGOS_LAB/datasets/crosstest/lab-alerts_flat.jsonl \\")
    print("      --out_dir src/models/ARGOS_LAB/datasets/crosstest/block_labels")


if __name__ == "__main__":
    main()
