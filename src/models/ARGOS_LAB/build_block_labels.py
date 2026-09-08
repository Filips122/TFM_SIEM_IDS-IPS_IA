#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Etiqueta de bloqueo derivada de la conducta observada del origen.

Motivacion
----------
Toda etiqueta disponible en este corpus procede del motor de reglas de Wazuh:
`rule_groups`, `rule_level`, `mitre_tactics`, `decoder_name` son campos de la
misma regla. Entrenar con ellas y evaluarlas contra si mismas es circular, y se
midio: una sola columna reproduce la etiqueta binaria con ROC-AUC 0,9990.

Sustituir el criterio por el nivel de gravedad no resuelve nada -- el nivel sale
del mismo motor, y ademas esta invertido en este corpus: los hallazgos de Trivy
son nivel 12-14 y la fuerza bruta real es nivel 5, de modo que "nivel >= 10 =>
ataque" clasificaria mal el 70,8 % de lo que captura.

Este modulo construye una etiqueta **independiente del motor de reglas**: si una
direccion de origen debe bloquearse, juzgado unicamente por lo que hizo. Los
unicos campos empleados son hechos observados que el decoder extrajo del texto
del registro, no veredictos de ninguna regla:

    src_ip, src_user, dst_user, agent_id, timestamp

Criterios de bloqueo
--------------------
Una IP merece bloqueo si exhibe conducta que ningun usuario legitimo exhibe:

  1. ENUMERACION   prueba >= `min_users` cuentas distintas
  2. AMPLITUD      alcanza >= `min_agents` maquinas independientes
  3. PERSISTENCIA  >= `min_alerts` intentos repartidos en >= `min_windows`
                   ventanas distintas

Cualquiera de los tres basta. Son condiciones sobre el *origen*, no sobre el
host atacado, de modo que transfieren entre maquinas por construccion -- a
diferencia de las variables de actividad, con las que se predice que agente es
con 99,75 % de exactitud.

Causalidad
----------
El perfil de cada IP se acumula **solo con el pasado**: una ventana en el
instante T se etiqueta con lo que sus IPs habian hecho hasta T. Sin esa
restriccion la etiqueta usaria informacion futura y el resultado seria
optimista.

Alcance
-------
Solo se etiquetan ventanas **con origen de red**. Una ventana sin `src_ip` no
admite decision de bloqueo: no hay nada que bloquear. Esto excluye por
construccion los hallazgos de escaner y el ruido del honeypot, que son la fuente
del confundido de host documentado en el README.

Uso:
    python build_block_labels.py
    python build_block_labels.py --min_users 8 --min_agents 2
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pandas as pd

DEFAULT_IN = Path("src/models/ARGOS_LAB/argos-alerts_30d.jsonl")
DEFAULT_OUT = Path("src/models/ARGOS_LAB/datasets/block_labels")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def resolve(path: str | Path) -> Path:
    p = Path(path).expanduser()
    return p.resolve() if p.is_absolute() else (repo_root() / p).resolve()


def clean(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in {"", "nan", "none", "null"} else text


def parse_ts(value: object) -> float:
    text = clean(value)
    if not text:
        return float("nan")
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return float("nan")


class IPProfile:
    """Conducta acumulada de una direccion de origen."""

    __slots__ = ("users", "agents", "windows", "alerts", "first_seen")

    def __init__(self) -> None:
        self.users: set[str] = set()
        self.agents: set[str] = set()
        self.windows: set[str] = set()
        self.alerts = 0
        self.first_seen = float("inf")

    def blockworthy(self, min_users: int, min_agents: int, min_alerts: int, min_windows: int) -> tuple[bool, str]:
        if len(self.users) >= min_users:
            return True, "enumeracion"
        if len(self.agents) >= min_agents:
            return True, "amplitud"
        if self.alerts >= min_alerts and len(self.windows) >= min_windows:
            return True, "persistencia"
        return False, ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Etiqueta de bloqueo por conducta del origen")
    parser.add_argument("--in_file", default=str(DEFAULT_IN))
    parser.add_argument("--out_dir", default=str(DEFAULT_OUT))
    parser.add_argument("--min_users", type=int, default=5, help="cuentas distintas => enumeracion")
    parser.add_argument("--min_agents", type=int, default=2, help="maquinas distintas => amplitud")
    parser.add_argument("--min_alerts", type=int, default=50, help="intentos => persistencia")
    parser.add_argument("--min_windows", type=int, default=3, help="ventanas distintas => persistencia")
    parser.add_argument("--block_ratio", type=float, default=0.5,
                        help="fraccion de alertas de la ventana procedentes de IPs bloqueables")
    parser.add_argument("--progress_every", type=int, default=300_000)
    args = parser.parse_args()

    src = resolve(args.in_file)
    if not src.exists():
        raise SystemExit(f"No existe el fichero de entrada: {src}")
    out = resolve(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("== build_block_labels (ARGOS-LAB) ==")
    print(f"Entrada  : {src}")
    print(f"Criterios: >={args.min_users} usuarios | >={args.min_agents} agentes | "
          f">={args.min_alerts} alertas en >={args.min_windows} ventanas")
    print("Recorriendo el flujo de alertas ...", flush=True)

    profiles: Dict[str, IPProfile] = defaultdict(IPProfile)
    # Por ventana: alertas totales, alertas de IPs ya bloqueables, motivos.
    windows: Dict[tuple, Dict[str, Any]] = {}
    counters = {"rows": 0, "with_ip": 0, "without_ip": 0}

    with src.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            counters["rows"] += 1
            if args.progress_every and counters["rows"] % args.progress_every == 0:
                print(f"  ... {counters['rows']:,} alertas", flush=True)
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            window_start = clean(alert.get("window_start"))
            agent = clean(alert.get("agent_id")) or "Unknown"
            if not window_start:
                continue
            key = (window_start, agent)
            cell = windows.get(key)
            if cell is None:
                cell = windows[key] = {"n": 0, "n_ip": 0, "n_block": 0, "reasons": defaultdict(int)}
            cell["n"] += 1

            ip = clean(alert.get("src_ip"))
            if not ip:
                counters["without_ip"] += 1
                continue
            counters["with_ip"] += 1

            # --- decision con el perfil ANTERIOR: solo pasado ---------------
            profile = profiles[ip]
            blocked, reason = profile.blockworthy(
                args.min_users, args.min_agents, args.min_alerts, args.min_windows
            )
            cell["n_ip"] += 1
            if blocked:
                cell["n_block"] += 1
                cell["reasons"][reason] += 1

            # --- ahora se actualiza el perfil -------------------------------
            user = (clean(alert.get("src_user")) or clean(alert.get("dst_user"))).lower()
            if user:
                profile.users.add(user)
            profile.agents.add(agent)
            profile.windows.add(window_start)
            profile.alerts += 1
            epoch = parse_ts(alert.get("timestamp"))
            if not np.isnan(epoch):
                profile.first_seen = min(profile.first_seen, epoch)

    print(f"Alertas  : {counters['rows']:,}  (con IP {counters['with_ip']:,}, "
          f"sin IP {counters['without_ip']:,})")

    rows = []
    for (window_start, agent), cell in windows.items():
        if cell["n_ip"] == 0:
            continue                      # sin origen de red: no hay decision de bloqueo
        ratio = cell["n_block"] / cell["n_ip"]
        reasons = cell["reasons"]
        rows.append({
            "window_start": pd.Timestamp(window_start),
            "agent_id": agent,
            "alerts": cell["n"],
            "alerts_with_ip": cell["n_ip"],
            "alerts_blockworthy": cell["n_block"],
            "block_ratio": ratio,
            "block_target": "BLOCK" if ratio >= args.block_ratio else "ALLOW",
            "reason": max(reasons, key=reasons.get) if reasons else "",
        })

    df = pd.DataFrame(rows).sort_values(["window_start", "agent_id"]).reset_index(drop=True)
    if df.empty:
        raise SystemExit("Ninguna ventana con origen de red: revisa los criterios")

    df.to_parquet(out / "block_labels.parquet", index=False)

    counts = df["block_target"].value_counts().to_dict()
    per_agent = pd.crosstab(df["agent_id"], df["block_target"])
    summary = {
        "criterios": {
            "min_users": args.min_users, "min_agents": args.min_agents,
            "min_alerts": args.min_alerts, "min_windows": args.min_windows,
            "block_ratio": args.block_ratio,
        },
        "ventanas_con_origen": int(len(df)),
        "distribucion": {str(k): int(v) for k, v in counts.items()},
        "por_agente": {str(a): {str(c): int(v) for c, v in row.items()} for a, row in per_agent.iterrows()},
        "motivos": {str(k): int(v) for k, v in df.loc[df.block_target == "BLOCK", "reason"].value_counts().items()},
        "ips_perfiladas": len(profiles),
        "nota": (
            "Etiqueta derivada unicamente de src_ip / src_user / dst_user / agent_id / timestamp. "
            "Ningun campo del motor de reglas interviene. El perfil de cada IP es causal: una "
            "ventana en T se juzga con lo que sus IPs habian hecho antes de T."
        ),
    }
    (out / "block_labels_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"\nVentanas con origen de red : {len(df):,}")
    print(f"Distribucion               : {counts}")
    minority = min(counts.values()) / sum(counts.values()) if len(counts) > 1 else 0.0
    print(f"Clase minoritaria          : {minority:.2%}")
    print(f"Motivos de bloqueo         : {summary['motivos']}")
    print("\nPor agente:")
    print(per_agent.to_string())
    print(f"\nGuardado: {out}")


if __name__ == "__main__":
    main()
