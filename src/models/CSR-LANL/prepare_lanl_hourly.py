#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CSR-LANL: agregacion horaria por maquina de origen, contra ground truth real.

Por que este dataset cierra la tesis
------------------------------------
Toda la linea ARGOS-LAB trabaja con etiquetas heuristicas y lo declara como su
limitacion central. LANL trae lo que falta: `redteam.txt`, el registro de
autenticaciones de compromiso de un red team real. La etiqueta procede de una
fuente INDEPENDIENTE del flujo de eventos (el log del equipo rojo, no una regla
sobre los propios eventos), de modo que la circularidad que invalido la
etiqueta debil de Wazuh es aqui imposible por construccion.

Diseno (metodologia ARGOS transplantada)
----------------------------------------
  unidad    : (maquina origen, hora). El red team opera desde 4 maquinas; una
              celda es positiva si contiene >=1 autenticacion del red team
              (91 celdas positivas en 58 dias -- aguja en pajar).
  filtro    : solo autenticaciones de usuarios reales (U*). Se excluyen cuentas
              de maquina (C*$) y ANONYMOUS LOGON, que son ~75 % del volumen y
              ruido computador-a-computador; los 749 eventos rojos son todos de
              usuarios U*.
  features  : volumen, diversidad, mezcla de protocolos y NOVEDAD CAUSAL
              (usuario nunca visto desde esa maquina; arista origen->destino
              nunca vista) -- el analogo exacto de las features de ARGOS.
  particion : temporal por dias, con actividad roja en train/val/test.

Salida: parquet de celdas + resumen. El entrenamiento vive en
`train_lanl_redteam.py`.

Uso:
    python prepare_lanl_hourly.py
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

AUTH = Path("out/CSR-LANL/auth.txt.gz")
REDTEAM = Path("out/CSR-LANL/redteam.txt.gz")
OUT = Path("src/models/CSR-LANL/datasets/hourly")

SET_CAP = 512          # tope de cardinalidad por celda (con contador de exceso)

FEATURES = [
    "n_events", "log_n_events", "n_fail", "fail_ratio",
    "n_users", "n_dsts", "users_per_event", "dsts_per_event", "events_per_dst",
    "ntlm_ratio", "kerberos_ratio", "unknown_auth_ratio",
    "network_ratio", "service_batch_ratio",
    "logon_ratio", "tgs_tgt_ratio",
    "new_user_src_count", "new_user_src_ratio",
    "new_edge_count", "new_edge_ratio",
    "new_user_dst_count", "new_user_dst_ratio",
    "hour_of_day", "day_of_week",
    "src_hours_active", "src_prev_hour_events",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


class Cell:
    __slots__ = ("n", "fail", "users", "dsts", "ntlm", "kerb", "unk", "network",
                 "svc", "logon", "tgstgt", "new_user_src", "new_edge", "new_user_dst")

    def __init__(self) -> None:
        self.n = 0
        self.fail = 0
        self.users: set = set()
        self.dsts: set = set()
        self.ntlm = self.kerb = self.unk = 0
        self.network = self.svc = 0
        self.logon = self.tgstgt = 0
        self.new_user_src = self.new_edge = self.new_user_dst = 0


def main() -> None:
    parser = argparse.ArgumentParser(description="LANL auth -> celdas (src, hora)")
    parser.add_argument("--max_rows", type=int, default=0, help="0 = fichero completo")
    parser.add_argument("--progress_every", type=int, default=50_000_000)
    args = parser.parse_args()

    root = repo_root()
    out = root / OUT
    out.mkdir(parents=True, exist_ok=True)

    # ---------------- ground truth ------------------------------------------
    red_cells: set = set()
    red_meta = defaultdict(list)
    with gzip.open(root / REDTEAM, "rt") as handle:
        for line in handle:
            parts = line.strip().split(",")
            if len(parts) < 4:
                continue
            hour = int(parts[0]) // 3600
            red_cells.add((parts[2], hour))
            red_meta[(parts[2], hour)].append(parts[1])
    print(f"red team: {len(red_cells)} celdas (src,hora) positivas")

    # ---------------- pasada unica sobre auth.txt ---------------------------
    cells: dict = {}
    seen_user_src: set = set()      # usuario|src   (novedad causal)
    seen_edge: set = set()          # src|dst
    seen_user_dst: set = set()      # usuario|dst
    src_hours: dict = {}            # src -> horas activas acumuladas
    src_prev: dict = {}             # src -> (hora_anterior, eventos)

    t0 = time.time()
    n_read = n_kept = 0
    with gzip.open(root / AUTH, "rt") as handle:
        for line in handle:
            n_read += 1
            if args.max_rows and n_read > args.max_rows:
                break
            if args.progress_every and n_read % args.progress_every == 0:
                rate = n_read / (time.time() - t0) / 1e6
                print(f"  ... {n_read/1e6:.0f}M leidas ({rate:.1f} M/s), "
                      f"{len(cells):,} celdas, {n_kept/1e6:.1f}M usadas", flush=True)
            parts = line.rstrip("\n").split(",")
            if len(parts) != 9:
                continue
            src_user = parts[1]
            if src_user[0] != "U":            # solo usuarios reales
                continue
            n_kept += 1
            t = int(parts[0])
            hour = t // 3600
            src = parts[3]
            dst = parts[4]
            key = (src, hour)
            cell = cells.get(key)
            if cell is None:
                cell = cells[key] = Cell()
                hours = src_hours.get(src, 0)
                src_hours[src] = hours + 1
            cell.n += 1
            if parts[8] != "Success":
                cell.fail += 1
            if len(cell.users) < SET_CAP:
                cell.users.add(src_user)
            if len(cell.dsts) < SET_CAP:
                cell.dsts.add(dst)
            auth_type = parts[5]
            if auth_type == "NTLM":
                cell.ntlm += 1
            elif auth_type == "Kerberos":
                cell.kerb += 1
            elif auth_type == "?":
                cell.unk += 1
            logon_type = parts[6]
            if logon_type == "Network":
                cell.network += 1
            elif logon_type in ("Service", "Batch"):
                cell.svc += 1
            orient = parts[7]
            if orient == "LogOn":
                cell.logon += 1
            elif orient in ("TGS", "TGT"):
                cell.tgstgt += 1

            us = src_user + "|" + src
            if us not in seen_user_src:
                seen_user_src.add(us)
                cell.new_user_src += 1
            ed = src + "|" + dst
            if ed not in seen_edge:
                seen_edge.add(ed)
                cell.new_edge += 1
            ud = src_user + "|" + dst
            if ud not in seen_user_dst:
                seen_user_dst.add(ud)
                cell.new_user_dst += 1

    dt = time.time() - t0
    print(f"leidas {n_read/1e6:.0f}M, usadas {n_kept/1e6:.1f}M en {dt/60:.1f} min "
          f"-> {len(cells):,} celdas")

    # ---------------- materializar ------------------------------------------
    rows = []
    for (src, hour), cell in cells.items():
        n = cell.n
        prev_hour, prev_events = src_prev.get(src, (None, 0.0))
        rows.append({
            "src_computer": src,
            "hour": hour,
            "day": hour // 24,
            "red": int((src, hour) in red_cells),
            "red_users": ",".join(sorted(set(red_meta.get((src, hour), []))))[:120],
            "n_events": float(n),
            "log_n_events": math.log1p(n),
            "n_fail": float(cell.fail),
            "fail_ratio": cell.fail / n,
            "n_users": float(len(cell.users)),
            "n_dsts": float(len(cell.dsts)),
            "users_per_event": len(cell.users) / n,
            "dsts_per_event": len(cell.dsts) / n,
            "events_per_dst": n / max(len(cell.dsts), 1),
            "ntlm_ratio": cell.ntlm / n,
            "kerberos_ratio": cell.kerb / n,
            "unknown_auth_ratio": cell.unk / n,
            "network_ratio": cell.network / n,
            "service_batch_ratio": cell.svc / n,
            "logon_ratio": cell.logon / n,
            "tgs_tgt_ratio": cell.tgstgt / n,
            "new_user_src_count": float(cell.new_user_src),
            "new_user_src_ratio": cell.new_user_src / n,
            "new_edge_count": float(cell.new_edge),
            "new_edge_ratio": cell.new_edge / n,
            "new_user_dst_count": float(cell.new_user_dst),
            "new_user_dst_ratio": cell.new_user_dst / n,
            "hour_of_day": float(hour % 24),
            "day_of_week": float((hour // 24) % 7),
            "src_hours_active": 0.0,       # se rellena abajo en orden temporal
            "src_prev_hour_events": 0.0,
        })
    df = pd.DataFrame(rows).sort_values(["hour", "src_computer"]).reset_index(drop=True)

    # linea base causal por maquina, en orden temporal
    hours_seen: dict = {}
    prev_events: dict = {}
    hs = np.zeros(len(df)); pe = np.zeros(len(df))
    for i, (src, n) in enumerate(zip(df["src_computer"].to_numpy(), df["n_events"].to_numpy())):
        hs[i] = hours_seen.get(src, 0)
        pe[i] = prev_events.get(src, 0.0)
        hours_seen[src] = hs[i] + 1
        prev_events[src] = n
    df["src_hours_active"] = hs
    df["src_prev_hour_events"] = pe

    df.to_parquet(out / "cells.parquet", index=False)
    red_by_day = df[df.red == 1].groupby("day").size().to_dict()
    summary = {
        "rows_read": n_read, "rows_kept": n_kept, "cells": int(len(df)),
        "red_cells_present": int(df.red.sum()),
        "red_cells_expected": len(red_cells),
        "prevalence": float(df.red.mean()),
        "days": [int(df.day.min()), int(df.day.max())],
        "red_cells_by_day": {str(k): int(v) for k, v in sorted(red_by_day.items())},
        "features": FEATURES,
        "set_cap": SET_CAP,
        "nota": ("Etiqueta de redteam.txt: fuente independiente del flujo de eventos. "
                 "Novedad y lineas base causales (solo pasado). Solo usuarios U*."),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"celdas rojas presentes: {int(df.red.sum())}/{len(red_cells)}  "
          f"prevalencia: {df.red.mean():.2e}")
    print(f"rojas por dia: {summary['red_cells_by_day']}")
    print(f"Guardado: {out}")


if __name__ == "__main__":
    main()
