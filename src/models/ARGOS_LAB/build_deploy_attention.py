#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Anade el puntuador de ATENCION al paquete de despliegue `deploy/argos_scorer/`.

No toca los modelos HGB ya empaquetados por `build_deploy_bundle.py`: entrena
un transformer por presupuesto K (los de `experiment_early_blocking_transformer.py`)
con el MISMO protocolo que el bloqueo temprano del paquete (split temporal por
primera aparicion de la IP, entrenamiento en train, umbral p99 por K fijado en
validacion, semilla 42), exporta todos los pesos a UN fichero numpy
(`attention_block.npz`, claves `K{k}__...`), escribe la seccion
`attention_block` en `models/config.json` y VERIFICA:

  1. que las fichas que construye el paquete (`argos_scorer.attention.event_tokens`,
     sobre los dicts de `ip_event`) son identicas a las del experimento;
  2. que el forward en numpy del paquete reproduce al modelo torch en las 719
     IPs de validacion y en todos los K (max |diff| < 1e-4), o aborta.

Ademas mide, sobre el test interno y con los HGB YA empaquetados, la politica
secuencial de cada servicio y de los consensos OR/AND, y lo deja en config.json
para que el README cite exactamente lo que se despliega.

Uso:
    python build_deploy_attention.py                          # base, K = 2 3 5 10 20
    python build_deploy_attention.py --budgets 1 2 3 5 10 20  # incluir K=1
    python build_deploy_attention.py --token_set rich
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np

from experiment_early_blocking import threshold_for_precision
from experiment_early_blocking_transformer import (
    HYPER, TRAIN, build_dataset, fit_per_k, predict, safe_auc, sequential_policy, slice_k, token_names,
)
from experiment_early_blocking_v2 import SUBNET_FEATURES, V2_FEATURES
from train_utils import get_device, repo_root, set_seed

DEPLOY = Path("deploy/argos_scorer")
ALL_BUDGETS = [1, 2, 3, 5, 10, 20]
TARGET_PRECISION = 0.99
SEED = 42
WEIGHTS_FILE = "attention_block.npz"


def fmt_seq(s: dict) -> str:
    return (f"recall {s['recall']:.3f} · precision {s['precision']:.3f} · FP {s['ips_legitimas_cortadas']} · "
            f"mediana K {s['aviso_mediano_de_bloqueo']} · evitado {s['avisos_evitados_pct']:.1%}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Empaqueta el transformer de bloqueo temprano")
    parser.add_argument("--token_set", choices=["base", "rich"], default="base")
    parser.add_argument("--budgets", type=int, nargs="+", default=[2, 3, 5, 10, 20],
                        help="presupuestos en los que decide el servicio de atencion")
    args = parser.parse_args()
    set_seed(SEED)
    device = get_device()
    root = repo_root()
    models_dir = root / DEPLOY / "models"
    config_path = models_dir / "config.json"
    if not config_path.exists():
        raise SystemExit("Falta models/config.json: ejecuta antes build_deploy_bundle.py")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    rich = args.token_set == "rich"
    budgets = sorted(args.budgets)

    # ------------------------------------------------------------ 1) entrenar
    t0 = time.time()
    print(f"== 1/4 entrenando un transformer por K {budgets} ({args.token_set}) ==", flush=True)
    data = build_dataset(ALL_BUDGETS, rich)          # tabular para TODOS los K (los HGB del paquete)
    y, part, lens = data["y"], data["part"], data["lens"]
    va, te = part == "val", part == "test"
    models, thresholds, per_k_test, dec_att = {}, {}, {}, {}
    for k in budgets:
        models[k] = fit_per_k(data, k, SEED, device)
        Xk, Lk = slice_k(data["X"], data["L"], k)
        s_va = predict(models[k], Xk[va], Lk[va], data["C"][va], device)
        s_te = predict(models[k], Xk[te], Lk[te], data["C"][te], device)
        thresholds[k] = threshold_for_precision(y[va], s_va, TARGET_PRECISION)
        dec_att[k] = s_te >= thresholds[k]
        tp, fp = int(np.sum(dec_att[k] & (y[te] == 1))), int(np.sum(dec_att[k] & (y[te] == 0)))
        per_k_test[k] = {"roc_auc": safe_auc(y[te], s_te), "recall_p99": tp / max(int(y[te].sum()), 1), "fp": fp}
        print(f"   K={k:<3} umbral={thresholds[k]:.4f}  AUC test={per_k_test[k]['roc_auc']:.4f}  "
              f"recall@p99={per_k_test[k]['recall_p99']:.3f}  FP={fp}")
    seq_att = sequential_policy(dec_att, y[te], lens[te])
    print(f"   atencion secuencial : {fmt_seq(seq_att)}  [{time.time() - t0:.0f}s]")

    # HGB ya empaquetados: misma particion, mismos IPs de test
    hgb_cfg = config["early_block"]
    dec_hgb = {}
    for k in hgb_cfg["budgets"]:
        model = joblib.load(models_dir / f"early_block_K{k}.joblib")
        s_te = model.predict_proba(data["tab"][k].loc[te, V2_FEATURES])[:, 1]
        dec_hgb[k] = s_te >= float(hgb_cfg["thresholds"][str(k)])
    seq_hgb = sequential_policy(dec_hgb, y[te], lens[te])
    common = sorted(set(dec_hgb) & set(dec_att))
    seq_or = sequential_policy({k: dec_hgb[k] | dec_att[k] for k in common}, y[te], lens[te])
    seq_and = sequential_policy({k: dec_hgb[k] & dec_att[k] for k in common}, y[te], lens[te])
    print(f"   HGB empaquetado     : {fmt_seq(seq_hgb)}")
    print(f"   consenso OR  (K {common}): {fmt_seq(seq_or)}")
    print(f"   consenso AND (K {common}): {fmt_seq(seq_and)}")

    # ------------------------------------------------------------- 2) exportar
    print("== 2/4 exportando pesos a numpy ==", flush=True)
    weights = {}
    for k, model in models.items():
        for name, tensor in model.state_dict().items():
            weights[f"K{k}__{name.replace('.', '__')}"] = tensor.detach().cpu().numpy().astype(np.float32)
    np.savez(models_dir / WEIGHTS_FILE, **weights)
    strip = {k: v for k, v in seq_att.items() if k != "por_agente_primer_aviso"}
    config["attention_block"] = {
        "weights_file": WEIGHTS_FILE,
        "budgets": budgets,
        "thresholds": {str(k): float(v) for k, v in thresholds.items()},
        "target_precision": TARGET_PRECISION,
        "token_set": args.token_set,
        "token_names": token_names(rich),
        "ctx_features": SUBNET_FEATURES,
        "hyper": HYPER,
        "train": TRAIN,
        "norm": data["norm"],
        "seed": SEED,
        "n_params_por_modelo": int(sum(v.size for k, v in weights.items() if k.startswith(f"K{budgets[0]}__"))),
        "test_interno": {
            "nota": "misma particion temporal que early_block; SIN validacion externa (presupuesto LAB-ALERTS gastado)",
            "por_K": {str(k): v for k, v in per_k_test.items()},
            "secuencial_atencion": strip,
            "secuencial_hgb_empaquetado": {k: v for k, v in seq_hgb.items() if k != "por_agente_primer_aviso"},
            "consenso_or": {k: v for k, v in seq_or.items() if k != "por_agente_primer_aviso"},
            "consenso_and": {k: v for k, v in seq_and.items() if k != "por_agente_primer_aviso"},
        },
        "validado": (f"R13 · test interno: AUC medio por K {np.mean([v['roc_auc'] for v in per_k_test.values()]):.4f}; "
                     f"secuencial recall {seq_att['recall']:.3f} / precision {seq_att['precision']:.3f}. "
                     f"Consenso OR {seq_or['recall']:.3f}/{seq_or['precision']:.3f}, AND {seq_and['recall']:.3f}/{seq_and['precision']:.3f}."),
    }

    # ------------------------------------------------------------ 3) verificar
    print("== 3/4 verificando el paquete contra torch ==", flush=True)
    sys.path.insert(0, str(root / DEPLOY))
    from argos_scorer.attention import NumpyAttention, event_tokens as deploy_tokens  # noqa: E402

    nets = NumpyAttention.load_all(models_dir / WEIGHTS_FILE, HYPER, data["norm"])
    assert sorted(nets) == budgets, f"presupuestos en el npz {sorted(nets)} != {budgets}"
    idx_va = np.where(va)[0]
    ctx_mean, ctx_std = np.array(data["norm"]["ctx_mean"]), np.array(data["norm"]["ctx_std"])
    max_tok_diff = max_score_diff = 0.0
    n_checked = 0
    for k in budgets:
        Xk, Lk = slice_k(data["X"], data["L"], k)
        s_torch = predict(models[k], Xk[idx_va], Lk[idx_va], data["C"][idx_va], device)
        for j, i in enumerate(idx_va):
            ip = data["ips"][i]
            events = [{"t": t, "agent": a, "user": u, "has_port": p, "window": w}
                      for (t, a, u, p, w) in data["histories"][ip]]
            tokens = deploy_tokens(events, k, rich)
            n = tokens.shape[0]
            max_tok_diff = max(max_tok_diff, float(np.abs(tokens - data["X_raw"][i, :n]).max()))
            ctx_raw = data["C"][i] * ctx_std + ctx_mean                 # deshacer la normalizacion
            score, att = nets[k].forward(tokens, ctx_raw)
            max_score_diff = max(max_score_diff, abs(score - float(s_torch[j])))
            assert 0.0 < att.sum() <= 1.0 + 1e-4 and len(att) == n   # fila CLS sin el peso CLS->CLS
            n_checked += 1
    print(f"   fichas: max |paquete - experimento| = {max_tok_diff:.2e}")
    print(f"   scores: max |numpy - torch| = {max_score_diff:.2e}  ({n_checked:,} evaluaciones)")
    if max_tok_diff > 1e-5 or max_score_diff > 1e-4:
        raise SystemExit("VERIFICACION FALLIDA: el paquete no reproduce al modelo entrenado")
    config["attention_block"]["verificacion"] = {
        "max_diff_fichas": max_tok_diff, "max_diff_scores": max_score_diff, "evaluaciones": n_checked}

    # -------------------------------------------------------------- 4) escribir
    print("== 4/4 escribiendo config.json ==", flush=True)
    config["version"] = "1.1"
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    size_kb = (models_dir / WEIGHTS_FILE).stat().st_size / 1e3
    print(f"\n{WEIGHTS_FILE}: {size_kb:.0f} KB, {len(models)} modelos x "
          f"{config['attention_block']['n_params_por_modelo']:,} parametros. Paquete en {root / DEPLOY}")


if __name__ == "__main__":
    main()
