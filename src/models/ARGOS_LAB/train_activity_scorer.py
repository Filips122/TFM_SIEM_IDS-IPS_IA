#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Puntuador de ataque por host, calibrado y con rechazo de actividad desconocida.

Sustituye a la tarea binaria supervisada, que es circular: la etiqueta ATTACK /
BENIGN se deriva de `rule_groups`, y una sola columna la reproduce con ROC-AUC
0,9990. En su lugar se clasifica la **familia de actividad** -- la unica tarea
supervisada de este corpus que no esta saturada -- y el score de ataque es la
probabilidad acumulada de las familias hostiles.

Tres decisiones de diseno, cada una respaldada por una medicion:

1. UN MODELO POR HOST. Con las 54 features `behavioral` se predice que agente
   es con 99,75 % de exactitud, pese a que `agent_id` no esta entre ellas: cada
   maquina tiene una huella de actividad propia repartida por variables
   correlacionadas. Un modelo global aprende esa huella; entre hosts el MCC cae
   a 0,000. Dentro de un solo host la huella es constante, no aporta
   informacion, y el modelo se ve forzado a aprender conducta: el agente 011
   alcanza macro-F1 0,9654.

2. RECHAZO EN LUGAR DE DETECCION DE ANOMALIAS. Un clasificador no puede
   reconocer una familia que nunca vio, pero si puede declarar que no la
   reconoce. Se rechaza cuando la probabilidad maxima cae por debajo de un
   umbral fijado en validacion. Se prefiere al detector de anomalias porque
   este ultimo, medido por agente, no supera el azar (lift 0,57x-0,95x).

   El umbral de rechazo es el mando de coste operativo. Ocultando por completo
   la familia PortChange del entrenamiento y midiendo sobre test:

       cuantil   rechaza no vista   rechaza conocida   razon
        0,05          3,7 %              4,3 %         0,85x   (inutil)
        0,25         39,5 %             20,8 %         1,90x
        0,50         99,8 %             34,4 %         2,90x

   Se adopta 0,25 por defecto; un SOC que priorice cobertura sobre volumen de
   revision deberia subirlo.

3. CALIBRACION. Un score sin calibrar no es una probabilidad. Se aplica
   calibracion isotonica o sigmoide sobre validacion para que "0,8" signifique
   80 % de probabilidad y el umbral operativo sea interpretable.

Uso:
    python train_activity_scorer.py --split_mode date
    python train_activity_scorer.py --split_mode date --holdout_family CredentialBrute
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score

from data_loader import EmptySplitError, load_split
from feature_spec import HOSTILE_FAMILIES, resolve_feature_set
from reporting import per_group_metrics, print_per_group, save_metrics_and_plots
from train_utils import artifacts_root, now_run_id, run_header, save_json, set_seed

MIN_TRAIN_PER_HOST = 200      # ventanas minimas para justificar un modelo propio
MIN_CLASS_SUPPORT = 12        # muestras minimas para conservar una clase


# ---------------------------------------------------------------------------
# modelo
# ---------------------------------------------------------------------------
class HostActivityScorer:
    """Un clasificador calibrado por agente, con reserva global.

    Un agente que no aparece en entrenamiento -- o que no reune ventanas
    suficientes -- se atiende con el modelo global. Es una reserva degradada,
    no equivalente: el experimento leave-one-agent-out muestra que la
    transferencia entre hosts falla, de modo que un agente nuevo debe acumular
    su propio historial y reentrenarse.
    """

    def __init__(self, feature_names: List[str], seed: int = 42, calibration: str = "isotonic"):
        self.feature_names = list(feature_names)
        self.seed = seed
        self.calibration = calibration
        self.models: Dict[str, Any] = {}
        self.classes: Dict[str, np.ndarray] = {}
        self.reject_threshold: Dict[str, float] = {}
        self.global_model: Any = None
        self.global_classes: Optional[np.ndarray] = None
        self.global_reject: float = 0.0

    # -- construccion -------------------------------------------------------
    def _new_estimator(self):
        return HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.08, max_depth=6, l2_regularization=1.0,
            early_stopping=True, validation_fraction=0.15, n_iter_no_change=15,
            class_weight="balanced", random_state=self.seed,
        )

    def _fit_one(self, X: np.ndarray, y: np.ndarray):
        """Ajusta y calibra. Con muy pocas muestras la calibracion se omite:
        `CalibratedClassifierCV` necesita varios pliegues por clase."""
        counts = pd.Series(y).value_counts()
        base = self._new_estimator()
        if len(counts) < 2:
            return None, None
        n_splits = int(min(3, counts.min()))
        if n_splits < 2:
            base.fit(X, y)
            return base, np.array(sorted(set(y)))
        model = CalibratedClassifierCV(base, method=self.calibration, cv=n_splits)
        model.fit(X, y)
        return model, model.classes_

    def fit(self, df_train: pd.DataFrame, df_val: pd.DataFrame, reject_quantile: float) -> Dict[str, Any]:
        info: Dict[str, Any] = {"hosts": {}, "global": {}}
        X_all = df_train[self.feature_names].to_numpy(np.float32)
        y_all = df_train["target"].astype(str).to_numpy()

        self.global_model, self.global_classes = self._fit_one(X_all, y_all)
        info["global"] = {
            "n_train": int(len(df_train)),
            "classes": [] if self.global_classes is None else list(map(str, self.global_classes)),
        }

        for host, part in df_train.groupby("agent_id"):
            host = str(host)
            counts = part["target"].astype(str).value_counts()
            keep = counts[counts >= MIN_CLASS_SUPPORT].index.tolist()
            usable = part[part["target"].astype(str).isin(keep)]
            if len(usable) < MIN_TRAIN_PER_HOST or len(keep) < 2:
                info["hosts"][host] = {
                    "n_train": int(len(part)), "model": "global (reserva)",
                    "reason": f"solo {len(keep)} clase(s) con >= {MIN_CLASS_SUPPORT} muestras",
                }
                continue
            model, classes = self._fit_one(
                usable[self.feature_names].to_numpy(np.float32),
                usable["target"].astype(str).to_numpy(),
            )
            if model is None:
                info["hosts"][host] = {"n_train": int(len(part)), "model": "global (reserva)"}
                continue
            self.models[host] = model
            self.classes[host] = classes
            info["hosts"][host] = {
                "n_train": int(len(usable)), "model": "propio",
                "classes": list(map(str, classes)),
                "dropped_classes": sorted(set(counts.index) - set(keep)),
            }

        self._fit_reject(df_val, reject_quantile)
        for host, entry in info["hosts"].items():
            if host in self.reject_threshold:
                entry["reject_threshold"] = round(float(self.reject_threshold[host]), 4)
        info["global"]["reject_threshold"] = round(float(self.global_reject), 4)
        return info

    def _fit_reject(self, df_val: pd.DataFrame, quantile: float) -> None:
        """Umbral de rechazo = cuantil bajo de la confianza sobre validacion.

        Sobre actividad conocida el modelo es seguro; una familia nunca vista
        cae en la cola inferior de esa distribucion. Fijar el umbral en el
        cuantil `q` acepta, por construccion, un ~q de falsos rechazos sobre
        trafico conocido.
        """
        for host, part in df_val.groupby("agent_id"):
            host = str(host)
            if host not in self.models or part.empty:
                continue
            proba = self.models[host].predict_proba(part[self.feature_names].to_numpy(np.float32))
            self.reject_threshold[host] = float(np.quantile(proba.max(axis=1), quantile))
        if self.global_model is not None and not df_val.empty:
            proba = self.global_model.predict_proba(df_val[self.feature_names].to_numpy(np.float32))
            self.global_reject = float(np.quantile(proba.max(axis=1), quantile))

    # -- inferencia ---------------------------------------------------------
    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        """Devuelve score de ataque, familia, confianza y si es desconocido."""
        X = df[self.feature_names].to_numpy(np.float32)
        hosts = df["agent_id"].astype(str).to_numpy()
        n = len(df)
        attack = np.zeros(n); family = np.empty(n, dtype=object)
        confidence = np.zeros(n); unknown = np.zeros(n, dtype=bool)
        used = np.empty(n, dtype=object)

        for host in np.unique(hosts):
            mask = hosts == host
            model = self.models.get(host, self.global_model)
            classes = self.classes.get(host, self.global_classes)
            threshold = self.reject_threshold.get(host, self.global_reject)
            used[mask] = "propio" if host in self.models else "global"
            if model is None or classes is None:
                family[mask] = "Unknown"; unknown[mask] = True
                continue
            proba = model.predict_proba(X[mask])
            hostile = np.array([str(c) in HOSTILE_FAMILIES for c in classes], dtype=bool)
            attack[mask] = proba[:, hostile].sum(axis=1) if hostile.any() else 0.0
            confidence[mask] = proba.max(axis=1)
            family[mask] = np.asarray(classes, dtype=object)[proba.argmax(axis=1)]
            unknown[mask] = proba.max(axis=1) < threshold

        return pd.DataFrame({
            "attack_score": attack,
            "family": family,
            "confidence": confidence,
            "is_unknown": unknown,
            "model_used": used,
            "agent_id": hosts,
        }, index=df.index)


# ---------------------------------------------------------------------------
# evaluacion
# ---------------------------------------------------------------------------
def load_frame(split: str, args, feature_names: List[str]) -> pd.DataFrame:
    part = load_split(
        split_mode=args.split_mode, dataset=args.dataset, pipeline="multiclass",
        split=split, fold=args.fold, feature_set=args.feature_set,
    )
    df = part.meta.copy()
    for index, name in enumerate(part.feature_names):
        df[name] = part.X[:, index]
    df["target"] = part.y.astype(str)
    return df[feature_names + ["target", "agent_id"]]


def evaluate(scorer: HostActivityScorer, df: pd.DataFrame, out_dir: Path, tag: str) -> Dict[str, Any]:
    result = scorer.score(df)
    truth = df["target"].astype(str).to_numpy()
    is_hostile = np.array([t in HOSTILE_FAMILIES for t in truth], dtype=int)

    metrics: Dict[str, Any] = {"n": int(len(df))}
    if 0 < is_hostile.sum() < len(is_hostile):
        metrics["attack_score_roc_auc"] = float(roc_auc_score(is_hostile, result["attack_score"]))
        metrics["attack_score_pr_auc"] = float(average_precision_score(is_hostile, result["attack_score"]))
        metrics["attack_score_baseline"] = float(is_hostile.mean())
    metrics["family_macro_f1"] = float(
        f1_score(truth, result["family"].astype(str), average="macro", zero_division=0)
    )
    metrics["unknown_rate"] = float(result["is_unknown"].mean())

    classes = sorted(set(truth) | set(result["family"].astype(str)))
    index = {c: i for i, c in enumerate(classes)}
    report = per_group_metrics(
        np.array([index[t] for t in truth]),
        np.array([index[f] for f in result["family"].astype(str)]),
        df["agent_id"].to_numpy(), classes, scores=result["attack_score"].to_numpy(),
    )
    metrics["per_agent"] = report
    print(f"\n  [{tag}] score ROC-AUC={metrics.get('attack_score_roc_auc', float('nan')):.4f}  "
          f"familia macro-F1={metrics['family_macro_f1']:.4f}  "
          f"desconocidas={metrics['unknown_rate']:.3f}")
    print_per_group(report, f"{tag}: familia por agente")
    result.assign(target=truth).to_parquet(out_dir / f"scores_{tag}.parquet", index=False)
    return metrics


def holdout_experiment(scorer: HostActivityScorer, df_test: pd.DataFrame, family: str) -> Dict[str, Any]:
    """Prueba de ataque nunca visto.

    La familia se excluyo del entrenamiento. Un sistema honesto no debe
    clasificarla bien -- no puede -- sino **rechazarla**: marcarla como
    actividad desconocida con mas frecuencia que al trafico conocido.
    """
    result = scorer.score(df_test)
    truth = df_test["target"].astype(str).to_numpy()
    mask = truth == family
    if mask.sum() == 0:
        return {"skipped": f"la familia '{family}' no aparece en test"}
    out = {
        "family": family,
        "n_unseen": int(mask.sum()),
        "reject_rate_unseen": float(result.loc[mask, "is_unknown"].mean()),
        "reject_rate_known": float(result.loc[~mask, "is_unknown"].mean()),
        "mean_confidence_unseen": float(result.loc[mask, "confidence"].mean()),
        "mean_confidence_known": float(result.loc[~mask, "confidence"].mean()),
        "mean_attack_score_unseen": float(result.loc[mask, "attack_score"].mean()),
    }
    out["detection_ratio"] = (
        out["reject_rate_unseen"] / out["reject_rate_known"] if out["reject_rate_known"] > 0 else float("inf")
    )
    print(f"\n  -- ataque no visto: '{family}' " + "-" * 28)
    print(f"    ventanas ocultadas        : {out['n_unseen']}")
    print(f"    rechazadas (no vista)     : {out['reject_rate_unseen']:.3f}")
    print(f"    rechazadas (conocidas)    : {out['reject_rate_known']:.3f}")
    print(f"    razon de deteccion        : {out['detection_ratio']:.2f}x")
    print(f"    confianza media no vista  : {out['mean_confidence_unseen']:.4f}"
          f"   conocida: {out['mean_confidence_known']:.4f}")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Puntuador de ataque por host para ARGOS-LAB")
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    parser.add_argument("--dataset", default="ARGOS-LAB")
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--feature_set", default="behavioral",
                        choices=["full", "nosignature", "behavioral", "shape"])
    parser.add_argument("--calibration", default="isotonic", choices=["isotonic", "sigmoid"])
    parser.add_argument("--reject_quantile", type=float, default=0.25,
                        help="cuantil de confianza en validacion que fija el umbral de rechazo. "
                             "Medido ocultando la familia PortChange: q=0,05 rechaza el 3,7%% de lo "
                             "no visto (inutil); q=0,25 el 39,5%% con 20,8%% de falsos; q=0,50 el "
                             "99,8%% con 34,4%% de falsos. Es el mando de coste operativo.")
    parser.add_argument("--holdout_family", default=None,
                        help="excluye esta familia del entrenamiento para simular un ataque no visto")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    set_seed(args.seed)
    feature_names = resolve_feature_set(args.feature_set)
    root = artifacts_root("activity_scorer", args.split_mode,
                          f"{args.dataset}__{args.feature_set}", now_run_id())
    run_header("train_activity_scorer (ARGOS-LAB)", dataset=args.dataset,
               split_mode=args.split_mode, feature_set=args.feature_set,
               calibracion=args.calibration, rechazo_q=args.reject_quantile,
               familia_oculta=args.holdout_family or "ninguna", out=root)

    try:
        train = load_frame("train", args, feature_names)
        val = load_frame("val", args, feature_names)
        test = load_frame("test", args, feature_names)
    except (FileNotFoundError, EmptySplitError) as exc:
        raise SystemExit(f"No se pudo cargar {args.dataset}: {exc}")

    if args.holdout_family:
        before = len(train)
        train = train[train["target"] != args.holdout_family]
        val = val[val["target"] != args.holdout_family]
        print(f"  familia '{args.holdout_family}' excluida del entrenamiento: "
              f"{before - len(train)} ventanas retiradas\n")

    print(f"  train={len(train):,}  val={len(val):,}  test={len(test):,}  "
          f"variables={len(feature_names)}")

    scorer = HostActivityScorer(feature_names, seed=args.seed, calibration=args.calibration)
    info = scorer.fit(train, val, args.reject_quantile)
    print("\n  -- modelos ajustados " + "-" * 40)
    for host, entry in info["hosts"].items():
        extra = f" umbral={entry['reject_threshold']}" if "reject_threshold" in entry else ""
        print(f"    agente {host}: {entry['model']:<18} n={entry['n_train']:<7}"
              f"{' clases=' + str(len(entry.get('classes', []))) if 'classes' in entry else ''}{extra}")

    metrics = {"val": evaluate(scorer, val, root, "val"),
               "test": evaluate(scorer, test, root, "test")}
    if args.holdout_family:
        metrics["holdout"] = holdout_experiment(scorer, test, args.holdout_family)

    joblib.dump(scorer, root / "scorer.joblib")
    save_json(root / "results.json", {"args": vars(args), "fit_info": info, **metrics})
    print(f"\nGuardado: {root}")


if __name__ == "__main__":
    main()
