#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metric helpers.

Accuracy is close to useless on this dataset (the majority class is ~98% of
windows), so every reported summary leads with PR-AUC, balanced accuracy and
macro-F1, and anomaly scoring adds precision@k, which is what an analyst
triaging a daily alert queue actually experiences.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, Sequence

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
)


@dataclass
class AnomalyReport:
    roc_auc: float
    pr_auc: float
    pr_auc_baseline: float
    pr_auc_lift: float
    best_f1: float
    best_threshold: float
    precision_at_1pct: float
    precision_at_5pct: float
    recall_at_1pct: float
    recall_at_5pct: float
    positives: int
    negatives: int

    def to_dict(self) -> Dict[str, float]:
        return asdict(self)


def to_binary(y: Sequence[object], positive_label: str = "ATTACK") -> np.ndarray:
    return np.array([1 if str(value) == positive_label else 0 for value in y], dtype=int)


def precision_recall_at_k(y: np.ndarray, scores: np.ndarray, fraction: float) -> tuple[float, float]:
    """Precision and recall inside the top `fraction` highest-scored windows."""
    n = len(scores)
    k = max(1, int(round(n * fraction)))
    order = np.argsort(-scores, kind="stable")[:k]
    hits = int(y[order].sum())
    total_positives = int(y.sum())
    precision = hits / k
    recall = hits / total_positives if total_positives else float("nan")
    return float(precision), float(recall)


def evaluate_anomaly_scores(y_true: Sequence[object], scores: np.ndarray, positive_label: str = "ATTACK") -> AnomalyReport:
    y = to_binary(y_true, positive_label)
    s = np.asarray(scores, dtype=np.float64)
    mask = np.isfinite(s)
    y, s = y[mask], s[mask]

    positives, negatives = int(y.sum()), int(len(y) - y.sum())
    if len(y) == 0 or len(np.unique(y)) < 2:
        return AnomalyReport(
            roc_auc=float("nan"), pr_auc=float("nan"), pr_auc_baseline=float("nan"),
            pr_auc_lift=float("nan"), best_f1=0.0, best_threshold=float("nan"),
            precision_at_1pct=float("nan"), precision_at_5pct=float("nan"),
            recall_at_1pct=float("nan"), recall_at_5pct=float("nan"),
            positives=positives, negatives=negatives,
        )

    roc = float(roc_auc_score(y, s))
    pr = float(average_precision_score(y, s))
    # A random ranker scores PR-AUC == prevalence, so the lift is the number
    # that actually says whether the model learned anything.
    baseline = float(y.mean())
    precision, recall, thresholds = precision_recall_curve(y, s)
    f1 = 2 * (precision[:-1] * recall[:-1]) / (precision[:-1] + recall[:-1] + 1e-12)
    best_index = int(np.nanargmax(f1)) if len(f1) else 0
    p1, r1 = precision_recall_at_k(y, s, 0.01)
    p5, r5 = precision_recall_at_k(y, s, 0.05)

    return AnomalyReport(
        roc_auc=roc,
        pr_auc=pr,
        pr_auc_baseline=baseline,
        pr_auc_lift=float(pr / baseline) if baseline > 0 else float("nan"),
        best_f1=float(f1[best_index]) if len(f1) else 0.0,
        best_threshold=float(thresholds[best_index]) if len(thresholds) else float("nan"),
        precision_at_1pct=p1,
        precision_at_5pct=p5,
        recall_at_1pct=r1,
        recall_at_5pct=r5,
        positives=positives,
        negatives=negatives,
    )


def evaluate_anomaly_both_directions(y_true: Sequence[object], scores: np.ndarray) -> Dict[str, Dict[str, float]]:
    """Score the ranking in both directions.

    On this capture ATTACK is ~98% of windows, so "is the anomaly score high
    for ATTACK?" is the wrong question: an anomaly detector surfaces the rare
    thing, and here the rare thing is BENIGN. Reporting only the ATTACK
    direction makes a working detector look broken (and vice versa), so both
    are always emitted.

    Returns {"attack": ..., "rare": ...} where the `rare` entry scores the
    minority class with the score direction flipped when needed.
    """
    labels = np.array([str(v) for v in y_true])
    attack = evaluate_anomaly_scores(labels, scores, positive_label="ATTACK")

    unique, counts = np.unique(labels, return_counts=True)
    if len(unique) < 2:
        return {"attack": attack.to_dict(), "rare": attack.to_dict()}

    rare_label = str(unique[int(np.argmin(counts))])
    # A high anomaly score should mean "this is the rare class". When the rare
    # class is not ATTACK the ranking must be inverted before scoring.
    rare_scores = np.asarray(scores, dtype=np.float64)
    if rare_label != "ATTACK":
        rare_scores = -rare_scores
    rare = evaluate_anomaly_scores(labels, rare_scores, positive_label=rare_label)
    out = rare.to_dict()
    out["positive_label"] = rare_label
    out["score_inverted"] = rare_label != "ATTACK"
    return {"attack": attack.to_dict(), "rare": out}
