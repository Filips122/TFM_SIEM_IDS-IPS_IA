#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score


@dataclass
class AnomalyReport:
    roc_auc: float
    pr_auc: float
    best_f1: float
    best_threshold: float


def evaluate_anomaly_scores(y_true_binary: np.ndarray, scores: np.ndarray, positive_label: str = "ATTACK") -> AnomalyReport:
    y = np.array([1 if str(value) == positive_label else 0 for value in y_true_binary], dtype=int)
    s = np.asarray(scores, dtype=np.float64)
    mask = np.isfinite(s)
    y = y[mask]
    s = s[mask]
    if len(y) == 0 or len(np.unique(y)) < 2:
        return AnomalyReport(roc_auc=float("nan"), pr_auc=float("nan"), best_f1=0.0, best_threshold=float("nan"))
    roc = float(roc_auc_score(y, s))
    pr = float(average_precision_score(y, s))
    precision, recall, thresholds = precision_recall_curve(y, s)
    f1 = 2 * (precision[:-1] * recall[:-1]) / (precision[:-1] + recall[:-1] + 1e-12)
    best_index = int(np.nanargmax(f1)) if len(f1) else 0
    best_f1 = float(f1[best_index]) if len(f1) else 0.0
    best_threshold = float(thresholds[best_index]) if len(thresholds) else float("nan")
    return AnomalyReport(roc_auc=roc, pr_auc=pr, best_f1=best_f1, best_threshold=best_threshold)