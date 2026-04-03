#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
)


@dataclass
class ClsReport:
    accuracy: float
    balanced_accuracy: float
    macro_f1: float
    weighted_f1: float
    confusion: np.ndarray
    labels: List[str]
    report_text: str


def evaluate_classification(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    labels: Optional[Sequence[str]] = None,
) -> ClsReport:
    if labels is None:
        labels = sorted(list({*map(str, y_true), *map(str, y_pred)}))

    acc = float(accuracy_score(y_true, y_pred))
    bacc = float(balanced_accuracy_score(y_true, y_pred))
    macro = float(f1_score(y_true, y_pred, average="macro", labels=labels, zero_division=0))
    w = float(f1_score(y_true, y_pred, average="weighted", labels=labels, zero_division=0))
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    rpt = classification_report(y_true, y_pred, labels=labels, zero_division=0, digits=4)

    return ClsReport(
        accuracy=acc,
        balanced_accuracy=bacc,
        macro_f1=macro,
        weighted_f1=w,
        confusion=cm,
        labels=list(labels),
        report_text=rpt,
    )


@dataclass
class AnomalyReport:
    roc_auc: float
    pr_auc: float
    best_f1: float
    best_threshold: float


def evaluate_anomaly_scores(
    y_true_binary: np.ndarray,
    scores: np.ndarray,
    positive_label: str = "ATTACK",
) -> AnomalyReport:
    y = np.array([1 if str(v) == positive_label else 0 for v in y_true_binary], dtype=int)

    roc = float(roc_auc_score(y, scores))
    pr = float(average_precision_score(y, scores))

    prec, rec, thr = precision_recall_curve(y, scores)
    f1 = 2 * (prec[:-1] * rec[:-1]) / (prec[:-1] + rec[:-1] + 1e-12)
    best_idx = int(np.nanargmax(f1)) if len(f1) else 0
    best_f1 = float(f1[best_idx]) if len(f1) else 0.0
    best_thr = float(thr[best_idx]) if len(thr) else float("nan")

    return AnomalyReport(roc_auc=roc, pr_auc=pr, best_f1=best_f1, best_threshold=best_thr)
