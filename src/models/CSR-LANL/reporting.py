#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_recall_curve,
    recall_score,
    roc_auc_score,
)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def has_mpl() -> bool:
    try:
        import matplotlib.pyplot as plt  # noqa: F401
        return True
    except Exception:
        return False


HAS_MPL = has_mpl()


def save_json(path: Path, payload: Dict[str, Any]) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def positive_index(class_names: Sequence[str]) -> int:
    names = [str(name).upper() for name in class_names]
    if "ATTACK" in names:
        return names.index("ATTACK")
    return 1 if len(names) == 2 else 0


def expected_calibration_error(confidence: np.ndarray, correct: np.ndarray, n_bins: int = 15) -> float:
    if len(confidence) == 0:
        return float("nan")
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for index in range(n_bins):
        lo, hi = bins[index], bins[index + 1]
        mask = (confidence >= lo) & (confidence < hi) if index < n_bins - 1 else (confidence >= lo) & (confidence <= hi)
        if not np.any(mask):
            continue
        ece += float(np.mean(mask)) * abs(float(np.mean(correct[mask])) - float(np.mean(confidence[mask])))
    return float(ece)


def plot_confusion(root: Path, split_name: str, cm: np.ndarray, class_names: Sequence[str]) -> None:
    if not HAS_MPL:
        return
    import matplotlib.pyplot as plt

    ensure_dir(root / "plots")
    plt.figure(figsize=(7, 6))
    plt.imshow(cm, aspect="auto")
    plt.title(f"Confusion matrix ({split_name})")
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.xticks(range(len(class_names)), class_names, rotation=45, ha="right")
    plt.yticks(range(len(class_names)), class_names)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, str(cm[i, j]), ha="center", va="center")
    plt.tight_layout()
    plt.savefig(root / "plots" / f"confusion_{split_name}.png", dpi=160)
    plt.close()


def plot_corr_matrix(X: np.ndarray, out_path: Path, max_rows: int = 200_000, seed: int = 42) -> None:
    if not HAS_MPL or X.size == 0 or X.shape[1] == 0:
        return
    import matplotlib.pyplot as plt

    rng = np.random.default_rng(seed)
    if len(X) > max_rows:
        X = X[rng.choice(len(X), size=max_rows, replace=False)]
    corr = np.corrcoef(X, rowvar=False)
    corr = np.nan_to_num(corr, nan=0.0, posinf=0.0, neginf=0.0)
    ensure_dir(out_path.parent)
    plt.figure(figsize=(10, 8))
    plt.imshow(corr, aspect="auto")
    plt.title("Feature correlation")
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def binary_auc_metrics(y_true_int: np.ndarray, proba: np.ndarray, class_names: Sequence[str]) -> tuple[Optional[float], Optional[float]]:
    if proba.shape[1] != 2:
        return None, None
    pos = positive_index(class_names)
    y = (y_true_int == pos).astype(int)
    if len(np.unique(y)) < 2:
        return None, None
    scores = proba[:, pos]
    return float(roc_auc_score(y, scores)), float(average_precision_score(y, scores))


def save_metrics_and_plots(root: Path, split_name: str, y_true_int: np.ndarray, proba: np.ndarray, class_names: Sequence[str]) -> Dict[str, Any]:
    y_pred = proba.argmax(axis=1)
    labels = list(range(len(class_names)))
    cm = confusion_matrix(y_true_int, y_pred, labels=labels)
    report_text = classification_report(y_true_int, y_pred, labels=labels, target_names=list(map(str, class_names)), zero_division=0, digits=4)
    confidence = proba.max(axis=1)
    correct = (y_pred == y_true_int).astype(int)
    roc_auc, pr_auc = binary_auc_metrics(y_true_int, proba, class_names)
    try:
        loss = float(log_loss(y_true_int, proba, labels=labels))
    except Exception:
        loss = float("nan")

    metrics = {
        "accuracy": float(accuracy_score(y_true_int, y_pred)),
        "macro_f1": float(f1_score(y_true_int, y_pred, average="macro", labels=labels, zero_division=0)),
        "macro_recall": float(recall_score(y_true_int, y_pred, average="macro", labels=labels, zero_division=0)),
        "logloss": loss,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "ece": expected_calibration_error(confidence, correct),
    }
    save_json(root / f"metrics_{split_name}.json", metrics)
    (root / f"classification_report_{split_name}.txt").write_text(report_text, encoding="utf-8")
    np.savetxt(root / f"confusion_{split_name}.csv", cm, delimiter=",", fmt="%d")
    plot_confusion(root, split_name, cm, class_names)
    return metrics


def save_anomaly_plots(root: Path, split_name: str, y_true_binary: np.ndarray, scores: np.ndarray, positive_label: str = "ATTACK") -> None:
    if not HAS_MPL:
        return
    import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve

    y = np.array([1 if str(value) == positive_label else 0 for value in y_true_binary], dtype=int)
    s = np.asarray(scores, dtype=np.float64)
    mask = np.isfinite(s)
    y = y[mask]
    s = s[mask]
    ensure_dir(root / "plots")
    plt.figure()
    plt.hist(s[y == 0], bins=50, alpha=0.6, label="BENIGN")
    plt.hist(s[y == 1], bins=50, alpha=0.6, label="ATTACK")
    plt.title(f"Anomaly scores ({split_name})")
    plt.legend()
    plt.tight_layout()
    plt.savefig(root / "plots" / f"anomaly_hist_{split_name}.png", dpi=160)
    plt.close()
    if len(np.unique(y)) < 2:
        return
    fpr, tpr, _ = roc_curve(y, s)
    precision, recall, _ = precision_recall_curve(y, s)
    plt.figure()
    plt.plot(fpr, tpr)
    plt.title(f"Anomaly ROC ({split_name})")
    plt.tight_layout()
    plt.savefig(root / "plots" / f"anomaly_roc_{split_name}.png", dpi=160)
    plt.close()
    plt.figure()
    plt.plot(recall, precision)
    plt.title(f"Anomaly PR ({split_name})")
    plt.tight_layout()
    plt.savefig(root / "plots" / f"anomaly_pr_{split_name}.png", dpi=160)
    plt.close()