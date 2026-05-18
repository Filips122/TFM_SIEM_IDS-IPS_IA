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


def plot_history(history_csv: Path, out_dir: Path) -> None:
    if not HAS_MPL:
        return
    import pandas as pd
    import matplotlib.pyplot as plt

    ensure_dir(out_dir)
    df = pd.read_csv(history_csv)
    if "epoch" not in df.columns:
        return
    df = df.sort_values("epoch")

    has_loss = {"train_loss", "val_loss"}.issubset(df.columns)
    has_acc = {"train_acc", "val_acc"}.issubset(df.columns)
    if has_loss or has_acc:
        fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
        if has_loss:
            axes[0].plot(df["epoch"], df["train_loss"], label="train loss", linewidth=1.8)
            axes[0].plot(df["epoch"], df["val_loss"], label="val loss", linewidth=1.8)
        else:
            axes[0].text(0.5, 0.5, "No loss history", ha="center", va="center", transform=axes[0].transAxes)
        axes[0].set_title("Loss by epoch")
        axes[0].set_xlabel("epoch")
        axes[0].set_ylabel("loss")
        axes[0].grid(True, alpha=0.3)
        axes[0].legend()

        if has_acc:
            axes[1].plot(df["epoch"], df["train_acc"], label="train accuracy", linewidth=1.8)
            axes[1].plot(df["epoch"], df["val_acc"], label="val accuracy", linewidth=1.8)
            axes[1].set_ylim(0.0, 1.05)
        else:
            axes[1].text(0.5, 0.5, "No accuracy history", ha="center", va="center", transform=axes[1].transAxes)
        axes[1].set_title("Accuracy by epoch")
        axes[1].set_xlabel("epoch")
        axes[1].set_ylabel("accuracy")
        axes[1].grid(True, alpha=0.3)
        axes[1].legend()

        fig.suptitle("Train/validation history")
        fig.tight_layout()
        fig.savefig(out_dir / "training_history_accuracy_loss.png", dpi=160)
        plt.close(fig)

    if has_loss:
        plt.figure()
        plt.plot(df["epoch"], df["train_loss"], label="train loss")
        plt.plot(df["epoch"], df["val_loss"], label="val loss")
        plt.xlabel("epoch")
        plt.ylabel("loss")
        plt.legend()
        plt.tight_layout()
        plt.savefig(out_dir / "curve_loss.png", dpi=160)
        plt.close()

    if has_acc:
        plt.figure()
        plt.plot(df["epoch"], df["train_acc"], label="train accuracy")
        plt.plot(df["epoch"], df["val_acc"], label="val accuracy")
        plt.xlabel("epoch")
        plt.ylabel("accuracy")
        plt.ylim(0.0, 1.05)
        plt.legend()
        plt.tight_layout()
        plt.savefig(out_dir / "curve_accuracy.png", dpi=160)
        plt.close()


def _history_sample(X: np.ndarray, y: np.ndarray, max_rows: int | None, seed: int) -> tuple[np.ndarray, np.ndarray]:
    if max_rows is None or len(X) <= max_rows:
        return X, y
    rng = np.random.default_rng(seed)
    index = rng.choice(len(X), size=max_rows, replace=False)
    return X[index], y[index]


def _history_logloss(y_true: np.ndarray, proba: np.ndarray, labels: list[int]) -> float:
    try:
        return float(log_loss(y_true, proba, labels=labels))
    except Exception:
        return float("nan")


def save_staged_classification_history(
    root: Path,
    model: Any,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    class_names: Sequence[str],
    max_rows: int | None = 200_000,
    seed: int = 42,
) -> list[dict[str, float | int]]:
    if not hasattr(model, "staged_predict_proba"):
        return []
    import pandas as pd

    X_train_hist, y_train_hist = _history_sample(X_train, y_train, max_rows, seed)
    X_val_hist, y_val_hist = _history_sample(X_val, y_val, max_rows, seed + 1)
    labels = list(range(len(class_names)))
    rows: list[dict[str, float | int]] = []
    try:
        train_stages = model.staged_predict_proba(X_train_hist)
        val_stages = model.staged_predict_proba(X_val_hist)
        for epoch, (train_proba, val_proba) in enumerate(zip(train_stages, val_stages), start=1):
            train_pred = train_proba.argmax(axis=1)
            val_pred = val_proba.argmax(axis=1)
            rows.append(
                {
                    "epoch": epoch,
                    "train_loss": _history_logloss(y_train_hist, train_proba, labels),
                    "train_acc": float(accuracy_score(y_train_hist, train_pred)),
                    "val_loss": _history_logloss(y_val_hist, val_proba, labels),
                    "val_acc": float(accuracy_score(y_val_hist, val_pred)),
                }
            )
    except Exception:
        return []

    if not rows:
        return []
    history_path = root / "history.csv"
    ensure_dir(history_path.parent)
    pd.DataFrame(rows).to_csv(history_path, index=False)
    plot_history(history_path, root / "plots")
    return rows


def metric_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if np.isfinite(out) else None


def plot_overfitting_metrics(root: Path) -> None:
    if not HAS_MPL:
        return
    import matplotlib.pyplot as plt

    split_names = ["train", "val", "test"]
    metrics: Dict[str, Dict[str, Any]] = {}
    for split_name in split_names:
        path = root / f"metrics_{split_name}.json"
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(payload, dict):
            metrics[split_name] = payload

    labels = [split_name for split_name in split_names if split_name in metrics]
    if not labels:
        return

    accuracy = [metric_float(metrics[split_name].get("accuracy")) for split_name in labels]
    logloss = [metric_float(metrics[split_name].get("logloss")) for split_name in labels]
    if not any(value is not None for value in accuracy + logloss):
        return

    plots_dir = root / "plots"
    ensure_dir(plots_dir)
    x = list(range(len(labels)))

    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, values, title, ylabel in [
        (axes[0], accuracy, "Accuracy by split", "accuracy"),
        (axes[1], logloss, "Log-loss by split", "log-loss"),
    ]:
        valid_x = [index for index, value in enumerate(values) if value is not None]
        valid_y = [value for value in values if value is not None]
        if valid_y:
            ax.plot(valid_x, valid_y, marker="o")
        else:
            ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
        ax.set_title(title)
        ax.set_xlabel("split")
        ax.set_ylabel(ylabel)
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.grid(True, alpha=0.3)
    if any(value is not None for value in accuracy):
        axes[0].set_ylim(0.0, 1.05)
    if any(value is not None and value >= 0.0 for value in logloss):
        axes[1].set_ylim(bottom=0.0)
    fig.suptitle("Overfitting check")
    fig.tight_layout()
    fig.savefig(plots_dir / "overfitting_accuracy_loss.png", dpi=160)
    plt.close(fig)


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
    plot_overfitting_metrics(root)
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