#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metrics, plots and permutation importance for ARGOS-LAB runs.

Two deliberate departures from the sibling dataset reporters:

1. The decision threshold is tuned on validation, not fixed at argmax. With a
   2% positive rate, argmax collapses to the majority class and hides whatever
   the model actually learned.
2. Every classification report also carries `no_posture`, the same metrics
   recomputed over windows that are not vulnerability-scanner output. The
   dataset manifest explicitly asks for this, because posture findings are
   trivially separable and inflate every score.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
    matthews_corrcoef,
    precision_recall_curve,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def has_mpl() -> bool:
    try:
        import matplotlib  # noqa: F401
        return True
    except Exception:
        return False


HAS_MPL = has_mpl()

if HAS_MPL:
    import matplotlib
    matplotlib.use("Agg")


def save_json(path: Path, payload: Dict[str, Any]) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


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
        mask = (confidence >= lo) & (confidence <= hi) if index == n_bins - 1 else (confidence >= lo) & (confidence < hi)
        if not np.any(mask):
            continue
        ece += float(np.mean(mask)) * abs(float(np.mean(correct[mask])) - float(np.mean(confidence[mask])))
    return float(ece)


def best_threshold(y_true_int: np.ndarray, proba: np.ndarray, class_names: Sequence[str]) -> float:
    """Threshold maximising F1 on the positive class. Returns 0.5 when the
    problem is not binary or one class is absent."""
    if proba.shape[1] != 2:
        return 0.5
    pos = positive_index(class_names)
    y = (y_true_int == pos).astype(int)
    if len(np.unique(y)) < 2:
        return 0.5
    precision, recall, thresholds = precision_recall_curve(y, proba[:, pos])
    f1 = 2 * (precision[:-1] * recall[:-1]) / (precision[:-1] + recall[:-1] + 1e-12)
    if not len(f1):
        return 0.5
    return float(thresholds[int(np.nanargmax(f1))])


def _core_metrics(y_true_int: np.ndarray, y_pred: np.ndarray, labels: Sequence[int]) -> Dict[str, float]:
    return {
        "accuracy": float(accuracy_score(y_true_int, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true_int, y_pred)),
        "macro_f1": float(f1_score(y_true_int, y_pred, average="macro", labels=list(labels), zero_division=0)),
        "macro_recall": float(recall_score(y_true_int, y_pred, average="macro", labels=list(labels), zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true_int, y_pred)) if len(np.unique(y_true_int)) > 1 else float("nan"),
    }


def save_metrics_and_plots(
    root: Path,
    split_name: str,
    y_true_int: np.ndarray,
    proba: np.ndarray,
    class_names: Sequence[str],
    threshold: Optional[float] = None,
    posture_ratio: Optional[np.ndarray] = None,
) -> Dict[str, Any]:
    class_names = [str(name) for name in class_names]
    labels = list(range(len(class_names)))
    pos = positive_index(class_names)
    binary = proba.shape[1] == 2

    if binary and threshold is not None:
        y_pred = (proba[:, pos] >= threshold).astype(int)
        if pos == 0:
            y_pred = 1 - y_pred
    else:
        y_pred = proba.argmax(axis=1)

    metrics: Dict[str, Any] = _core_metrics(y_true_int, y_pred, labels)
    metrics["threshold"] = float(threshold) if (binary and threshold is not None) else None
    metrics["support"] = {name: int((y_true_int == index).sum()) for index, name in enumerate(class_names)}

    if binary:
        y = (y_true_int == pos).astype(int)
        scores = proba[:, pos]
        if len(np.unique(y)) > 1:
            metrics["roc_auc"] = float(roc_auc_score(y, scores))
            metrics["pr_auc"] = float(average_precision_score(y, scores))
            metrics["pr_auc_baseline"] = float(y.mean())
            metrics["pr_auc_lift"] = float(metrics["pr_auc"] / y.mean()) if y.mean() > 0 else float("nan")
            # ATTACK is the MAJORITY class in this capture (~98% of windows), so
            # PR-AUC against it is saturated by construction and says nothing.
            # The rare class carries the information, so report it explicitly.
            minority = int(np.argmin([len(y) - y.sum(), y.sum()]))
            y_min = (y == minority).astype(int)
            s_min = scores if minority == 1 else -scores
            metrics["minority_class"] = class_names[pos] if minority == 1 else class_names[1 - pos]
            metrics["pr_auc_minority"] = float(average_precision_score(y_min, s_min))
            metrics["pr_auc_minority_baseline"] = float(y_min.mean())
            metrics["pr_auc_minority_lift"] = (
                float(metrics["pr_auc_minority"] / y_min.mean()) if y_min.mean() > 0 else float("nan")
            )
        else:
            metrics["roc_auc"] = metrics["pr_auc"] = metrics["pr_auc_baseline"] = metrics["pr_auc_lift"] = None
            metrics["pr_auc_minority"] = None
    try:
        metrics["logloss"] = float(log_loss(y_true_int, proba, labels=labels))
    except Exception:
        metrics["logloss"] = float("nan")
    confidence = proba.max(axis=1)
    metrics["ece"] = expected_calibration_error(confidence, (y_pred == y_true_int).astype(int))

    # --- the manifest's requested posture-free view -------------------------
    if posture_ratio is not None:
        mask = np.asarray(posture_ratio) < 0.5
        if mask.sum() > 0 and len(np.unique(y_true_int[mask])) > 1:
            sub = _core_metrics(y_true_int[mask], y_pred[mask], labels)
            if binary:
                y_sub = (y_true_int[mask] == pos).astype(int)
                sub["pr_auc"] = float(average_precision_score(y_sub, proba[mask, pos]))
                sub["pr_auc_baseline"] = float(y_sub.mean())
                sub["roc_auc"] = float(roc_auc_score(y_sub, proba[mask, pos]))
            sub["rows"] = int(mask.sum())
            metrics["no_posture"] = sub
        else:
            metrics["no_posture"] = {"rows": int(mask.sum()), "note": "single class after removing posture windows"}

    cm = confusion_matrix(y_true_int, y_pred, labels=labels)
    report_text = classification_report(
        y_true_int, y_pred, labels=labels, target_names=class_names, zero_division=0, digits=4
    )
    save_json(root / f"metrics_{split_name}.json", metrics)
    (root / f"classification_report_{split_name}.txt").write_text(report_text, encoding="utf-8")
    np.savetxt(root / f"confusion_{split_name}.csv", cm, delimiter=",", fmt="%d")
    plot_confusion(root, split_name, cm, class_names)
    if binary and len(np.unique(y_true_int)) > 1:
        plot_pr_roc(root, split_name, (y_true_int == pos).astype(int), proba[:, pos])
    return metrics


# --------------------------------------------------------------------------
# plots
# --------------------------------------------------------------------------
def plot_confusion(root: Path, split_name: str, cm: np.ndarray, class_names: Sequence[str]) -> None:
    if not HAS_MPL:
        return
    import matplotlib.pyplot as plt

    ensure_dir(root / "plots")
    normalized = cm.astype(float) / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    fig, ax = plt.subplots(figsize=(1.6 + 1.1 * len(class_names), 1.4 + 1.0 * len(class_names)))
    ax.imshow(normalized, aspect="auto", cmap="Blues", vmin=0, vmax=1)
    ax.set_title(f"Confusion matrix ({split_name})")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_xticks(range(len(class_names)), class_names, rotation=45, ha="right")
    ax.set_yticks(range(len(class_names)), class_names)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, f"{cm[i, j]:,}\n{normalized[i, j]:.2f}", ha="center", va="center",
                    fontsize=8, color="white" if normalized[i, j] > 0.5 else "black")
    fig.tight_layout()
    fig.savefig(root / "plots" / f"confusion_{split_name}.png", dpi=150)
    plt.close(fig)


def plot_pr_roc(root: Path, split_name: str, y: np.ndarray, scores: np.ndarray) -> None:
    if not HAS_MPL:
        return
    import matplotlib.pyplot as plt

    ensure_dir(root / "plots")
    precision, recall, _ = precision_recall_curve(y, scores)
    fpr, tpr, _ = roc_curve(y, scores)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    axes[0].plot(recall, precision)
    axes[0].axhline(y.mean(), ls="--", c="grey", label=f"random = {y.mean():.3f}")
    axes[0].set_xlabel("Recall")
    axes[0].set_ylabel("Precision")
    axes[0].set_title(f"PR curve ({split_name})  AP={average_precision_score(y, scores):.4f}")
    axes[0].legend()
    axes[1].plot(fpr, tpr, label="model")
    axes[1].plot([0, 1], [0, 1], ls="--", c="grey", label="random")
    axes[1].set_xlabel("FPR")
    axes[1].set_ylabel("TPR")
    axes[1].set_title(f"ROC ({split_name})  AUC={roc_auc_score(y, scores):.4f}")
    fig.tight_layout()
    fig.savefig(root / "plots" / f"pr_roc_{split_name}.png", dpi=150)
    plt.close(fig)


def plot_corr_matrix(X: np.ndarray, out_path: Path, feature_names: Optional[Sequence[str]] = None, max_rows: int = 200_000, seed: int = 42) -> None:
    if not HAS_MPL or X.size == 0 or X.shape[1] == 0:
        return
    import matplotlib.pyplot as plt

    rng = np.random.default_rng(seed)
    if len(X) > max_rows:
        X = X[rng.choice(len(X), size=max_rows, replace=False)]
    corr = np.nan_to_num(np.corrcoef(X, rowvar=False), nan=0.0, posinf=0.0, neginf=0.0)
    ensure_dir(out_path.parent)
    fig, ax = plt.subplots(figsize=(11, 9))
    image = ax.imshow(corr, aspect="auto", cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_title("Feature correlation")
    if feature_names is not None and len(feature_names) <= 60:
        ax.set_xticks(range(len(feature_names)), feature_names, rotation=90, fontsize=5)
        ax.set_yticks(range(len(feature_names)), feature_names, fontsize=5)
    fig.colorbar(image, ax=ax, shrink=0.8)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_history(history_csv: Path, plots_dir: Path) -> None:
    if not HAS_MPL or not history_csv.exists():
        return
    import matplotlib.pyplot as plt
    import pandas as pd

    history = pd.read_csv(history_csv)
    ensure_dir(plots_dir)
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    for column in [c for c in history.columns if c.endswith("loss")]:
        axes[0].plot(history["epoch"], history[column], label=column)
    axes[0].set_xlabel("epoch")
    axes[0].set_title("Loss")
    axes[0].legend()
    for column in [c for c in history.columns if c.endswith(("acc", "auc", "f1"))]:
        axes[1].plot(history["epoch"], history[column], label=column)
    axes[1].set_xlabel("epoch")
    axes[1].set_title("Score")
    axes[1].legend()
    fig.tight_layout()
    fig.savefig(plots_dir / "history.png", dpi=150)
    plt.close(fig)


def save_anomaly_plots(root: Path, split_name: str, y_true: Sequence[object], scores: np.ndarray, positive_label: str = "ATTACK") -> None:
    if not HAS_MPL:
        return
    import matplotlib.pyplot as plt

    y = np.array([1 if str(value) == positive_label else 0 for value in y_true], dtype=int)
    s = np.asarray(scores, dtype=np.float64)
    mask = np.isfinite(s)
    y, s = y[mask], s[mask]
    ensure_dir(root / "plots")
    fig, ax = plt.subplots(figsize=(7, 4))
    bins = np.linspace(np.percentile(s, 0.5), np.percentile(s, 99.5), 60)
    ax.hist(s[y == 0], bins=bins, alpha=0.6, label=f"BENIGN (n={int((y == 0).sum()):,})", density=True)
    ax.hist(s[y == 1], bins=bins, alpha=0.6, label=f"ATTACK (n={int(y.sum()):,})", density=True)
    ax.set_title(f"Anomaly score distribution ({split_name})")
    ax.set_xlabel("anomaly score")
    ax.legend()
    fig.tight_layout()
    fig.savefig(root / "plots" / f"anomaly_hist_{split_name}.png", dpi=150)
    plt.close(fig)
    if len(np.unique(y)) > 1:
        plot_pr_roc(root, f"anomaly_{split_name}", y, s)


# --------------------------------------------------------------------------
# feature importance
# --------------------------------------------------------------------------
def permutation_importance_report(
    predict_proba,
    X: np.ndarray,
    y_int: np.ndarray,
    feature_names: Sequence[str],
    root: Path,
    class_names: Sequence[str],
    n_repeats: int = 3,
    max_rows: int = 30_000,
    seed: int = 42,
) -> Dict[str, float]:
    """Permutation importance measured on PR-AUC (binary) or macro-F1.

    This is the diagnostic that makes the leak visible: on the `full` regime a
    couple of signature features carry essentially all the importance.
    """
    rng = np.random.default_rng(seed)
    if len(X) > max_rows:
        keep = rng.choice(len(X), size=max_rows, replace=False)
        X, y_int = X[keep], y_int[keep]
    pos = positive_index(class_names)
    binary = len(class_names) == 2 and len(np.unique(y_int)) > 1

    # Scoring against ATTACK saturates at 1.0 here (it is ~98% of windows), and a
    # saturated baseline makes every permutation drop read as 0.0. Score the
    # MINORITY class instead, which still has headroom to lose.
    if binary:
        y_pos = (y_int == pos).astype(int)
        minority = int(np.argmin([len(y_pos) - y_pos.sum(), y_pos.sum()]))
        y_target = (y_pos == minority).astype(int)
        sign = 1.0 if minority == 1 else -1.0
        metric_name = f"pr_auc[{class_names[pos] if minority == 1 else class_names[1 - pos]}]"
    else:
        metric_name = "macro_f1"

    def score(matrix: np.ndarray) -> float:
        proba = predict_proba(matrix)
        if binary:
            return float(average_precision_score(y_target, sign * proba[:, pos]))
        return float(f1_score(y_int, proba.argmax(axis=1), average="macro", zero_division=0))

    base = score(X)
    drops: Dict[str, float] = {}
    for index, name in enumerate(feature_names):
        deltas = []
        for repeat in range(n_repeats):
            shuffled = X.copy()
            shuffled[:, index] = rng.permutation(shuffled[:, index])
            deltas.append(base - score(shuffled))
        drops[name] = float(np.mean(deltas))

    ordered = dict(sorted(drops.items(), key=lambda item: item[1], reverse=True))
    save_json(root / "feature_importance.json", {"baseline_score": base, "metric": metric_name, "importance": ordered})

    if HAS_MPL:
        import matplotlib.pyplot as plt

        top = list(ordered.items())[:25][::-1]
        ensure_dir(root / "plots")
        fig, ax = plt.subplots(figsize=(8, max(4, 0.28 * len(top))))
        ax.barh([name for name, _ in top], [value for _, value in top])
        ax.set_xlabel("drop in score when shuffled")
        ax.set_title("Permutation importance (top 25)")
        fig.tight_layout()
        fig.savefig(root / "plots" / "feature_importance.png", dpi=150)
        plt.close(fig)
    return ordered


def predict_proba_torch(model, X: np.ndarray, device, batch_size: int = 8192) -> np.ndarray:
    import torch

    model.eval()
    outputs = []
    with torch.no_grad():
        for start in range(0, len(X), batch_size):
            batch = torch.from_numpy(X[start : start + batch_size]).to(device)
            batch = torch.nan_to_num(batch, nan=0.0, posinf=0.0, neginf=0.0)
            outputs.append(torch.softmax(model(batch), dim=1).cpu().numpy())
    return np.concatenate(outputs, axis=0) if outputs else np.zeros((0, 2), dtype=np.float32)


def per_group_metrics(
    y_true_int: np.ndarray,
    y_pred: np.ndarray,
    groups: Sequence[object],
    class_names: Sequence[str],
    scores: Optional[np.ndarray] = None,
    min_rare_support: int = 8,
) -> Dict[str, Any]:
    """Break every metric down by group (agent), and never report only the pooled value.

    This exists because of a concrete failure in this project. A tabular
    autoencoder reported an 18.26x lift over random at surfacing the rare class,
    which looked like the strongest unsupervised result in the study. Broken
    down by agent, every single host sat at or below random (0.57x-0.95x): the
    pooled number came entirely from the rare class being 74.5% concentrated in
    one agent, so the model was ranking "which machine is this", not "what is
    happening". That is Simpson's paradox, and a pooled metric cannot reveal it.

    Any aggregate figure quoted from this codebase must be accompanied by the
    per-group table this function produces.
    """
    groups = np.asarray([str(g) for g in groups])
    out: Dict[str, Any] = {"pooled": {}, "per_group": {}, "warnings": []}

    labels = list(range(len(class_names)))
    out["pooled"] = {
        "n": int(len(y_true_int)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true_int, y_pred))
        if len(np.unique(y_true_int)) > 1 else None,
        "macro_f1": float(f1_score(y_true_int, y_pred, average="macro", labels=labels, zero_division=0)),
    }

    lifts = []
    for group in sorted(set(groups.tolist())):
        mask = groups == group
        yt, yp = y_true_int[mask], y_pred[mask]
        entry: Dict[str, Any] = {
            "n": int(mask.sum()),
            "classes_present": int(len(np.unique(yt))),
            "class_counts": {class_names[i]: int((yt == i).sum()) for i in np.unique(yt)},
        }
        if len(np.unique(yt)) > 1:
            # Average only over classes this group can actually exhibit. Scoring
            # a two-class host against the full nine-class label set charges it
            # for seven classes it never sees and drags macro-F1 to 2/9.
            present = sorted(set(yt.tolist()) | set(yp.tolist()))
            entry["classes_scored"] = [class_names[i] for i in present]
            entry["balanced_accuracy"] = float(balanced_accuracy_score(yt, yp))
            entry["macro_f1"] = float(f1_score(yt, yp, average="macro", labels=present, zero_division=0))
            entry["macro_f1_global_labels"] = float(
                f1_score(yt, yp, average="macro", labels=labels, zero_division=0)
            )
            if scores is not None:
                # Rank quality against the rarer class inside this group. A lift
                # computed over a handful of samples is noise, not evidence.
                counts = np.bincount(yt, minlength=len(class_names))
                rare = int(np.argmin(np.where(counts > 0, counts, np.inf)))
                y_rare = (yt == rare).astype(int)
                s = np.asarray(scores)[mask]
                if y_rare.sum() < min_rare_support:
                    entry["lift_note"] = (
                        f"clase rara '{class_names[rare]}' con {int(y_rare.sum())} muestras "
                        f"(< {min_rare_support}): lift no evaluable"
                    )
                elif 0 < y_rare.sum() < len(y_rare):
                    ap = float(average_precision_score(y_rare, s if rare == 1 else -s))
                    base = float(y_rare.mean())
                    entry["rare_class"] = class_names[rare]
                    entry["pr_auc"] = ap
                    entry["pr_auc_baseline"] = base
                    entry["lift"] = ap / base if base > 0 else float("nan")
                    lifts.append(entry["lift"])
        else:
            entry["note"] = "single class in this group; not evaluable"
        out["per_group"][str(group)] = entry

    if lifts and out["pooled"].get("macro_f1") is not None:
        worst, best = min(lifts), max(lifts)
        if worst < 1.0 and best < 1.5:
            out["warnings"].append(
                "Every group sits at or below random lift. A favourable pooled figure here "
                "reflects group composition, not detection. Do not quote the pooled value."
            )
    return out


def print_per_group(report: Dict[str, Any], title: str = "desglose por agente") -> None:
    print(f"\n  -- {title} " + "-" * max(0, 52 - len(title)))
    for group, entry in report["per_group"].items():
        if entry.get("classes_present", 0) < 2:
            print(f"    {group:<8} n={entry['n']:<7} (una sola clase, no evaluable)")
            continue
        line = (f"    {group:<8} n={entry['n']:<7} "
                f"bal_acc={entry.get('balanced_accuracy', float('nan')):.4f} "
                f"macro_f1={entry.get('macro_f1', float('nan')):.4f} "
                f"({len(entry.get('classes_scored', []))} clases)")
        if "lift" in entry:
            line += f"  lift={entry['lift']:.2f}x"
        print(line)
        if "lift_note" in entry:
            print(f"    {'':<8} {entry['lift_note']}")
    pooled = report["pooled"]
    print(f"    {'POOLED':<8} n={pooled['n']:<7} macro_f1={pooled.get('macro_f1', float('nan')):.4f}")
    for warning in report.get("warnings", []):
        print(f"    [AVISO] {warning}")
