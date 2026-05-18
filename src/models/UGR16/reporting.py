from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import numpy as np
from sklearn.metrics import accuracy_score, log_loss, recall_score

from metrics import evaluate_classification


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _try_import_mpl() -> bool:
    try:
        import matplotlib.pyplot as plt  # noqa: F401
        return True
    except Exception:
        return False


HAS_MPL = _try_import_mpl()


def predict_proba_torch(model, X: np.ndarray, device, batch_size: int = 65536) -> np.ndarray:
    import torch

    model.eval()
    probs = []
    with torch.no_grad():
        for i in range(0, len(X), batch_size):
            xb = torch.from_numpy(X[i : i + batch_size]).to(device)
            xb = torch.nan_to_num(xb, nan=0.0, posinf=0.0, neginf=0.0)
            logits = model(xb)
            logits = torch.nan_to_num(logits, nan=0.0, posinf=0.0, neginf=0.0)
            p = torch.softmax(logits, dim=1).cpu().numpy()
            probs.append(p.astype(np.float32, copy=False))
    return np.concatenate(probs, axis=0) if probs else np.empty((0, 0), dtype=np.float32)


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

    if {"train_loss", "val_loss", "epoch"}.issubset(df.columns):
        plt.figure()
        plt.plot(df["epoch"], df["train_loss"], label="train loss")
        plt.plot(df["epoch"], df["val_loss"], label="val loss")
        plt.xlabel("epoch")
        plt.ylabel("loss")
        plt.legend()
        plt.tight_layout()
        plt.savefig(out_dir / "curve_loss.png", dpi=160)
        plt.close()

    if {"train_acc", "val_acc", "epoch"}.issubset(df.columns):
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


def _metric_float(value: Any) -> Optional[float]:
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

    import json
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

    accuracy = [_metric_float(metrics[split_name].get("accuracy")) for split_name in labels]
    logloss = [_metric_float(metrics[split_name].get("logloss")) for split_name in labels]
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


def plot_confusion(cm: np.ndarray, labels: List[str], out_path: Path, title: str) -> None:
    if not HAS_MPL:
        return

    import matplotlib.pyplot as plt

    ensure_dir(out_path.parent)
    plt.figure()
    plt.imshow(cm, aspect="auto")
    plt.title(title)
    plt.xlabel("Pred")
    plt.ylabel("True")
    plt.xticks(range(len(labels)), labels, rotation=45, ha="right")
    plt.yticks(range(len(labels)), labels)
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, str(cm[i, j]), ha="center", va="center")
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def _pick_positive_index(class_names: Sequence[str]) -> int:
    lower = [str(c).lower() for c in class_names]
    for i, c in enumerate(lower):
        if "attack" in c:
            return i
    return 1 if len(class_names) == 2 else 0


def plot_roc_curve_binary(y_true_int: np.ndarray, proba: np.ndarray, class_names: Sequence[str], out_path: Path) -> Optional[float]:
    if not HAS_MPL:
        return None

    from sklearn.metrics import roc_auc_score, roc_curve
    import matplotlib.pyplot as plt

    pos_idx = _pick_positive_index(class_names)
    y = (y_true_int == pos_idx).astype(int)
    y_score = proba[:, pos_idx].astype(np.float64, copy=False)

    mask = np.isfinite(y_score)
    y = y[mask]
    y_score = y_score[mask]
    if len(np.unique(y)) < 2:
        return None

    auc = float(roc_auc_score(y, y_score))
    fpr, tpr, _ = roc_curve(y, y_score)

    ensure_dir(out_path.parent)
    plt.figure()
    plt.plot(fpr, tpr, label=f"AUC={auc:.4f}")
    plt.plot([0, 1], [0, 1], linestyle="--", label="random")
    plt.xlabel("FPR")
    plt.ylabel("TPR")
    plt.title("ROC curve (test)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()
    return auc


def expected_calibration_error(conf: np.ndarray, correct: np.ndarray, n_bins: int = 15) -> float:
    conf = np.asarray(conf, dtype=np.float64)
    correct = np.asarray(correct, dtype=np.float64)

    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = len(conf)
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        m = (conf >= lo) & (conf < hi) if i < n_bins - 1 else (conf >= lo) & (conf <= hi)
        if not np.any(m):
            continue
        acc_bin = float(np.mean(correct[m]))
        conf_bin = float(np.mean(conf[m]))
        ece += (np.sum(m) / n) * abs(acc_bin - conf_bin)
    return float(ece)


def plot_calibration_and_ece(
    y_true_int: np.ndarray,
    proba: np.ndarray,
    class_names: Sequence[str],
    out_path: Path,
    n_bins: int = 15,
) -> float:
    if not HAS_MPL:
        return float("nan")

    import matplotlib.pyplot as plt
    from sklearn.calibration import calibration_curve

    n_classes = proba.shape[1]
    ensure_dir(out_path.parent)

    if n_classes == 2:
        pos_idx = _pick_positive_index(class_names)
        y = (y_true_int == pos_idx).astype(int)
        conf = proba[:, pos_idx].astype(np.float64, copy=False)
        mask = np.isfinite(conf)
        y = y[mask]
        conf = conf[mask]
        frac_pos, mean_pred = calibration_curve(y, conf, n_bins=n_bins, strategy="uniform")
        pred_bin = (conf >= 0.5).astype(int)
        correct = (pred_bin == y).astype(int)
        ece = expected_calibration_error(conf, correct, n_bins=n_bins)
    else:
        conf = proba.max(axis=1).astype(np.float64, copy=False)
        pred = proba.argmax(axis=1)
        mask = np.isfinite(conf)
        conf = conf[mask]
        pred = pred[mask]
        y = y_true_int[mask]
        correct = (pred == y).astype(int)
        frac_pos, mean_pred = calibration_curve(correct, conf, n_bins=n_bins, strategy="uniform")
        ece = expected_calibration_error(conf, correct, n_bins=n_bins)

    plt.figure()
    plt.plot(mean_pred, frac_pos, marker="o", label="model")
    plt.plot([0, 1], [0, 1], linestyle="--", label="perfect")
    plt.xlabel("Predicted confidence")
    plt.ylabel("Empirical accuracy")
    plt.title(f"Calibration (ECE={ece:.4f})")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()

    return float(ece)


def plot_corr_matrix(X: np.ndarray, out_path: Path, max_rows: int = 200_000, seed: int = 42) -> None:
    if not HAS_MPL:
        return

    import matplotlib.pyplot as plt

    if X.size == 0 or X.shape[1] == 0:
        return

    rng = np.random.default_rng(seed)
    n = len(X)
    if n > max_rows:
        idx = rng.choice(n, size=max_rows, replace=False)
        X = X[idx]

    with np.errstate(invalid="ignore", divide="ignore", over="ignore", under="ignore"):
        C = np.corrcoef(X, rowvar=False)
    C = np.nan_to_num(C, nan=0.0, posinf=0.0, neginf=0.0)
    if C.shape[0] == C.shape[1]:
        np.fill_diagonal(C, 1.0)

    ensure_dir(out_path.parent)
    plt.figure(figsize=(10, 8))
    plt.imshow(C, aspect="auto")
    plt.title("Feature correlation (sampled)")
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def save_anomaly_plots(
    root: Path,
    split_name: str,
    y_true_binary: np.ndarray,
    scores: np.ndarray,
    positive_label: str = "ATTACK",
) -> Dict[str, Optional[float]]:
    out = {"roc_auc": None, "pr_auc": None}
    if not HAS_MPL:
        return out

    from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve
    import matplotlib.pyplot as plt

    plots_dir = root / "plots"
    ensure_dir(plots_dir)

    y = np.array([1 if str(v) == positive_label else 0 for v in y_true_binary], dtype=int)
    s = np.asarray(scores, dtype=np.float64)
    mask = np.isfinite(s)
    y = y[mask]
    s = s[mask]

    if len(y) == 0:
        return out

    plt.figure()
    plt.hist(s[y == 0], bins=60, alpha=0.6, label="BENIGN")
    plt.hist(s[y == 1], bins=60, alpha=0.6, label="ATTACK")
    plt.xlabel("anomaly score")
    plt.ylabel("count")
    plt.title(f"Anomaly score distribution ({split_name})")
    plt.legend()
    plt.tight_layout()
    plt.savefig(plots_dir / f"anomaly_score_hist_{split_name}.png", dpi=160)
    plt.close()

    if len(np.unique(y)) > 1:
        fpr, tpr, _ = roc_curve(y, s)
        roc = float(roc_auc_score(y, s))
        prec, rec, _ = precision_recall_curve(y, s)
        pr = float(average_precision_score(y, s))

        plt.figure()
        plt.plot(fpr, tpr, label=f"AUC={roc:.4f}")
        plt.plot([0, 1], [0, 1], "--", label="random")
        plt.xlabel("FPR")
        plt.ylabel("TPR")
        plt.title(f"Anomaly ROC ({split_name})")
        plt.legend()
        plt.tight_layout()
        plt.savefig(plots_dir / f"anomaly_roc_{split_name}.png", dpi=160)
        plt.close()

        plt.figure()
        plt.plot(rec, prec, label=f"AP={pr:.4f}")
        plt.xlabel("Recall")
        plt.ylabel("Precision")
        plt.title(f"Anomaly PR ({split_name})")
        plt.legend()
        plt.tight_layout()
        plt.savefig(plots_dir / f"anomaly_pr_{split_name}.png", dpi=160)
        plt.close()

        out["roc_auc"] = roc
        out["pr_auc"] = pr

    return out


def save_metrics_and_plots(
    root: Path,
    split_name: str,
    y_true_int: np.ndarray,
    proba: np.ndarray,
    class_names: Sequence[str],
    make_roc_and_calibration: bool = False,
) -> Dict[str, Any]:
    plots_dir = root / "plots"
    ensure_dir(plots_dir)

    y_pred = proba.argmax(axis=1)
    rep = evaluate_classification(y_true_int, y_pred, labels=list(range(len(class_names))))

    macro_rec = float(recall_score(y_true_int, y_pred, average="macro", zero_division=0))
    out: Dict[str, Any] = {
        "accuracy": rep.accuracy,
        "balanced_accuracy": rep.balanced_accuracy,
        "macro_f1": rep.macro_f1,
        "weighted_f1": rep.weighted_f1,
        "macro_recall": macro_rec,
        "logloss": None,
        "roc_auc": None,
        "ece": None,
        "labels": [str(c) for c in class_names],
    }

    try:
        out["logloss"] = float(log_loss(y_true_int, proba, labels=list(range(len(class_names)))))
    except Exception:
        out["logloss"] = None

    cm_png = plots_dir / f"confusion_{split_name}.png"
    plot_confusion(rep.confusion, [str(c) for c in class_names], cm_png, title=f"Confusion ({split_name})")

    if make_roc_and_calibration:
        if proba.shape[1] == 2:
            out["roc_auc"] = plot_roc_curve_binary(y_true_int, proba, class_names, plots_dir / "roc_curve.png")
        out["ece"] = plot_calibration_and_ece(y_true_int, proba, class_names, plots_dir / "calibration.png")

    import json

    (root / f"metrics_{split_name}.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    plot_overfitting_metrics(root)
    return out
