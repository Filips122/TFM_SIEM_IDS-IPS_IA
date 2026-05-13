from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import numpy as np
from sklearn.metrics import log_loss, recall_score

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

    if {"train_loss", "val_loss", "epoch"}.issubset(df.columns):
        plt.figure()
        plt.plot(df["epoch"], df["train_loss"], label="train_loss")
        plt.plot(df["epoch"], df["val_loss"], label="val_loss")
        plt.xlabel("epoch")
        plt.ylabel("loss")
        plt.legend()
        plt.tight_layout()
        plt.savefig(out_dir / "curve_loss.png", dpi=160)
        plt.close()

    if {"train_acc", "val_acc", "epoch"}.issubset(df.columns):
        plt.figure()
        plt.plot(df["epoch"], df["train_acc"], label="train_acc")
        plt.plot(df["epoch"], df["val_acc"], label="val_acc")
        plt.xlabel("epoch")
        plt.ylabel("accuracy")
        plt.legend()
        plt.tight_layout()
        plt.savefig(out_dir / "curve_accuracy.png", dpi=160)
        plt.close()


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
    return out
