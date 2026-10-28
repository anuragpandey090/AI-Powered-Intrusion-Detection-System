"""Model Evaluation Module.

Computes comprehensive detection metrics:
- Accuracy, Precision, Recall, F1
- Confusion Matrix (TN, FP, FN, TP)
- False Positive Rate (FPR), False Negative Rate (FNR)
- Class-level metrics & support
- Single-record and batch inference latency
"""

import time
from typing import Dict, Any, List
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)


def evaluate_binary_predictions(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray = None,
    evaluation_name: str = "Evaluation",
) -> Dict[str, Any]:
    """Computes full evaluation suite for binary intrusion detection."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    accuracy = float(accuracy_score(y_true, y_pred))
    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    report_dict = classification_report(
        y_true,
        y_pred,
        target_names=["BENIGN", "ATTACK"],
        output_dict=True,
        zero_division=0,
    )

    return {
        "evaluation_name": evaluation_name,
        "sample_size": int(len(y_true)),
        "confusion_matrix": {
            "TN": int(tn),
            "FP": int(fp),
            "FN": int(fn),
            "TP": int(tp),
        },
        "metrics": {
            "accuracy": round(accuracy, 5),
            "precision": round(precision, 5),
            "recall": round(recall, 5),
            "f1_score": round(f1, 5),
            "false_positive_rate": round(fpr, 5),
            "false_negative_rate": round(fnr, 5),
        },
        "per_class": report_dict,
    }


def measure_inference_latency(
    model,
    X_sample: np.ndarray,
    warmup_runs: int = 5,
    benchmark_runs: int = 20,
) -> Dict[str, float]:
    """Measures single-record and batch inference latencies in milliseconds."""
    # Warmup
    for _ in range(warmup_runs):
        _ = model.predict(X_sample[:10])

    # Single-record latency
    single_record = X_sample[:1]
    single_times = []
    for _ in range(benchmark_runs):
        t0 = time.perf_counter()
        _ = model.predict(single_record)
        t1 = time.perf_counter()
        single_times.append((t1 - t0) * 1000.0)

    # Batch latency (1000 records or sample size)
    batch_size = min(len(X_sample), 1000)
    batch_records = X_sample[:batch_size]
    batch_times = []
    for _ in range(benchmark_runs):
        t0 = time.perf_counter()
        _ = model.predict(batch_records)
        t1 = time.perf_counter()
        batch_times.append((t1 - t0) * 1000.0)

    return {
        "single_record_mean_ms": round(float(np.mean(single_times)), 4),
        "single_record_std_ms": round(float(np.std(single_times)), 4),
        "batch_1000_total_mean_ms": round(float(np.mean(batch_times)), 4),
        "per_record_in_batch_ms": round(float(np.mean(batch_times) / batch_size), 5),
    }
