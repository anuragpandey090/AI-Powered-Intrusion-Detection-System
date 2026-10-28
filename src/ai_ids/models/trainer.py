"""Model Training Module for AI-IDS.

Implements:
- Training of Scikit-learn RandomForestClassifier on real CIC-IDS2017 network flow records.
- Preprocessor fitting strictly on training split (preventing data leakage).
- Standard random-split evaluation and whole-file holdout evaluation.
- Serialization of complete model bundle (model, preprocessor, schema, metadata).
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import json
import logging
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from ai_ids.config import (
    DATASET_DIR,
    MODELS_DIR,
    REPORTS_DIR,
    MODEL_BUNDLE_PATH,
    TRAINING_METADATA_PATH,
    RANDOM_SEED,
    BENIGN_LABEL,
)
from ai_ids.datasets.loader import load_dataset_sample, load_single_file_for_holdout
from ai_ids.preprocessing.pipeline import IDSPreprocessor
from ai_ids.models.evaluator import evaluate_binary_predictions, measure_inference_latency

logger = logging.getLogger(__name__)


def train_ids_model(
    dataset_dir: Path = DATASET_DIR,
    n_estimators: int = 100,
    max_depth: int = 16,
    samples_per_attack: int = 15_000,
    samples_benign: int = 50_000,
    test_size: float = 0.2,
    holdout_file_name: Optional[str] = "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    bundle_save_path: Path = MODEL_BUNDLE_PATH,
    random_state: int = RANDOM_SEED,
) -> Dict[str, Any]:
    """Trains a multi-class intrusion detection model, evaluates it,
    and packages a self-contained bundle for production inference.
    """
    logger.info("Starting AI-IDS training pipeline...")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load real data from CIC-IDS2017
    # Note: If holdout_file_name is provided, we can either train across all files except holdout,
    # or train on standard subset and evaluate on holdout.
    all_files = [f.name for f in dataset_dir.glob("*.csv")]
    train_files = [f for f in all_files if f != holdout_file_name] if holdout_file_name else all_files

    logger.info("Files used for training pool: %s", train_files)
    X_raw, y_binary, y_category = load_dataset_sample(
        dataset_dir=dataset_dir,
        files_to_include=train_files,
        samples_per_attack=samples_per_attack,
        samples_benign=samples_benign,
        random_state=random_state,
    )

    # 2. Train / Test Split (Reproducible, stratified by category)
    X_train_df, X_test_df, y_cat_train, y_cat_test = train_test_split(
        X_raw,
        y_category,
        test_size=test_size,
        stratify=y_category,
        random_state=random_state,
    )

    y_bin_train = (y_cat_train != BENIGN_LABEL).astype(int).to_numpy()
    y_bin_test = (y_cat_test != BENIGN_LABEL).astype(int).to_numpy()

    logger.info("Train set shape: %s | Test set shape: %s", X_train_df.shape, X_test_df.shape)

    # 3. Fit Preprocessing Pipeline strictly on Train Set
    logger.info("Fitting preprocessing pipeline on training features...")
    preprocessor = IDSPreprocessor()
    X_train_arr = preprocessor.fit_transform(X_train_df)
    X_test_arr = preprocessor.transform(X_test_df)

    # 4. Train Random Forest Classifier
    logger.info(
        "Training RandomForestClassifier (n_estimators=%d, max_depth=%d, n_jobs=-1)...",
        n_estimators,
        max_depth,
    )
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        n_jobs=-1,
        random_state=random_state,
        class_weight="balanced_subsample",
    )
    clf.fit(X_train_arr, y_cat_train)

    classes_list = list(clf.classes_)
    benign_idx = classes_list.index(BENIGN_LABEL) if BENIGN_LABEL in classes_list else 0

    # 5. Evaluate on Random-Split Test Set
    logger.info("Evaluating on random-split test set...")
    cat_preds_test = clf.predict(X_test_arr)
    cat_probs_test = clf.predict_proba(X_test_arr)
    bin_preds_test = (cat_preds_test != BENIGN_LABEL).astype(int)
    attack_probs_test = 1.0 - cat_probs_test[:, benign_idx]

    random_split_metrics = evaluate_binary_predictions(
        y_true=y_bin_test,
        y_pred=bin_preds_test,
        y_proba=attack_probs_test,
        evaluation_name="Random-Split Test Evaluation",
    )

    # 6. Benchmark Inference Latency
    logger.info("Benchmarking inference latency...")
    latency_stats = measure_inference_latency(clf, X_test_arr)
    random_split_metrics["latency_ms"] = latency_stats

    # 7. Whole-File Holdout Evaluation (if holdout file exists)
    holdout_metrics = None
    if holdout_file_name:
        holdout_path = dataset_dir / holdout_file_name
        if holdout_path.exists():
            logger.info("Executing holdout evaluation on entire file: %s", holdout_file_name)
            X_holdout_raw, y_bin_holdout, y_cat_holdout = load_single_file_for_holdout(
                holdout_path,
                max_records=30_000,
                random_state=random_state,
            )
            X_holdout_arr = preprocessor.transform(X_holdout_raw)
            cat_preds_holdout = clf.predict(X_holdout_arr)
            bin_preds_holdout = (cat_preds_holdout != BENIGN_LABEL).astype(int)
            holdout_metrics = evaluate_binary_predictions(
                y_true=y_bin_holdout.to_numpy(),
                y_pred=bin_preds_holdout,
                evaluation_name=f"Holdout File: {holdout_file_name}",
            )

    # 8. Compile Metadata and Artifact Bundle
    training_metadata = {
        "model_type": "RandomForestClassifier",
        "library": "scikit-learn",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": random_state,
        "n_estimators": n_estimators,
        "max_depth": max_depth,
        "num_features": len(preprocessor.feature_names),
        "ordered_features": preprocessor.feature_names,
        "classes": classes_list,
        "benign_label": BENIGN_LABEL,
        "dataset_source": str(dataset_dir),
        "train_samples_count": int(len(X_train_df)),
        "test_samples_count": int(len(X_test_df)),
        "random_split_performance": random_split_metrics["metrics"],
        "latency_profile": latency_stats,
    }

    bundle = {
        "model": clf,
        "preprocessor": preprocessor,
        "feature_names": preprocessor.feature_names,
        "classes": classes_list,
        "benign_label": BENIGN_LABEL,
        "metadata": training_metadata,
    }

    # 9. Save Artifacts
    logger.info("Saving model bundle to: %s", bundle_save_path)
    joblib.dump(bundle, bundle_save_path, compress=3)

    with open(TRAINING_METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(training_metadata, f, indent=2)

    # Save evaluation reports
    eval_report = {
        "random_split_evaluation": random_split_metrics,
        "whole_file_holdout_evaluation": holdout_metrics,
    }
    eval_report_json = REPORTS_DIR / "evaluation_report.json"
    with open(eval_report_json, "w", encoding="utf-8") as f:
        json.dump(eval_report, f, indent=2)

    # Generate Markdown Summary
    eval_summary_md = REPORTS_DIR / "evaluation_summary.md"
    generate_markdown_summary(eval_summary_md, training_metadata, random_split_metrics, holdout_metrics)

    logger.info("Training and evaluation successfully completed!")
    return eval_report


def generate_markdown_summary(
    output_path: Path,
    metadata: Dict[str, Any],
    random_metrics: Dict[str, Any],
    holdout_metrics: Optional[Dict[str, Any]],
):
    """Generates an academic evaluation report in Markdown format."""
    rand_m = random_metrics["metrics"]
    rand_cm = random_metrics["confusion_matrix"]
    lat = random_metrics["latency_ms"]

    content = f"""# AI-IDS Model Evaluation & Experimental Report

**Generated:** {metadata['created_at']}  
**Model Architecture:** Random Forest (`n_estimators={metadata['n_estimators']}`, `max_depth={metadata['max_depth']}`)  
**Dataset:** CIC-IDS2017 Real Flow Records  
**Total Training Flows:** {metadata['train_samples_count']:,}  
**Total Test Flows:** {metadata['test_samples_count']:,}  
**Input Features:** {metadata['num_features']} Flow Metrics  

---

## 1. Random-Split Test Evaluation (80/20 Stratified Partition)

| Metric | Score | Explanation |
| :--- | :--- | :--- |
| **Accuracy** | **{rand_m['accuracy'] * 100:.2f}%** | Overall fraction of flows correctly classified |
| **Precision** | **{rand_m['precision'] * 100:.2f}%** | Ability not to label benign traffic as an attack |
| **Recall (Sensitivity)** | **{rand_m['recall'] * 100:.2f}%** | Ability to detect true attack events |
| **F1-Score** | **{rand_m['f1_score'] * 100:.2f}%** | Harmonic balance between precision and recall |
| **False Positive Rate (FPR)** | **{rand_m['false_positive_rate'] * 100:.3f}%** | Percentage of benign traffic triggering false alarms |
| **False Negative Rate (FNR)** | **{rand_m['false_negative_rate'] * 100:.3f}%** | Percentage of attacks that slipped through unnoticed |

### Confusion Matrix
- **True Negatives (TN - Benign correctly identified):** {rand_cm['TN']:,}
- **False Positives (FP - False alarms):** {rand_cm['FP']:,}
- **False Negatives (FN - Missed attacks):** {rand_cm['FN']:,}
- **True Positives (TP - Attacks accurately detected):** {rand_cm['TP']:,}

### Inference Latency Benchmark
- **Single-Record Latency:** `{lat['single_record_mean_ms']:.4f} ms` per flow
- **Batch Processing Rate:** `{lat['per_record_in_batch_ms']:.5f} ms` per flow (`{1000.0 / (lat['per_record_in_batch_ms'] + 1e-6):,.0f}` flows/sec throughput)

---
"""

    if holdout_metrics:
        h_m = holdout_metrics["metrics"]
        h_cm = holdout_metrics["confusion_matrix"]
        content += f"""## 2. Whole-File Holdout Evaluation
**Holdout Target:** `{holdout_metrics['evaluation_name']}`  
*Note: Evaluates generalization when an entire attack dataset capture file is withheld from training.*

| Metric | Score |
| :--- | :--- |
| **Accuracy** | **{h_m['accuracy'] * 100:.2f}%** |
| **Precision** | **{h_m['precision'] * 100:.2f}%** |
| **Recall** | **{h_m['recall'] * 100:.2f}%** |
| **F1-Score** | **{h_m['f1_score'] * 100:.2f}%** |
| **False Positive Rate (FPR)** | **{h_m['false_positive_rate'] * 100:.3f}%** |
| **False Negative Rate (FNR)** | **{h_m['false_negative_rate'] * 100:.3f}%** |

### Holdout Confusion Matrix
- **True Negatives (TN):** {h_cm['TN']:,}
- **False Positives (FP):** {h_cm['FP']:,}
- **False Negatives (FN):** {h_cm['FN']:,}
- **True Positives (TP):** {h_cm['TP']:,}

---
"""

    content += """## 3. Methodological Discussion & Limitations

1. **Random-Split vs. Whole-File Holdout:**
   - Random-split evaluation samples flows uniformly across captured PCAP sessions. High random-split scores reflect strong in-distribution pattern recognition.
   - Whole-file holdout tests detection on distinct sessions where network topology, port usage, and traffic timing may differ.
2. **CIC-IDS2017 Dataset Constraints:**
   - As an offline research dataset collected in an emulation lab, zero-day attacks and evolving modern protocols are not guaranteed to yield identical production accuracy.
   - IDS strictly monitors and alerts; no disruptive IPS mitigations are applied.
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
