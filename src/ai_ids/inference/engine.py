"""Inference Engine for AI-IDS.

Provides model loading, validation, chunked batch inference for uploaded CSVs,
single-flow inference for live network streams, alert triggering, and SQLite persistence.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import logging
import joblib
import numpy as np
import pandas as pd

from ai_ids.config import (
    MODEL_BUNDLE_PATH,
    BENIGN_LABEL,
    DEFAULT_CHUNK_SIZE,
)
from ai_ids.preprocessing.cleaner import clean_dataframe_columns
from ai_ids.preprocessing.pipeline import IDSPreprocessor
from ai_ids.alerts.schema import SecurityAlert
from ai_ids.alerts.generator import create_security_alert
from ai_ids.storage.db import insert_alerts_batch, insert_alert

logger = logging.getLogger(__name__)


class InferenceEngine:
    """Production inference engine consuming the trained model bundle."""

    def __init__(self, bundle_path: Path = MODEL_BUNDLE_PATH):
        self.bundle_path = bundle_path
        self.model = None
        self.preprocessor: Optional[IDSPreprocessor] = None
        self.feature_names: List[str] = []
        self.classes: List[str] = []
        self.benign_label: str = BENIGN_LABEL
        self.benign_idx: int = 0
        self.metadata: Dict[str, Any] = {}
        self.is_loaded: bool = False
        self.load_model()

    def load_model(self) -> None:
        """Loads and validates the serialized model bundle."""
        if not self.bundle_path.exists():
            raise FileNotFoundError(
                f"Model bundle not found at {self.bundle_path}. "
                "Please run model training first via 'python scripts/train.py'."
            )

        logger.info("Loading model bundle from %s...", self.bundle_path)
        bundle = joblib.load(self.bundle_path)
        
        self.model = bundle["model"]
        self.preprocessor = bundle["preprocessor"]
        self.feature_names = bundle["feature_names"]
        self.classes = list(bundle["classes"])
        self.benign_label = bundle.get("benign_label", BENIGN_LABEL)
        self.metadata = bundle.get("metadata", {})

        if self.benign_label in self.classes:
            self.benign_idx = self.classes.index(self.benign_label)
        else:
            self.benign_idx = 0

        self.is_loaded = True
        logger.info(
            "Model bundle loaded successfully. Model: %s, Features: %d, Classes: %s",
            self.metadata.get("model_type", "Unknown"),
            len(self.feature_names),
            self.classes,
        )

    def predict_dataframe(
        self,
        df: pd.DataFrame,
        source_name: str = "CSV_UPLOAD",
        save_alerts: bool = True,
        generate_benign_alerts: bool = False,
    ) -> Dict[str, Any]:
        """Runs batch inference on an uploaded DataFrame.
        
        Returns:
            Dictionary with aggregated metrics, predictions DataFrame, and generated alerts.
        """
        if not self.is_loaded:
            self.load_model()

        df_clean = clean_dataframe_columns(df)
        total_records = len(df_clean)

        if total_records == 0:
            return {
                "total_records": 0,
                "benign_count": 0,
                "attack_count": 0,
                "attacks_by_type": {},
                "predictions_df": pd.DataFrame(),
                "alerts": [],
            }

        # Transform using preprocessor fitted on training set
        X_mat = self.preprocessor.transform(df_clean)

        # Model predictions and probabilities
        preds = self.model.predict(X_mat)
        probs = self.model.predict_proba(X_mat)

        confidences = np.max(probs, axis=1)
        attack_probs = 1.0 - probs[:, self.benign_idx]

        # Assemble predictions into DataFrame
        results_df = df_clean.copy()
        results_df["predicted_label"] = np.where(preds == self.benign_label, "BENIGN", "ATTACK")
        results_df["attack_category"] = preds
        results_df["attack_probability"] = np.round(attack_probs, 4)
        results_df["confidence_score"] = np.round(confidences, 4)

        # Count distribution
        benign_mask = (preds == self.benign_label)
        benign_count = int(np.sum(benign_mask))
        attack_count = total_records - benign_count

        attack_cats, cat_counts = np.unique(preds[~benign_mask], return_counts=True)
        attacks_by_type = dict(zip(attack_cats, [int(c) for c in cat_counts]))

        # Generate structured alerts for SIEM layer
        alerts: List[SecurityAlert] = []
        for i in range(total_records):
            pred_class = str(preds[i])
            is_attack = (pred_class != self.benign_label)
            
            if is_attack or generate_benign_alerts:
                row_dict = df_clean.iloc[i].to_dict()
                alert = create_security_alert(
                    source=source_name,
                    flow_index=i,
                    prediction=pred_class,
                    confidence_score=confidences[i],
                    raw_features=row_dict,
                    model_version=self.metadata.get("version", "1.0.0"),
                )
                alerts.append(alert)

        # Persist alerts into SQLite if requested
        if save_alerts and alerts:
            insert_alerts_batch(alerts)

        return {
            "total_records": total_records,
            "benign_count": benign_count,
            "attack_count": attack_count,
            "attacks_by_type": attacks_by_type,
            "predictions_df": results_df,
            "alerts": alerts,
        }

    def predict_single_flow(
        self,
        flow_features: Dict[str, Any],
        source_name: str = "LIVE_INTERFACE",
        save_alert: bool = True,
    ) -> Dict[str, Any]:
        """Runs fast inference on a single real-time network flow."""
        df_single = pd.DataFrame([flow_features])
        result = self.predict_dataframe(
            df_single,
            source_name=source_name,
            save_alerts=save_alert,
            generate_benign_alerts=False,
        )
        pred_row = result["predictions_df"].iloc[0]
        alert = result["alerts"][0] if result["alerts"] else None

        return {
            "predicted_label": pred_row["predicted_label"],
            "attack_category": pred_row["attack_category"],
            "confidence_score": float(pred_row["confidence_score"]),
            "attack_probability": float(pred_row["attack_probability"]),
            "alert": alert.to_dict() if alert else None,
        }
