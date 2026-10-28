"""Tests for Trained Model Inference and Schema Alignment."""

from pathlib import Path
import pytest
import pandas as pd
from ai_ids.config import MODEL_BUNDLE_PATH
from ai_ids.inference.engine import InferenceEngine


def test_inference_engine_loading():
    if not MODEL_BUNDLE_PATH.exists():
        pytest.skip("Model bundle has not been trained yet.")

    engine = InferenceEngine(MODEL_BUNDLE_PATH)
    assert engine.is_loaded
    assert len(engine.feature_names) == 78
    assert "BENIGN" in engine.classes


def test_sample_csv_inference():
    if not MODEL_BUNDLE_PATH.exists():
        pytest.skip("Model bundle has not been trained yet.")

    engine = InferenceEngine(MODEL_BUNDLE_PATH)
    sample_csv = Path("data/sample/test_flows_sample.csv")
    if not sample_csv.exists():
        pytest.skip("Sample CSV does not exist.")

    df = pd.read_csv(sample_csv)
    results = engine.predict_dataframe(df, source_name="TEST_RUN", save_alerts=False)

    assert results["total_records"] == len(df)
    assert results["benign_count"] + results["attack_count"] == len(df)
    assert "predicted_label" in results["predictions_df"].columns
    assert "confidence_score" in results["predictions_df"].columns
    assert len(results["alerts"]) == results["attack_count"]
