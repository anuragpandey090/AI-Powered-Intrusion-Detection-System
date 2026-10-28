"""Tests for Data Cleaning and Preprocessing Pipeline."""

import numpy as np
import pandas as pd
import pytest
from ai_ids.preprocessing.cleaner import (
    clean_dataframe_columns,
    map_to_binary,
    map_to_attack_category,
    sanitize_numeric_features,
)
from ai_ids.preprocessing.pipeline import IDSPreprocessor


def test_clean_dataframe_columns():
    df = pd.DataFrame({" Destination Port ": [80, 443], " Flow Duration": [100, 200]})
    df_clean = clean_dataframe_columns(df)
    assert list(df_clean.columns) == ["Destination Port", "Flow Duration"]


def test_map_to_binary():
    labels = pd.Series(["BENIGN", "DDoS", "PortScan", "BENIGN"])
    bin_labels = map_to_binary(labels)
    assert list(bin_labels) == [0, 1, 1, 0]


def test_map_to_attack_category():
    labels = pd.Series(["BENIGN", "DDoS", "PortScan", "Web Attack \ufffd Brute Force", "DoS Hulk"])
    cats = map_to_attack_category(labels)
    assert list(cats) == ["BENIGN", "DDoS", "PortScan", "Web_Attack", "DoS"]


def test_sanitize_numeric_features():
    df = pd.DataFrame({
        "feat1": [1.0, np.inf, -np.inf, np.nan, 5.0],
        "Label": ["BENIGN", "DDoS", "DDoS", "BENIGN", "BENIGN"],
    })
    sanitized = sanitize_numeric_features(df)
    assert np.isnan(sanitized.loc[1, "feat1"])
    assert np.isnan(sanitized.loc[2, "feat1"])
    assert sanitized.loc[4, "feat1"] == 5.0


def test_preprocessor_fit_transform():
    train_df = pd.DataFrame({
        "col_a": [1.0, 2.0, np.nan, 4.0, 5.0],
        "col_b": [10.0, np.inf, 30.0, 40.0, 50.0],
        "Label": ["BENIGN", "DDoS", "BENIGN", "DDoS", "BENIGN"],
    })
    prep = IDSPreprocessor()
    transformed = prep.fit_transform(train_df)

    assert prep.is_fitted
    assert prep.feature_names == ["col_a", "col_b"]
    assert transformed.shape == (5, 2)
    # Check no NaNs or Infs remain
    assert not np.isnan(transformed).any()
    assert not np.isinf(transformed).any()

    # Test transform on new data with missing column
    test_df = pd.DataFrame({"col_a": [10.0, 20.0]})
    test_transformed = prep.transform(test_df)
    assert test_transformed.shape == (2, 2)
    # col_b should be imputed with learned median
    assert test_transformed[0, 1] == prep.medians["col_b"]
