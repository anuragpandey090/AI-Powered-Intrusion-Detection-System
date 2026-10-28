# Verification, Testing & Quality Assurance

This document details the automated test suite, verification methodologies, and test coverage for the AI-IDS system.

---

## 1. Test Architecture & Coverage

The automated test suite is implemented using `pytest` and spans five test modules located in `tests/`:

| Test Module | Focus Area | Key Verifications |
| :--- | :--- | :--- |
| `tests/test_preprocessing.py` | Data Cleaning & Transformation | Column header trimming, duplicate naming, label normalization, infinity replacement, and zero data-leakage during preprocessor fitting. |
| `tests/test_alerts_storage.py` | SIEM Alerts & SQLite | Alert model instantiation, Pydantic validation, atomic SQLite insertion, indexed severity filtering, and stats aggregation. |
| `tests/test_models.py` | Inference Engine | Verification of loaded `.joblib` model bundle, 78 canonical feature ordering, batch inference on `data/sample/test_flows_sample.csv`, and confidence scores. |
| `tests/test_log_adapter.py` | System Log Ingestion | Regex extraction of SSH failed/accepted events, IP tracking, and automatic threshold-based Brute-Force alert triggering. |
| `tests/test_api.py` | REST API Endpoints | Testing `/`, `/alerts/stats`, and `/status/capture` HTTP contracts via Starlette TestClient. |

---

## 2. Test Execution Commands

To execute the test suite in Windows PowerShell:

```powershell
# Set PYTHONPATH to include src and execute pytest
$env:PYTHONPATH='src'
python -m pytest tests/ -v
```

### Expected Output Summary:

```text
============================= test session starts =============================
platform win32 -- Python 3.13.2, pytest-9.1.1
collected 14 items

tests/test_alerts_storage.py::test_create_security_alert PASSED          [  7%]
tests/test_alerts_storage.py::test_sqlite_insert_and_query PASSED        [ 14%]
tests/test_api.py::test_root_endpoint PASSED                             [ 21%]
tests/test_api.py::test_capture_status_endpoint PASSED                   [ 28%]
tests/test_api.py::test_alerts_stats_endpoint PASSED                     [ 35%]
tests/test_log_adapter.py::test_ssh_log_parsing PASSED                   [ 42%]
tests/test_log_adapter.py::test_brute_force_correlation PASSED           [ 50%]
tests/test_models.py::test_inference_engine_loading PASSED               [ 57%]
tests/test_models.py::test_sample_csv_inference PASSED                   [ 64%]
tests/test_preprocessing.py::test_clean_dataframe_columns PASSED         [ 71%]
tests/test_preprocessing.py::test_map_to_binary PASSED                   [ 78%]
tests/test_preprocessing.py::test_map_to_attack_category PASSED          [ 85%]
tests/test_preprocessing.py::test_sanitize_numeric_features PASSED       [ 92%]
tests/test_preprocessing.py::test_preprocessor_fit_transform PASSED      [100%]

============================== 14 passed in 4.32s ==============================
```

---

## 3. Specific Regression Safeguards

1. **Data Leakage Prevention:**
   `test_preprocessor_fit_transform` asserts that when transforming unseen test records with missing features, the preprocessor uses medians calculated exclusively during the training fit stage, ensuring test data distributions cannot influence the model.
2. **Strict IDS Boundary Assertion:**
   `test_root_endpoint` programmatically checks that `safety_boundary.strict_ids_mode` is `True` and `automated_prevention_enabled` is `False`.
3. **Encoding & Format Immunity:**
   `test_map_to_attack_category` verifies that unicode anomalies (e.g., non-ASCII characters in Web Attack strings from CIC-IDS2017) are mapped without throwing character encoding exceptions.
