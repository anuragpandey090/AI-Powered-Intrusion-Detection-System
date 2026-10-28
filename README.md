# AI-Powered Intrusion Detection System (AI-IDS)

[![Python 3.13](https://img.shields.io/badge/Python-3.13.2-blue.svg)](https://www.python.org/)
[![License: Academic](https://img.shields.io/badge/License-Academic%20Evaluation-green.svg)]()
[![Dataset: CIC-IDS2017](https://img.shields.io/badge/Dataset-CIC--IDS2017%20(Real)-orange.svg)](https://www.unb.ca/cic/datasets/ids-2017.html)
[![Tests: 14/14 Passing](https://img.shields.io/badge/Tests-14%2F14%20Passing-brightgreen.svg)]()
[![Safety: Strict IDS](https://img.shields.io/badge/Mode-Strict%20IDS%20(No%20Disruption)-red.svg)]()

A clean, modular, demonstrable machine learning-driven Intrusion Detection System developed for the Major Project submission, aligned with the Phase-I report titled *"AI-Powered Intrusion Detection System."*

---

## 1. Core Objectives & Strict Safety Boundary

### Project Objectives:
1. **Modular Architecture:** Clean separation across data ingestion, preprocessing, training, inference, and SIEM alerting.
2. **Dual-Telemetry Ingestion:** Decoupled adapters for network flow CSVs and system authentication logs.
3. **Data Sanitation & Leakage Prevention:** Auditable inspection of 2.83 million real flow records from the CIC-IDS2017 benchmark with learned preprocessing strictly on training partitions.
4. **Supervised ML Core:** High-performance Scikit-learn `RandomForestClassifier` baseline achieving **99.35% accuracy** and sub-millisecond inference latency (0.059 ms/flow).
5. **SIEM Concepts & Persistence:** Standardized alert schema with structured severity levels persisted into SQLite.
6. **Academic Rigor:** In-distribution random-split benchmarking contrasted against out-of-distribution whole-file holdout testing.

> [!CAUTION]
> **STRICT SAFETY BOUNDARY (IDS vs. IPS):**  
> This system is an **Intrusion Detection System**, not an Intrusion Prevention System.  
> The software **never** automatically blocks IP addresses, modifies firewall rules (`netsh`, `iptables`), terminates operating system processes, or disrupts network traffic. All responses are restricted to generating, logging, and persisting security alerts.

---

## 2. Directory Structure

```text
AI-IDS-Final/
├── app/
│   └── dashboard.py               # Streamlit interactive security operations console
├── data/
│   ├── manifests/
│   │   └── dataset_audit_manifest.json  # Audited SHA-256 hashes, schemas & counts
│   └── sample/
│       └── test_flows_sample.csv  # 500-flow sample for instant demonstration
├── docs/
│   ├── ADDITIONAL_TECHNOLOGIES.md # Technical rationale & viva explanation for added tools
│   ├── DATASET_AND_METHODOLOGY.md # Dataset integrity audit & cleaning decisions
│   ├── MODEL_CARD.md              # Machine learning model card & metrics
│   ├── PROJECT_REQUIREMENTS.md    # Functional requirements & safety boundaries
│   ├── SUPERVISOR_DEMO_GUIDE.md   # 5-minute supervisor demonstration script
│   ├── SYSTEM_ARCHITECTURE.md     # Architectural layers, diagrams & data flows
│   ├── TESTING.md                 # Test suite documentation & coverage
│   └── VIVA_QUESTIONS_AND_ANSWERS.md # Technical viva Q&A for academic defense
├── models/
│   ├── ids_random_forest_bundle.joblib  # Serialized model, preprocessor & schema
│   └── training_metadata.json     # Hyperparameters, metrics & training timestamps
├── reports/
│   ├── evaluation_report.json     # Full JSON evaluation results
│   └── evaluation_summary.md      # Academic evaluation report in markdown
├── scripts/
│   ├── inspect_dataset.py         # Non-destructive chunked raw dataset auditor
│   ├── train.py                   # Model training & dual evaluation CLI
│   └── run_demo.py                # 10-second end-to-end CLI demonstration
├── src/
│   └── ai_ids/
│       ├── alerts/                # SIEM alert schema & generator
│       ├── api/                   # FastAPI REST API endpoints
│       ├── config.py              # Central configuration & paths
│       ├── datasets/              # Dataset inspection & memory-bounded loader
│       ├── inference/             # Batch & single-flow inference engine
│       ├── ingestion/             # CSV ingestion, log adapter & live probe
│       ├── models/                # Scikit-learn trainer & evaluator
│       ├── preprocessing/         # Feature cleaning & leakage-free preprocessor
│       └── storage/               # SQLite persistent database layer
├── tests/                         # Pytest automated test suite (14 tests)
├── requirements.txt               # Pinned Python package dependencies
└── README.md                      # Project documentation
```

---

## 3. Quick Start & Execution Guide (Windows PowerShell)

All commands are designed to run in **Windows PowerShell** from the project root (`E:\IILM\AI-IDS-Final`).

### Step 1: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 2: Audit the Raw CIC-IDS2017 Dataset
*Scans 2.83 million records, records SHA-256 hashes, and detects infinities/missing values without modifying raw files:*
```powershell
$env:PYTHONPATH='src'
python scripts/inspect_dataset.py
```

### Step 3: Train the Model Baseline & Generate Evaluation Reports
*Trains Random Forest on 70,000 balanced flows, evaluates holdout files, and exports `models/ids_random_forest_bundle.joblib`:*
```powershell
$env:PYTHONPATH='src'
python scripts/train.py
```

### Step 4: Run the 10-Second End-to-End CLI Demo
```powershell
$env:PYTHONPATH='src'
python scripts/run_demo.py
```

### Step 5: Run the Automated Test Suite (14 Tests)
```powershell
$env:PYTHONPATH='src'
python -m pytest tests/ -v
```

### Step 6: Launch the Web Operations Dashboard
```powershell
$env:PYTHONPATH='src'
streamlit run app/dashboard.py
```
*(Access in your web browser at `http://localhost:8501`)*

### Step 7: Launch the FastAPI REST Server (Optional)
```powershell
$env:PYTHONPATH='src'
uvicorn ai_ids.api.server:app --port 8000 --reload
```
*(Interactive API documentation at `http://localhost:8000/docs`)*

---

## 4. Empirical Evaluation Results

Metrics recorded from actual execution on the **CIC-IDS2017** benchmark:

| Evaluation Partition | Accuracy | Precision | Recall | F1-Score | False Positive Rate | Throughput |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Random-Split (In-Distribution)** | **99.35%** | **98.13%** | **99.62%** | **98.87%** | **0.760%** | **~16,700 flows/sec** |
| **PortScan Holdout (Out-of-Distribution)** | **97.56%** | **0.55%** | **57.14%** | **1.08%** | **2.431%** | — |

---

## 5. Implementation Status Checklist

- [x] **Raw Dataset Auditing:** All 8 CSV files verified with SHA-256 hashes and chunked counting.
- [x] **Zero Data Leakage:** Preprocessor fits imputation medians exclusively on the training partition.
- [x] **Model Serialization:** Re-loadable `.joblib` bundle packaging model, preprocessor, and schema.
- [x] **Mode 1 (CSV Detection):** Fully functional flow upload, schema validation, inference, and CSV export.
- [x] **SIEM Alert Center:** SQLite persistence with indexing and filtering by severity.
- [x] **System Log Adapter:** Separated parser for SSH authentication logs correlating brute-force attacks.
- [x] **Mode 2 (Live Traffic):** Host capability probe detecting Windows socket permissions honestly.
- [x] **Automated Testing:** 14/14 passing tests in `pytest`.
- [x] **Documentation:** Complete academic deliverables prepared for supervisor demonstration and viva defense.
