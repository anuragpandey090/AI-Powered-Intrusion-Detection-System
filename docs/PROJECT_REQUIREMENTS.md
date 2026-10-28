# Project Requirements & Scope Specification

## 1. Project Title & Scope

**Project Title:** AI-Powered Intrusion Detection System (AI-IDS)  
**Academic Submission Phase:** Phase-II Clean Implementation & Verification  
**Primary Discipline:** Cybersecurity, Machine Learning, Applied Network Security  

### Objectives Aligned with Phase-I Report:
1. **Modular Architecture:** Design a clean, decoupled architecture separating data ingestion, feature transformation, model inference, and alert correlation.
2. **Multi-Source Ingestion:** Support ingestion of network flow records and textual system authentication logs via distinct adapters.
3. **Data Sanitation & Leakage Prevention:** Implement explicit, auditable data cleaning for malformed rows, infinities, and missing values, fitting all preprocessing strictly on training splits.
4. **Machine Learning Detection Engine:** Implement supervised learning using Scikit-learn (Random Forest) as the benchmark baseline, providing honest comparison with alternative deep learning frameworks.
5. **SIEM Concepts & Persistence:** Generate structured alerts with standardized severity ratings, timestamps, flow index context, and persistent SQLite storage.
6. **Empirical Evaluation:** Benchmark detection accuracy, precision, recall, F1, false-positive rate, false-negative rate, and per-flow inference latency across both random-split and whole-file holdout experiments.
7. **Strict IDS Boundary:** Restrict the project to passive monitoring, detection, and alerting.

---

## 2. Strict Safety Boundary (IDS vs. IPS)

This software operates strictly as an **Intrusion Detection System (IDS)**, not an **Intrusion Prevention System (IPS)**.

### Mandatory Operational Boundaries:
- **No IP Blacklisting:** The software will never modify system firewall rules (e.g., `iptables`, `netsh`, Windows Defender Firewall) or add network blocking entries.
- **No Connection Termination:** The software will never forge TCP RST packets or forcibly terminate active network sockets.
- **No Process Disruption:** The software will never terminate system processes or isolate host machines from local subnets.
- **Response Limitation:** Every response action is strictly limited to generating, logging, and persisting structured security alerts for human security analyst review.

---

## 3. Environment & Operating Constraints

- **Host Operating System:** Microsoft Windows (x86_64).
- **Available Physical Memory:** ~12 GB RAM. Memory usage during data streaming and model training must remain strictly bounded (< 4 GB resident memory).
- **Runtime Interpreter:** Python 3.13.2.
- **Raw Benchmark Dataset:** Canadian Institute for Cybersecurity CIC-IDS2017 (`MachineLearningCVE`).
  - Path: `E:\IILM\Major Project\raw\MachineLearningCVE`
  - Total Raw Files: 8 CSV files (884 MB total).
  - Total Flow Instances: 2,830,743 network flows.
  - Integrity Policy: Read original CSV files directly in read-only streaming mode. Never duplicate, overwrite, or modify the source dataset directory.

---

## 4. Functional Requirements

| ID | Requirement Category | Detailed Description | Verification Method |
| :--- | :--- | :--- | :--- |
| **FR-01** | Dataset Audit | Compute SHA-256 checksums, count rows, check schema uniformity, and record NaN/infinity distribution across all 8 files. | `scripts/inspect_dataset.py` & JSON manifest |
| **FR-02** | Clean Preprocessing | Normalize headers, handle duplicate names, map labels to binary and attack taxonomy, replace infinities, impute medians learned only on train data. | `IDSPreprocessor` & `cleaner.py` unit tests |
| **FR-03** | Model Training | Train Random Forest on real CIC-IDS2017 flows using balanced sampling and reproducible seed (42). Save self-contained bundle. | `scripts/train.py` & `models/*.joblib` |
| **FR-04** | Dual Evaluation | Benchmark random-split test partition (in-distribution) and whole-file holdout (out-of-distribution PortScan PCAP). Record real metrics. | `reports/evaluation_summary.md` |
| **FR-05** | Batch CSV Inference | Enable uploading arbitrary flow CSVs, validating schema alignment, predicting labels, and exporting CSV results. | Streamlit Mode 1 & `InferenceEngine` |
| **FR-06** | SIEM Persistence | Persist all generated alerts with UUIDs, timestamps, attack categories, confidences, and severity into SQLite. | SQLite `data/alerts.db` & SQL indexes |
| **FR-07** | System Log Adapter | Parse Linux/Unix authentication logs, count repeated login failures, and generate correlated brute force alerts. | `SystemLogAdapter` & unit tests |
| **FR-08** | Diagnostic Status | Probe Windows socket permissions; display honest status without claiming live wire sniffing unless privileges exist. | Streamlit Mode 2 & `check_capture_capabilities` |
