# AI-IDS Model Evaluation & Experimental Report

**Generated:** 2026-10-28T15:07:26.143376+00:00  
**Model Architecture:** Random Forest (`n_estimators=100`, `max_depth=16`)  
**Dataset:** CIC-IDS2017 Real Flow Records  
**Total Training Flows:** 56,012  
**Total Test Flows:** 14,004  
**Input Features:** 78 Flow Metrics  

---

## 1. Random-Split Test Evaluation (80/20 Stratified Partition)

| Metric | Score | Explanation |
| :--- | :--- | :--- |
| **Accuracy** | **99.35%** | Overall fraction of flows correctly classified |
| **Precision** | **98.13%** | Ability not to label benign traffic as an attack |
| **Recall (Sensitivity)** | **99.62%** | Ability to detect true attack events |
| **F1-Score** | **98.87%** | Harmonic balance between precision and recall |
| **False Positive Rate (FPR)** | **0.760%** | Percentage of benign traffic triggering false alarms |
| **False Negative Rate (FNR)** | **0.375%** | Percentage of attacks that slipped through unnoticed |

### Confusion Matrix
- **True Negatives (TN - Benign correctly identified):** 9,925
- **False Positives (FP - False alarms):** 76
- **False Negatives (FN - Missed attacks):** 15
- **True Positives (TP - Attacks accurately detected):** 3,988

### Inference Latency Benchmark
- **Single-Record Latency:** `42.2898 ms` per flow
- **Batch Processing Rate:** `0.05964 ms` per flow (`16,767` flows/sec throughput)

---
## 2. Whole-File Holdout Evaluation
**Holdout Target:** `Holdout File: Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`  
*Note: Evaluates generalization when an entire attack dataset capture file is withheld from training.*

| Metric | Score |
| :--- | :--- |
| **Accuracy** | **97.56%** |
| **Precision** | **0.55%** |
| **Recall** | **57.14%** |
| **F1-Score** | **1.08%** |
| **False Positive Rate (FPR)** | **2.431%** |
| **False Negative Rate (FNR)** | **42.857%** |

### Holdout Confusion Matrix
- **True Negatives (TN):** 29,264
- **False Positives (FP):** 729
- **False Negatives (FN):** 3
- **True Positives (TP):** 4

---
## 3. Methodological Discussion & Limitations

1. **Random-Split vs. Whole-File Holdout:**
   - Random-split evaluation samples flows uniformly across captured PCAP sessions. High random-split scores reflect strong in-distribution pattern recognition.
   - Whole-file holdout tests detection on distinct sessions where network topology, port usage, and traffic timing may differ.
2. **CIC-IDS2017 Dataset Constraints:**
   - As an offline research dataset collected in an emulation lab, zero-day attacks and evolving modern protocols are not guaranteed to yield identical production accuracy.
   - IDS strictly monitors and alerts; no disruptive IPS mitigations are applied.
