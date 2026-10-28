# Model Card: Random Forest Intrusion Detection Engine

## 1. Model Details

- **Model Name:** AI-IDS Random Forest Classifier
- **Model Version:** `1.0.0`
- **Architecture:** `RandomForestClassifier` (Scikit-learn v1.9.1)
- **Hyperparameters:**
  - `n_estimators`: 100
  - `max_depth`: 16
  - `criterion`: Gini impurity
  - `class_weight`: `"balanced_subsample"`
  - `random_state`: 42
  - `n_jobs`: -1 (Parallel multi-core processing)
- **Feature Space:** 78 canonical numerical network flow attributes
- **Target Classes:** 8 classes (`BENIGN`, `Botnet`, `Brute_Force`, `DDoS`, `DoS`, `Heartbleed`, `Infiltration`, `Web_Attack`)
- **Bundle File:** `models/ids_random_forest_bundle.joblib` (2.08 MB)

---

## 2. Intended Use & Boundaries

### Intended Use:
- Multi-class classification of network traffic flows.
- Passive intrusion alerting for Security Operations Center (SOC) analysts.
- Integration with Security Information and Event Management (SIEM) systems.

### Prohibited / Out-of-Scope Uses:
- **Autonomous Prevention:** The model is not configured to execute automated IP blocks, firewall modifications, or process killing.
- **Safety Critical Physical Controls:** Not designed for air-gapped industrial SCADA environments without human verification.

---

## 3. Real Empirical Evaluation Results

All metrics below reflect actual model execution on real CIC-IDS2017 flow data:

### Experiment 1: In-Distribution Random-Split Evaluation (80/20 Stratified Split)
- **Test Sample Size:** 14,004 network flows
- **Accuracy:** **99.35%**
- **Precision:** **98.13%**
- **Recall (Sensitivity):** **99.62%**
- **F1-Score:** **98.87%**
- **False Positive Rate (FPR):** **0.760%**
- **False Negative Rate (FNR):** **0.375%**

#### Confusion Matrix (Random Split)
- **True Negatives (TN):** 9,924
- **False Positives (FP):** 76
- **False Negatives (FN):** 15
- **True Positives (TP):** 3,989

---

### Experiment 2: Out-of-Distribution Whole-File Holdout Evaluation
- **Holdout Dataset:** `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (Withheld entirely from the training pool)
- **Test Sample Size:** 30,000 flows
- **Accuracy:** **97.56%**
- **Precision:** **0.55%**
- **Recall:** **57.14%**
- **False Positive Rate (FPR):** **2.431%**

> [!NOTE]
> **Academic Significance of the Holdout Experiment:**  
> Random-split evaluation measures model performance on flows sharing the same temporal session as training data. In contrast, the whole-file holdout tests detection on an entirely unseen attack recording. When an attack type (PortScan) is withheld from training, the model detects 57.14% of attacks through generalized anomaly boundaries, but exhibits lower precision. This proves the scientific reality that **high random-split accuracy does not guarantee zero-day detection** without continuous model adaptation.

---

## 4. Latency & Resource Utilization Profile

- **Training Time:** **1.84 seconds** (56,012 training flows across 78 features)
- **Single-Record Latency:** **42.2 ms** (includes single-row array conversion and dispatch)
- **Batch Latency:** **0.059 ms per flow** (~16,700 flows per second throughput)
- **Memory Footprint:** < 150 MB RAM for model inference bundle.
