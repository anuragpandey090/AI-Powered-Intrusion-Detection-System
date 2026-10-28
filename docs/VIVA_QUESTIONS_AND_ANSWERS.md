# Comprehensive Viva Questions & Model Answers

This document prepares you for technical inquiries from your university supervisor, external examiners, or review panel regarding the **AI-Powered Intrusion Detection System (AI-IDS)**.

---

## 1. Domain & Conceptual Fundamentals

### Q1: What is the fundamental difference between an IDS and an IPS?
**Answer:**  
An **Intrusion Detection System (IDS)** passively monitors network traffic or system event logs, analyzes behavioral patterns, and generates structured security alerts for SOC analysts without altering network state.  
An **Intrusion Prevention System (IPS)** sits in-line with the network traffic and actively drops malicious packets, resets TCP sessions, or dynamically updates firewall ACL rules.  
*In this project, our scope is strictly bounded to an IDS: we detect, classify, and alert, but we never automatically disrupt network traffic or block IP addresses.*

### Q2: What is a "Network Flow", and how does it differ from a raw packet?
**Answer:**  
A raw packet is an individual Layer 3/4 PDU containing raw payload bytes and headers. A **network flow** is an aggregated, bi-directional sequence of packets sharing the same **5-tuple**:
$$\text{Flow} = (\text{Source IP}, \text{Source Port}, \text{Destination IP}, \text{Destination Port}, \text{Protocol})$$
Flows are summarized using statistical metrics over their duration—such as total forward packets, mean packet lengths, inter-arrival time (IAT) variance, and TCP flag counts. The CIC-IDS2017 dataset consists of these statistical flow records rather than raw payload bytes.

### Q3: Why is SIEM integration important in an AI-IDS?
**Answer:**  
Machine learning predictions (e.g. `[1]`) are unusable in enterprise operations unless contextualized. SIEM (Security Information and Event Management) integration standardizes predictions into structured security records containing unique alert IDs, UTC timestamps, source identifiers, attack classifications, model confidences, observed feature snapshots, and severity levels (`INFO`, `MEDIUM`, `HIGH`, `CRITICAL`), persisting them into searchable storage (SQLite) for forensic audits.

---

## 2. Dataset, Preprocessing & Data Leakage

### Q4: Why did you choose CIC-IDS2017, and what anomalies did you find in the raw data?
**Answer:**  
CIC-IDS2017 is a gold-standard benchmark containing benign network traffic alongside realistic modern cyber attacks (DoS, DDoS, PortScans, Web Attacks, Brute Force, Botnets, and Infiltration) collected over 5 days.  
During our automated audit of all 8 raw CSVs (2.83 million records), we discovered:
1. **Header Whitespace:** Irregular spaces in column names (`' Destination Port'`).
2. **Duplicate Headers:** `'Fwd Header Length'` appeared twice in the raw file schema.
3. **Infinite Values:** 2,886 instances of `+Infinity` and `-Infinity` in `Flow Bytes/s` and `Flow Packets/s` caused by 0-microsecond flow durations.
4. **Encoding Errors:** Malformed non-ASCII replacement characters in attack labels (`Web Attack \ufffd Brute Force`).

### Q5: How did you handle missing and infinite values, and how did you prevent data leakage?
**Answer:**  
1. All `+Inf` and `-Inf` values were converted to `NaN`.
2. Missing values were imputed using the feature's **median**, which is robust to extreme network traffic outliers.
3. **Data Leakage Prevention:** Crucially, the `IDSPreprocessor` computed and saved medians **strictly on the training split**. The test split and any user-uploaded CSVs were transformed using these stored medians, guaranteeing that test distributions never influenced the model's training parameters.

### Q6: Why did you separate system logs from network flow data?
**Answer:**  
Network flows are continuous numerical statistical vectors (e.g., packet counts, bytes per second, duration), whereas system logs (such as Linux `auth.log` or Windows Event Logs) are semi-structured textual strings containing user names, PAM authentication states, and process IDs. Forcing these disparate data modalities into a single matrix corrupts the feature space. We implemented a dedicated `SystemLogAdapter` that parses system logs, tracks authentication failures per IP, and triggers correlated brute-force alerts independently.

---

## 3. Machine Learning Algorithms & Decisions

### Q7: Why did you choose Random Forest over Deep Learning (TensorFlow)?
**Answer:**  
1. **Tabular Data Superiority:** Extensive empirical research shows that tree ensembles (Random Forest, Gradient Boosting) consistently outperform deep neural networks on tabular datasets with heterogeneous numerical features.
2. **Computational Efficiency:** Our Random Forest model trained in **1.84 seconds** on CPU, achieving **99.35% test accuracy** and a **0.059 ms per-record inference latency**, easily meeting the 12 GB RAM constraint without requiring dedicated GPUs.
3. **Environment & Dependency Realism:** Our runtime environment uses Python 3.13 on Windows. TensorFlow does not yet provide stable C-API wheels for Python 3.13 on Windows. Rather than using an unstable alpha build, we engineered a robust, reproducible Scikit-learn solution.

### Q8: How does Random Forest work, and how does it assign confidence scores?
**Answer:**  
Random Forest is an ensemble learning method that constructs a collection of $B$ de-correlated decision trees ($B=100$) during training. Each tree is trained on a bootstrap sample of the training data and selects a random subset of features ($\sqrt{p}$) at each split using the **Gini Impurity** criterion:
$$I_G(p) = 1 - \sum_{i=1}^{C} p_i^2$$
During inference, each tree casts a vote for the predicted class. The model confidence score is the proportion of trees voting for the winning class:
$$\text{Confidence}(x) = \max_c \left( \frac{1}{B} \sum_{b=1}^{B} I(h_b(x) = c) \right)$$

---

## 4. Evaluation Metrics & Scientific Honesty

### Q9: Why is Accuracy alone misleading in Intrusion Detection?
**Answer:**  
Because network traffic is heavily imbalanced. In CIC-IDS2017, **80.3%** of traffic is benign. A naive dummy model that predicts "BENIGN" for every single packet would achieve 80.3% accuracy while failing to detect 100% of cyber attacks. Therefore, we evaluate **Precision** (avoiding false alarms), **Recall** (detecting true attacks), **F1-Score** (harmonic balance), **False Positive Rate (FPR)**, and **False Negative Rate (FNR)**.

### Q10: What is the difference between your Random-Split evaluation and your Whole-File Holdout evaluation?
**Answer:**  
- **Random-Split Evaluation:** Randomly splits the dataset 80/20 across flows. This tests in-distribution generalization, where the model achieved **99.35% accuracy** and **98.87% F1-score**.
- **Whole-File Holdout Evaluation:** We withheld the entire `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` file from the training pool. When evaluated on this unseen recording, the model detected 57.14% of attacks through generalized anomaly boundaries, but precision dropped significantly.  
*Scientific Conclusion:* This proves that high random-split accuracy does not imply zero-day intrusion detection. When network topologies and attack mechanisms differ from training sessions, models require retraining. We document this limitation transparently.

---

## 5. Software Engineering & Deployment

### Q11: How is the trained model deployed and loaded in production?
**Answer:**  
The model, fitted `IDSPreprocessor`, ordered 78-feature list, class taxonomy, and training metadata are serialized into a single compressed `.joblib` bundle (`models/ids_random_forest_bundle.joblib`, 2.08 MB). The `InferenceEngine` loads this bundle once as a cached singleton, allowing the Streamlit dashboard and FastAPI server to run inference without retraining.

### Q12: Why is Live Capture marked as unavailable in Mode 2 on this computer?
**Answer:**  
On Windows, binding raw network sockets (`SOCK_RAW`) or promiscuous packet capture requires **Administrator privileges** and an active **Npcap kernel driver**. When running as a standard user, Windows throws `WinError 10013 (Access Forbidden)`.  
Rather than fabricating fake live data or misrepresenting prerecorded files as live traffic, our `LiveTrafficAdapter` queries system capabilities, detects the missing privilege, and reports the diagnostic status honestly in the UI. Mode 1 provides the verified working demonstration on real benchmark flows.
