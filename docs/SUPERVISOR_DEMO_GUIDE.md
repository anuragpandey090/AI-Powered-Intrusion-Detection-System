# University Supervisor Demonstration Guide

**Demonstration Objective:** Present a clean, working, academic demonstration of the **AI-Powered Intrusion Detection System (AI-IDS)** in under 5 minutes, demonstrating real model inference, SIEM alerting, and architectural boundaries.

---

## 1. Quick Launch Checklist (Before Supervisor Arrives)

Open **Windows PowerShell** in the project directory `E:\IILM\AI-IDS-Final` and run:

```powershell
# Set PYTHONPATH
$env:PYTHONPATH='src'

# Launch the Streamlit Security Dashboard
streamlit run app/dashboard.py
```
*(The browser will automatically open at `http://localhost:8501`)*

---

## 2. Step-by-Step 5-Minute Demonstration Script

### Minute 1: Introduction & Scope Boundary
**What to say:**
> *"Good morning/afternoon, Sir/Ma'am. Today I am presenting our implementation of the AI-Powered Intrusion Detection System. Before demonstrating, I want to emphasize our core scope boundary: as specified in our Phase-I report, this system operates strictly as an **Intrusion Detection System (IDS)**. It continuously inspects network flow traffic and system logs to generate structured security alerts, but it adheres strictly to passive detection and **never blocks IPs or disrupts network connections**."*

---

### Minute 2: Mode 1 — Flow Ingestion, Schema Validation & Inference
**What to do in the UI:**
1. Navigate to **"📂 Mode 1: CSV Flow Detection"** in the sidebar.
2. Click the blue button: **"Load Pre-Packaged Sample CSV"** (or upload `data/sample/test_flows_sample.csv`).
3. Expand **"🔍 Feature Schema Validation Details"**.

**What to say:**
> *"In Mode 1, we demonstrate flow-based detection. Here, we load flow records derived from the Canadian Institute for Cybersecurity CIC-IDS2017 benchmark. Notice that before making any prediction, our system executes an automated schema validation check. It verifies that all 78 canonical statistical flow attributes—such as flow durations, packet length distributions, and TCP flag ratios—are present and properly aligned."*

---

### Minute 3: Detection Results & Attack Breakdown
**What to point to on screen:**
1. Point to the top metric cards: Total Flows (500), Benign Traffic (492), Attacks Detected (8), SIEM Alerts Stored (8).
2. Point to the Attack Breakdown chart (Botnet / DDoS / DoS).
3. Scroll down to the predictions table showing model confidence scores (e.g. 89.9%, 99.9%).
4. Click **"📥 Download Full Inference Results (CSV)"**.

**What to say:**
> *"The inference engine evaluates all 500 flows in milliseconds using our trained Random Forest model. It flags 8 malicious flows with high confidence, while identifying 492 normal benign flows. Analysts can inspect individual confidence probabilities and export the full diagnostic spreadsheet for SIEM ingestion."*

---

### Minute 4: SIEM Alert Persistence & SQLite Querying
**What to do in the UI:**
1. Click **"🚨 SIEM Alerts History"** in the sidebar.
2. Show the filter dropdown: select **"CRITICAL"** or **"HIGH"**.
3. Point out an alert card: note the **Timestamp, Attack Type, Severity, and Source**.

**What to say:**
> *"Every detected attack is automatically transformed into a structured SIEM event and persisted to an embedded SQLite database (`data/alerts.db`). Here in the SIEM console, security analysts can query incidents by severity level, review exact feature snapshots taken at detection time, and audit past incidents. We also have a system log adapter that parses SSH authentication logs to detect brute-force attempts."*

---

### Minute 5: Mode 2 Diagnostics & Academic Honesty
**What to do in the UI:**
1. Click **"📡 Mode 2: Live Traffic Monitor"** in the sidebar.
2. Show the diagnostic message on screen: *"Live capture restricted: Administrator privileges required on Windows (WinError 10013)"*.

**What to say:**
> *"Finally, Mode 2 is designed for real-time packet capture. When we query the host capabilities, the system accurately detects that we are running without Windows Administrator privileges and without an active Npcap kernel driver. In line with academic integrity, our system **does not fabricate fake live data**; instead, it reports the exact operating constraint honestly while offering full, validated offline flow detection in Mode 1."*

---

## 3. Anticipated Viva Questions During the Demo

| Supervisor Question | Recommended Direct Answer |
| :--- | :--- |
| **"Where did the training data come from?"** | *"It was trained directly on the raw CIC-IDS2017 benchmark files stored on this machine (`E:\IILM\Major Project\raw\MachineLearningCVE`), containing 2.83 million real flows."* |
| **"Why Random Forest instead of TensorFlow?"** | *"On tabular flow metrics (78 numerical features), tree ensembles consistently outperform neural networks. Our Random Forest trained in 1.84 seconds on CPU, achieved 99.35% test accuracy, and processes flows at 0.059 ms per flow without requiring GPU hardware."* |
| **"How do you prevent data leakage?"** | *"Our `IDSPreprocessor` fits all imputation medians and boundaries strictly on the training partition. Unseen test and live inference data use only the pre-fitted medians."* |
| **"Does the model detect zero-day attacks?"** | *"In our whole-file holdout test where PortScan attacks were withheld entirely from training, the model detected 57% of attacks through generalized anomaly boundaries, but precision dropped. We honestly document that random-split accuracy does not guarantee zero-day detection."* |
