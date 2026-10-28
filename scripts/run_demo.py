"""End-to-End Demonstrator CLI Script.

Runs the complete AI-IDS workflow:
1. Ingests flow CSV data.
2. Executes pre-trained model inference.
3. Generates structured SIEM alerts.
4. Processes system logs via dedicated adapter.
5. Queries and prints stored alerts from SQLite.
"""

import sys
from pathlib import Path
import pandas as pd

# Add src to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ai_ids.config import MODEL_BUNDLE_PATH, ALERTS_DB_PATH
from ai_ids.inference.engine import InferenceEngine
from ai_ids.ingestion.log_adapter import SystemLogAdapter
from ai_ids.storage.db import query_alerts, get_alert_statistics


def main():
    print("=" * 75)
    print("      AI-POWERED INTRUSION DETECTION SYSTEM -- LIVE DEMO")
    print("=" * 75)
    print("Safety Boundary: STRICT IDS ONLY (No disruptive IPS actions)")

    # 1. Load Inference Engine
    print("\n[Step 1] Loading Model Bundle...")
    engine = InferenceEngine(MODEL_BUNDLE_PATH)
    print(f"  [+] Model Loaded: {engine.metadata.get('model_type', 'RandomForestClassifier')}")
    print(f"  [+] Feature Count: {len(engine.feature_names)} flow attributes")
    print(f"  [+] Classes Supported: {engine.classes}")

    # 2. Ingest Flow CSV
    sample_csv = Path("data/sample/test_flows_sample.csv")
    print(f"\n[Step 2] Processing Flow Records from: {sample_csv}...")
    df = pd.read_csv(sample_csv)
    print(f"  [+] Read {len(df)} flow records.")

    # 3. Execute Inference & SIEM Alerts
    print("\n[Step 3] Running Inference & Generating SIEM Alerts...")
    results = engine.predict_dataframe(
        df=df,
        source_name=sample_csv.name,
        save_alerts=True,
    )
    print(f"  [+] Total Flows Analyzed: {results['total_records']}")
    print(f"  [+] Normal Benign Traffic: {results['benign_count']} flows")
    print(f"  [+] Attacks Detected:      {results['attack_count']} flows")
    print(f"  [+] Breakdown: {results['attacks_by_type']}")
    print(f"  [+] Alerts Persisted to SQLite: {len(results['alerts'])}")

    # 4. System Log Correlation
    print("\n[Step 4] Ingesting System Authentication Logs (Log Adapter)...")
    log_adapter = SystemLogAdapter(failure_threshold=3)
    sample_logs = [
        "Oct 28 20:30:01 edge-gateway sshd[8120]: Failed password for invalid user admin from 198.51.100.42 port 49152 ssh2",
        "Oct 28 20:30:02 edge-gateway sshd[8121]: Failed password for invalid user admin from 198.51.100.42 port 49153 ssh2",
        "Oct 28 20:30:04 edge-gateway sshd[8122]: Failed password for invalid user admin from 198.51.100.42 port 49154 ssh2",
    ]
    log_alerts = log_adapter.process_log_stream(sample_logs, source_name="auth.log", persist=True)
    print(f"  [+] Processed 3 authentication failure lines.")
    print(f"  [+] Correlated Brute-Force Alerts Generated: {len(log_alerts)}")

    # 5. Query SIEM Database
    print("\n[Step 5] Querying Persistent SIEM Database (data/alerts.db)...")
    stats = get_alert_statistics()
    print(f"  [+] Total Alerts in Database: {stats['total_alerts']}")
    print(f"  [+] Severity Distribution:    {stats['by_severity']}")

    recent = query_alerts(limit=5)
    print("\nTop 5 Most Recent Security Alerts:")
    print("-" * 75)
    for a in recent:
        print(f"[{a['timestamp'][:19]}] [{a['severity']:8s}] {a['attack_type']:15s} (Conf: {a['confidence_score']*100:.1f}%) | Src: {a['source']}")
    print("-" * 75)

    print("\n===========================================================================")
    print("  DEMONSTRATION COMPLETED SUCCESSFULLY!")
    print("  To launch the Web Dashboard: streamlit run app/dashboard.py")
    print("  To launch the REST API:      uvicorn ai_ids.api.server:app --port 8000")
    print("===========================================================================")


if __name__ == "__main__":
    main()
