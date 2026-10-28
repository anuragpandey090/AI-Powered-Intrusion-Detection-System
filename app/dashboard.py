"""AI-Powered Intrusion Detection System — Interactive Security Dashboard.

Features:
- Premium dark cybersecurity UI theme.
- Mode 1: CSV Upload, Schema Validation, Inference, Metric KPIs, and Result Export.
- Mode 2: Live Network Sniffing Capability & Privilege Diagnostics.
- SIEM Alert Center: SQLite persistent alerts, severity filters, feature inspection.
- Model Performance & Architecture Transparency (Random Forest vs Holdout).
"""

import sys
from pathlib import Path
import json
import pandas as pd
import streamlit as st

# Ensure project src is in Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ai_ids.config import (
    MODEL_BUNDLE_PATH,
    DATASET_AUDIT_REPORT_PATH,
    REPORTS_DIR,
    STRICT_SAFETY_MODE,
    BENIGN_LABEL,
)
from ai_ids.inference.engine import InferenceEngine
from ai_ids.ingestion.csv_ingest import validate_csv_schema
from ai_ids.storage.db import query_alerts, get_alert_statistics, clear_alerts
from ai_ids.ingestion.live_capture import check_capture_capabilities

# Page Configuration
st.set_page_config(
    page_title="AI-IDS | Security Operations Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Cyber Styling
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }
    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    /* Sleek Dark Theme Overrides */
    .stApp {
        background: radial-gradient(circle at 10% 20%, #0b0f19 0%, #07090e 90%);
        color: #f1f5f9;
    }
    
    /* Metrics and Cards */
    div[data-testid="stMetric"] {
        background: rgba(30, 41, 59, 0.65);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
        backdrop-filter: blur(10px);
    }
    
    /* Banner Cards */
    .cyber-header {
        background: linear-gradient(135deg, rgba(14, 165, 233, 0.15) 0%, rgba(99, 102, 241, 0.15) 100%);
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 16px;
        padding: 24px 30px;
        margin-bottom: 25px;
    }
    .safety-badge {
        display: inline-block;
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.82rem;
        font-weight: 600;
        letter-spacing: 0.5px;
    }
    
    .status-crit {
        background: rgba(239, 68, 68, 0.2);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.4);
        padding: 2px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .status-high {
        background: rgba(249, 115, 22, 0.2);
        color: #fb923c;
        border: 1px solid rgba(249, 115, 22, 0.4);
        padding: 2px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .status-med {
        background: rgba(234, 179, 8, 0.2);
        color: #facc15;
        border: 1px solid rgba(234, 179, 8, 0.4);
        padding: 2px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .status-info {
        background: rgba(56, 189, 248, 0.2);
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.4);
        padding: 2px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def load_engine():
    """Caches loaded model bundle across Streamlit reruns."""
    if not MODEL_BUNDLE_PATH.exists():
        return None
    return InferenceEngine(MODEL_BUNDLE_PATH)


def main():
    # Sidebar
    with st.sidebar:
        st.markdown("### 🛡️ **AI-IDS Console**")
        st.caption("AI-Powered Intrusion Detection System")
        st.markdown("---")
        
        mode = st.radio(
            "Select Operational View:",
            [
                "📂 Mode 1: CSV Flow Detection",
                "📡 Mode 2: Live Traffic Monitor",
                "🚨 SIEM Alerts History",
                "📊 Model & Audit Reports",
            ],
            index=0,
        )

        st.markdown("---")
        st.markdown("#### System Boundaries")
        st.markdown('<span class="safety-badge">✓ IDS ONLY (NO IPS)</span>', unsafe_allow_html=True)
        st.caption("Automated packet dropping, host isolation, and IP blocking are strictly disabled.")

        st.markdown("---")
        st.caption("Model Engine: **Random Forest**")
        st.caption("Target Dataset: **CIC-IDS2017**")

    engine = load_engine()

    # Header Banner
    st.markdown(
        """
        <div class="cyber-header">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <h1 style="margin:0; font-size: 2rem; color: #f8fafc; font-weight: 700;">
                        AI-Powered Intrusion Detection System
                    </h1>
                    <p style="margin:5px 0 0 0; color: #94a3b8; font-size: 0.95rem;">
                        Real-Time Flow Analysis • Scikit-learn Baseline • SIEM Alert Correlation
                    </p>
                </div>
                <div style="text-align: right;">
                    <span class="safety-badge">STRICT IDS BOUNDARY</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if engine is None:
        st.error("⚠️ Model bundle not detected. Please execute `python scripts/train.py` to initialize the system.")
        return

    # View 1: CSV-Based Detection (Mode 1 - Guaranteed Demonstration)
    if mode == "📂 Mode 1: CSV Flow Detection":
        st.subheader("📂 Offline Network Flow Analysis (Mode 1)")
        st.markdown(
            "Upload a CIC-IDS2017 compatible network-flow CSV file. The system validates feature order, "
            "evaluates flows through the trained Random Forest model, persists high-severity alerts to SQLite, and outputs diagnostics."
        )

        col_sample, col_up = st.columns([1, 2])
        with col_sample:
            st.info("💡 **Quick Demonstration:**")
            st.markdown("Use the included sample file: `data/sample/test_flows_sample.csv` (contains 500 mixed real flows).")
            use_sample = st.button("Load Pre-Packaged Sample CSV")

        with col_up:
            uploaded_file = st.file_uploader("Or upload your custom flow CSV:", type=["csv"])

        df_to_analyze = None
        source_label = ""

        if use_sample:
            sample_path = Path("data/sample/test_flows_sample.csv")
            if sample_path.exists():
                df_to_analyze = pd.read_csv(sample_path)
                source_label = "sample_test_flows.csv"
                st.success(f"Loaded {len(df_to_analyze)} rows from `{sample_path}`.")
            else:
                st.error("Sample CSV not found.")

        elif uploaded_file is not None:
            try:
                df_to_analyze = pd.read_csv(uploaded_file)
                source_label = uploaded_file.name
            except Exception as e:
                st.error(f"Error parsing CSV file: {e}")

        if df_to_analyze is not None:
            st.markdown("---")
            # Step 1: Schema Validation
            is_valid, msg, schema_meta = validate_csv_schema(df_to_analyze, engine.feature_names)
            
            with st.expander("🔍 Feature Schema Validation Details", expanded=not is_valid):
                st.write(f"**Status:** {msg}")
                st.write(f"- Matched Features: **{schema_meta['matching_columns_count']} / {schema_meta['total_required_features']}** ({schema_meta['matching_ratio']*100:.1f}%)")
                if schema_meta['missing_columns_count'] > 0:
                    st.warning(f"Missing columns will be imputed with training medians: {schema_meta['missing_features_sample']}")

            if not is_valid:
                st.error("Uploaded file did not meet minimum schema compatibility (50% matching flow features required).")
            else:
                # Run Inference
                with st.spinner("Executing Random Forest inference & generating SIEM alerts..."):
                    results = engine.predict_dataframe(
                        df=df_to_analyze,
                        source_name=f"CSV_UPLOAD:{source_label}",
                        save_alerts=True,
                    )

                # Metrics KPIs
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Total Flows Analyzed", f"{results['total_records']:,}")
                m2.metric("Benign Normal Flows", f"{results['benign_count']:,}", delta=f"{results['benign_count']/max(1, results['total_records'])*100:.1f}%")
                m3.metric("Detected Attacks", f"{results['attack_count']:,}", delta=f"-{results['attack_count']/max(1, results['total_records'])*100:.1f}%", delta_color="inverse")
                m4.metric("SIEM Alerts Stored", f"{len(results['alerts']):,}")

                # Attack Categories Breakdown
                if results['attacks_by_type']:
                    st.markdown("#### Attack Breakdown")
                    chart_data = pd.DataFrame(
                        list(results['attacks_by_type'].items()),
                        columns=["Attack Category", "Count"]
                    ).set_index("Attack Category")
                    st.bar_chart(chart_data)

                # Detailed Results Table
                st.markdown("#### Flow Prediction Results & Model Scores")
                pred_df = results["predictions_df"]
                display_cols = ["predicted_label", "attack_category", "confidence_score", "attack_probability"]
                # Add destination port and duration if present
                for extra in ["Destination Port", "Flow Duration", "Flow Bytes/s"]:
                    if extra in pred_df.columns:
                        display_cols.append(extra)

                st.dataframe(
                    pred_df[display_cols].head(100),
                    use_container_width=True,
                )

                # Export CSV
                csv_bytes = pred_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="📥 Download Full Inference Results (CSV)",
                    data=csv_bytes,
                    file_name=f"ids_predictions_{source_label}.csv",
                    mime="text/csv",
                )

    # View 2: Live Traffic Monitoring (Mode 2 - Diagnostic & Safety)
    elif mode == "📡 Mode 2: Live Traffic Monitor":
        st.subheader("📡 Real-Time Packet Sniffing & Flow Extraction (Mode 2)")
        st.markdown(
            "This module interfaces with network adapters to capture packets in real time, aggregates 5-tuples into flows, "
            "and passes extracted features into the inference engine."
        )

        cap_status = check_capture_capabilities()

        col_stat, col_diag = st.columns(2)
        with col_stat:
            st.markdown("#### Live Monitoring Status")
            if cap_status.is_available:
                st.success("🟢 Real-Time Capture Engine: **ACTIVE**")
            else:
                st.error("🔴 Real-Time Capture Engine: **UNAVAILABLE**")
                st.caption(f"Reason: {cap_status.message}")

        with col_diag:
            st.markdown("#### Host Diagnostics")
            st.write(f"- Platform: **{cap_status.platform}**")
            st.write(f"- Administrator Privileges: **{'YES' if cap_status.has_admin_rights else 'NO (Standard User)'}**")
            st.write(f"- Raw Socket Access: **{'Granted' if cap_status.has_admin_rights else 'Restricted (WinError 10013)'}**")

        st.markdown("---")
        st.markdown("#### University Supervisor Note / Methodology Boundary")
        st.info(
            """
            **Academic Integrity Disclosure:**
            - Genuine real-time packet capture on Windows requires an active kernel driver (Npcap / WinPcap) and elevated Administrator rights.
            - To preserve strict scientific integrity, this project **does not fabricate fake live data** or falsely pretend that prerecorded files are live network wires.
            - Mode 1 provides the fully functional, verified demonstration on the actual CIC-IDS2017 benchmark.
            """
        )

    # View 3: SIEM Alerts History
    elif mode == "🚨 SIEM Alerts History":
        st.subheader("🚨 SIEM Security Alerts & Incident History")
        st.markdown("Searchable, auditable alert repository backed by persistent SQLite storage.")

        stats = get_alert_statistics()
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Stored Alerts", f"{stats['total_alerts']:,}")
        c2.metric("Critical / High Alerts", f"{stats['by_severity'].get('CRITICAL', 0) + stats['by_severity'].get('HIGH', 0):,}")
        c3.metric("Monitored Sources", f"{len(stats['by_source']):,}")

        col_filt1, col_filt2, col_clear = st.columns([1, 1, 1])
        with col_filt1:
            sev_filter = st.selectbox("Filter by Severity:", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "INFO"])
        with col_filt2:
            limit_val = st.slider("Alert Display Limit:", 10, 200, 50)
        with col_clear:
            st.write("")
            if st.button("🗑️ Clear Alert History"):
                clear_alerts()
                st.rerun()

        filter_arg = None if sev_filter == "ALL" else sev_filter
        alerts_list = query_alerts(limit=limit_val, severity=filter_arg)

        if not alerts_list:
            st.info("No security alerts found matching the selected filter.")
        else:
            for alert in alerts_list:
                sev = alert["severity"]
                css_class = (
                    "status-crit" if sev == "CRITICAL"
                    else "status-high" if sev == "HIGH"
                    else "status-med" if sev == "MEDIUM"
                    else "status-info"
                )
                with st.container():
                    st.markdown(
                        f"""
                        <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 8px; padding: 12px 18px; margin-bottom: 10px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <span class="{css_class}">{sev}</span>
                                    <strong style="margin-left: 10px; font-size: 1.05rem;">{alert['attack_type']}</strong>
                                    <span style="color: #94a3b8; font-size: 0.85rem; margin-left: 10px;">Source: {alert['source']}</span>
                                </div>
                                <div style="color: #64748b; font-size: 0.82rem;">
                                    {alert['timestamp']}
                                </div>
                            </div>
                            <div style="margin-top: 8px; font-size: 0.88rem; color: #cbd5e1;">
                                Model Confidence: <strong>{alert['confidence_score']*100:.1f}%</strong> | 
                                Flow Index: <code>#{alert['flow_index']}</code> | 
                                Mitigated: <code>False (IDS Alert Only)</code>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

    # View 4: Model & Dataset Audits
    elif mode == "📊 Model & Audit Reports":
        st.subheader("📊 Dataset Integrity & Experimental Evaluation Reports")

        tab1, tab2 = st.tabs(["Model Evaluation Summary", "Raw Dataset Audit Manifest"])

        with tab1:
            eval_summary_file = REPORTS_DIR / "evaluation_summary.md"
            if eval_summary_file.exists():
                st.markdown(eval_summary_file.read_text(encoding="utf-8"))
            else:
                st.warning("Evaluation summary file not found. Run training first.")

        with tab2:
            if DATASET_AUDIT_REPORT_PATH.exists():
                with open(DATASET_AUDIT_REPORT_PATH, "r", encoding="utf-8") as f:
                    audit_json = json.load(f)
                st.write(f"- Total CSV Files: **{audit_json['total_csv_files']}**")
                st.write(f"- Total Records: **{audit_json['total_records']:,}**")
                st.write(f"- Canonical Features: **{audit_json['canonical_feature_count']}**")
                st.write(f"- Schema Uniformity: **{audit_json['schema_consistent_across_all_files']}**")
                st.markdown("#### Aggregated Label Distribution")
                st.json(audit_json["aggregated_label_distribution"])
            else:
                st.warning("Audit manifest not found. Run `python scripts/inspect_dataset.py`.")


if __name__ == "__main__":
    main()
