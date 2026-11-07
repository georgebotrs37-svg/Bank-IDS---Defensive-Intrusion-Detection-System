import json
import streamlit as st
import pandas as pd
from frontend.components.ui_helpers import api_get, render_metric_card, get_severity_badge
from frontend.components.charts import create_ml_anomaly_scatter


def render_financial_fraud():
    st.markdown("### 💳 Financial Fraud & AML Transaction Sentinel")
    st.markdown("<p style='color: #94a3b8; margin-top:-10px; font-size:13px;'>Detect transaction structuring (smurfing), automated velocity bursts, large unauthorized wires, and unsupervised ML anomalies.</p>", unsafe_allow_html=True)

    summary = api_get("/fraud/summary") or {
        "total_fraud_alerts": 0, "structuring_smurfing_count": 0,
        "velocity_spikes_count": 0, "large_transaction_count": 0,
        "ml_isolation_forest_count": 0, "flagged_accounts": [], "recent_alerts": []
    }

    # Fraud KPI Metric Cards
    f_cols = st.columns(4)
    with f_cols[0]:
        st.markdown(render_metric_card("Structuring (Smurfing)", summary.get("structuring_smurfing_count", 0), "BSA/FinCEN CTR evasion (<$10k)", badge="CRITICAL"), unsafe_allow_html=True)
    with f_cols[1]:
        st.markdown(render_metric_card("Velocity Bursts", summary.get("velocity_spikes_count", 0), ">= 4 tx in <= 3 min", badge="HIGH"), unsafe_allow_html=True)
    with f_cols[2]:
        st.markdown(render_metric_card("High-Value Transfers", summary.get("large_transaction_count", 0), "Single wire >= $50,000", badge="HIGH"), unsafe_allow_html=True)
    with f_cols[3]:
        st.markdown(render_metric_card("ML Outliers", summary.get("ml_isolation_forest_count", 0), "Isolation Forest flags", badge="MEDIUM"), unsafe_allow_html=True)

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # ML Anomaly Scatter Plot
    all_fraud_alerts = api_get("/alerts", params={"category": "FINANCIAL_FRAUD", "limit": 100}) or []
    
    # Extract amount from evidence
    processed_fraud = []
    for a in all_fraud_alerts:
        amt = 1000.0
        try:
            ev = json.loads(a.get("evidence", "{}"))
            amt = float(ev.get("amount") or ev.get("total_structured_amount") or ev.get("cumulative_amount") or 1000.0)
        except Exception:
            pass
        item = dict(a)
        item["amount"] = amt
        processed_fraud.append(item)

    scatter_fig = create_ml_anomaly_scatter(processed_fraud)
    st.plotly_chart(scatter_fig, use_container_width=True)

    # Detailed Fraud Tabs
    tab_struct, tab_velo, tab_large, tab_ml = st.tabs([
        "💰 AML Structuring (Smurfing)",
        "⚡ Transaction Velocity Spikes",
        "🏦 Large High-Value Wires",
        "🧠 ML Isolation Forest Insights"
    ])

    with tab_struct:
        st.markdown("#### Anti-Money Laundering (AML) Transaction Structuring")
        st.markdown("""
        **Regulatory Framework:** Bank Secrecy Act (BSA) 31 U.S.C. 5324 & FinCEN Currency Transaction Report (CTR).  
        *Structuring (Smurfing)* occurs when an individual or entity breaks large fund transfers into multiple deposits or wires 
        intentionally beneath the mandatory $10,000 statutory reporting threshold (typically $9,000 - $9,999) to evade compliance detection.
        """)

        struct_alerts = [a for a in all_fraud_alerts if a.get("rule_id") == "RULE-FRD-003"]
        if struct_alerts:
            for sa in struct_alerts:
                with st.expander(f"⚠️ {sa['alert_uuid']} - Account {sa.get('affected_account')} | Risk Score: {sa.get('ai_risk_score')}/100"):
                    st.write(sa.get("description"))
                    try:
                        ev = json.loads(sa.get("evidence", "{}"))
                        st.json(ev)
                    except Exception:
                        st.write(sa.get("evidence"))
                    st.button(f"📄 Prepare FinCEN Form 111 SAR for {sa.get('affected_account')}", key=f"sar_{sa['id']}")
        else:
            st.info("No structuring patterns currently observed.")

    with tab_velo:
        st.markdown("#### Rapid Transaction Velocity Spikes")
        st.markdown("Identifies high-frequency automated disbursements (>= 4 transfers within 180 seconds) targeting compromised retail accounts.")
        velo_alerts = [a for a in all_fraud_alerts if a.get("rule_id") == "RULE-FRD-002"]
        if velo_alerts:
            for va in velo_alerts:
                st.markdown(f"- **{va['alert_uuid']}**: {va.get('description')}")
        else:
            st.info("No velocity spikes detected.")

    with tab_large:
        st.markdown("#### High-Value Wire Transfers Exceeding Threshold ($50,000+)")
        large_alerts = [a for a in all_fraud_alerts if a.get("rule_id") == "RULE-FRD-001"]
        if large_alerts:
            for la in large_alerts:
                st.markdown(f"- **{la['alert_uuid']}**: {la.get('description')}")
        else:
            st.info("No transactions exceeding $50,000 threshold.")

    with tab_ml:
        st.markdown("#### Unsupervised Isolation Forest Model Architecture")
        st.markdown("""
        - **Algorithm:** Scikit-Learn `IsolationForest(n_estimators=100, contamination=0.05)`
        - **Feature Space:** `[Transaction Amount, Circadian Hour, Velocity In Last 10m, Weekend Indicator]`
        - **Scoring Function:** Normalized isolation path length distance mapped to 0-100 risk score.
        - **Decision Boundary:** Anomalies flagged when score >= 70 or tree partition depth is below outlier threshold.
        """)

