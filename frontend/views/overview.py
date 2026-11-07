import streamlit as st
import pandas as pd
from datetime import datetime
from frontend.components.ui_helpers import api_get, render_metric_card, get_severity_badge, get_mitre_badge
from frontend.components.charts import create_severity_donut, create_category_bar, create_risk_score_gauge


def render_security_overview():
    st.markdown("### 🛡️ Security Operations Center - Executive & Tactical HUD")
    st.markdown("<p style='color: #94a3b8; margin-top:-10px; font-size:13px;'>Real-time situational awareness, detection metrics, and banking threat posture.</p>", unsafe_allow_html=True)

    # Fetch stats
    stats = api_get("/stats") or {
        "total_events": 0, "total_alerts": 0, "critical_alerts": 0,
        "high_alerts": 0, "active_incidents": 0, "suspicious_ips": 0,
        "transaction_anomalies": 0, "threat_posture_score": 95
    }

    # Fetch alerts
    alerts = api_get("/alerts", params={"limit": 100}) or []

    # KPI Top Bar
    kpi_cols = st.columns(6)
    with kpi_cols[0]:
        st.markdown(render_metric_card("Total Logs Ingested", f"{stats['total_events']:,}", "Normalized events"), unsafe_allow_html=True)
    with kpi_cols[1]:
        st.markdown(render_metric_card("Total Alerts", f"{stats['total_alerts']:,}", "Detection engine triggers"), unsafe_allow_html=True)
    with kpi_cols[2]:
        st.markdown(render_metric_card("Critical Alarms", f"{stats['critical_alerts']}", "Requires immediate containment", badge="CRITICAL"), unsafe_allow_html=True)
    with kpi_cols[3]:
        st.markdown(render_metric_card("High Severity", f"{stats['high_alerts']}", "Triage queue priority", badge="HIGH"), unsafe_allow_html=True)
    with kpi_cols[4]:
        st.markdown(render_metric_card("Active Incidents", f"{stats['active_incidents']}", "Under L1/L2 investigation"), unsafe_allow_html=True)
    with kpi_cols[5]:
        st.markdown(render_metric_card("Fraud Outliers", f"{stats['transaction_anomalies']}", "Structuring & velocity spikes"), unsafe_allow_html=True)

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Posture Gauge & Distribution Row
    chart_cols = st.columns([1, 1.2, 1.2])
    with chart_cols[0]:
        gauge_fig = create_risk_score_gauge(stats.get("threat_posture_score", 85), title="MR.X Defense Posture Index")
        st.plotly_chart(gauge_fig, use_container_width=True)
    with chart_cols[1]:
        donut_fig = create_severity_donut(alerts)
        st.plotly_chart(donut_fig, use_container_width=True)
    with chart_cols[2]:
        bar_fig = create_category_bar(alerts)
        st.plotly_chart(bar_fig, use_container_width=True)

    # High Priority Alarms Ticker / Table
    st.markdown("#### 🚨 Active High-Priority Security Alarms")
    critical_and_high = [a for a in alerts if a.get("severity") in ("CRITICAL", "HIGH")]

    if critical_and_high:
        table_rows = []
        for a in critical_and_high[:8]:
            ts_formatted = a.get("timestamp", "").replace("T", " ")[:19]
            table_rows.append({
                "Alert UUID": a.get("alert_uuid"),
                "Time (UTC)": ts_formatted,
                "Severity": a.get("severity"),
                "Rule Name": a.get("rule_name"),
                "Source IP": a.get("source_ip"),
                "Target / Account": a.get("affected_user") or a.get("affected_account") or "Core System",
                "AI Risk Score": f"{a.get('ai_risk_score', 50)}/100",
                "Status": a.get("status", "NEW")
            })

        df_display = pd.DataFrame(table_rows)
        st.dataframe(
            df_display,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Severity": st.column_config.TextColumn("Severity"),
                "AI Risk Score": st.column_config.ProgressColumn(
                    "AI Risk Score",
                    min_value=0,
                    max_value=100,
                    format="%d"
                )
            }
        )
    else:
        st.info("No Critical or High severity security alarms currently active. Perimeter baseline normal.")

    # Defense Pulse & Operating Status
    st.markdown("---")
    op_cols = st.columns(4)
    with op_cols[0]:
        st.markdown("**🛡️ Firewall Defense State:** `ARMED & FILTERING`")
    with op_cols[1]:
        st.markdown("**🔍 Isolation Forest ML:** `BASELINE TRAINED (v1.8)`")
    with op_cols[2]:
        st.markdown("**🌐 Threat Intel Feeds:** `CONNECTED (6 FEEDS)`")
    with op_cols[3]:
        st.markdown("**⚖️ AML Compliance Engine:** `CTR/SAR MONITOR ACTIVE`")

