import json
import streamlit as st
from frontend.components.ui_helpers import api_get, api_post, get_severity_badge, get_mitre_badge
from frontend.components.charts import create_risk_score_gauge


def render_ai_analyzer():
    st.markdown("### 🤖 AI Security Analyzer & Decision Support System")
    st.markdown("<p style='color: #94a3b8; margin-top:-10px; font-size:13px;'>Contextual threat correlation, explainable root-cause reasoning, and dynamic risk scoring for L1/L2 Analysts.</p>", unsafe_allow_html=True)

    mode = st.radio("Analysis Mode", ["Analyze Existing Alert", "Analyze Custom Raw Log / Ad-Hoc Payload"], horizontal=True)

    if mode == "Analyze Existing Alert":
        alerts = api_get("/alerts", params={"limit": 50}) or []
        if not alerts:
            st.info("No alerts available to inspect. Run an attack simulation or ingest logs.")
            return

        alert_map = {f"[{a['severity']}] {a['alert_uuid']} - {a['rule_name']} ({a['source_ip']})": a['id'] for a in alerts}
        selected_key = st.selectbox("Choose Alert to Analyze:", list(alert_map.keys()))
        selected_alert_id = alert_map[selected_key]

        if st.button("🚀 Run Deep AI Analysis", type="primary"):
            with st.spinner("Analyzing threat telemetry, calculating dynamic risk score, and synthesizing playbook..."):
                analysis = api_post("/ai/analyze", json_data={"alert_id": selected_alert_id})
                if analysis:
                    _display_ai_results(analysis)
                else:
                    st.error("Failed to run AI Security Analyzer.")

    else:
        st.markdown("#### Input Ad-Hoc Suspicious Log Payload")
        col_in1, col_in2 = st.columns(2)
        with col_in1:
            source_ip = st.text_input("Source IP", "185.220.101.5")
            rule_type = st.selectbox("Threat Vector", [
                "SQL Injection (RULE-WEB-001)",
                "Brute Force Attempt (RULE-AUTH-001)",
                "Transaction Structuring (RULE-FRD-003)",
                "Suspicious Admin Login (RULE-AUTH-005)"
            ])
            user = st.text_input("Username (Optional)", "clara.oswald")
        with col_in2:
            account = st.text_input("Account ID (Optional)", "ACC-882910")
            payload_text = st.text_area("Request Payload / URL Parameter", "user=admin' OR '1'='1'--")

        if st.button("🚀 Analyze Custom Event with AI", type="primary"):
            rule_id = rule_type.split("(")[-1].replace(")", "")
            rule_name = rule_type.split("(")[0].strip()
            category = "WEB_APPLICATION" if "WEB" in rule_id else ("AUTHENTICATION" if "AUTH" in rule_id else "FINANCIAL_FRAUD")

            with st.spinner("Processing event through AI Security Engine..."):
                analysis = api_post("/ai/analyze", json_data={
                    "event_payload": {
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "category": category,
                        "severity": "HIGH",
                        "source_ip": source_ip,
                        "username": user,
                        "source_account": account,
                        "payload": payload_text
                    }
                })
                if analysis:
                    _display_ai_results(analysis)
                else:
                    st.error("Analysis failed.")


def _display_ai_results(analysis: dict):
    st.markdown("---")
    res_col1, res_col2 = st.columns([1, 2.2])

    with res_col1:
        gauge_fig = create_risk_score_gauge(analysis.get("dynamic_risk_score", 50), title="Dynamic Threat Score")
        st.plotly_chart(gauge_fig, use_container_width=True)
        st.markdown(f"**Assessed Risk Level:** {get_severity_badge(analysis.get('risk_level', 'MEDIUM'))}", unsafe_allow_html=True)
        st.markdown(f"**Containment Priority:** `{analysis.get('containment_priority')}`")
        st.markdown(f"**MITRE ATT&CK:** {get_mitre_badge(analysis.get('mitre_technique_id'), analysis.get('mitre_technique_name'))}", unsafe_allow_html=True)

    with res_col2:
        st.markdown("#### Executive Investigation Summary")
        st.info(analysis.get("event_summary"))

        st.markdown("#### Root Cause Breakdown (Why Alert Generated)")
        st.markdown(f"""
        <div class="ai-box">
            <div style="color: #f1f5f9; font-size: 14px; line-height: 1.6;">
                {analysis.get('root_cause_explanation')}
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("#### 🕵️ Suspicious Behavioral Patterns Identified")
    patterns = analysis.get("suspicious_patterns", [])
    if patterns:
        for p in patterns:
            st.markdown(f"- ⚠️ **{p}**")
    else:
        st.markdown("- No additional behavioral anomalies detected beyond base rule criteria.")

    st.markdown("#### 🛡️ AI Recommended Defensive Playbook Steps")
    playbook = analysis.get("recommended_playbook", [])
    for step in playbook:
        st.markdown(f"- `{step}`")

    # Analyst Decision Support Directive
    st.markdown(f"""
    <div class="soc-callout soc-callout-warning">
        {analysis.get('analyst_decision_support')}
    </div>
    """, unsafe_allow_html=True)

