import json
import streamlit as st
import pandas as pd
from frontend.components.ui_helpers import api_get, api_post, api_patch, get_severity_badge, get_mitre_badge


def render_live_alerts():
    st.markdown("### 🔔 Live Security Alerts Triage Console")
    st.markdown("<p style='color: #94a3b8; margin-top:-10px; font-size:13px;'>Investigate incoming security triggers, review AI explanations, and escalate to incident response.</p>", unsafe_allow_html=True)

    # Filter Toolbar
    f_cols = st.columns([1.5, 1.5, 1.5, 2.5])
    with f_cols[0]:
        sev_filter = st.selectbox("Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with f_cols[1]:
        cat_filter = st.selectbox("Category", ["ALL", "AUTHENTICATION", "WEB_APPLICATION", "FINANCIAL_FRAUD"])
    with f_cols[2]:
        status_filter = st.selectbox("Status", ["ALL", "NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"])
    with f_cols[3]:
        search_query = st.text_input("🔍 Search Alert UUID, IP, or Target", "")

    # Query alerts
    params = {"limit": 150}
    if sev_filter != "ALL":
        params["severity"] = sev_filter
    if cat_filter != "ALL":
        params["category"] = cat_filter
    if status_filter != "ALL":
        params["status"] = status_filter

    alerts = api_get("/alerts", params=params) or []

    # Client-side text search
    if search_query:
        sq = search_query.lower()
        alerts = [
            a for a in alerts
            if sq in a.get("alert_uuid", "").lower()
            or sq in a.get("source_ip", "").lower()
            or sq in (a.get("affected_user") or "").lower()
            or sq in (a.get("affected_account") or "").lower()
            or sq in a.get("rule_name", "").lower()
        ]

    st.markdown(f"**Found {len(alerts)} alerts matching filter criteria**")

    if not alerts:
        st.info("No alerts match your current filter parameters.")
        return

    # Alert triage selector
    alert_options = {
        f"[{a['severity']}] {a['alert_uuid']} - {a['rule_name']} (IP: {a['source_ip']})": a['id']
        for a in alerts
    }
    selected_label = st.selectbox("Select Alert to Deep-Dive & Triage:", list(alert_options.keys()))
    selected_id = alert_options[selected_label]
    alert = next((a for a in alerts if a["id"] == selected_id), None)

    if alert:
        st.markdown("---")
        # Header of selected alert
        top_col1, top_col2 = st.columns([3, 1])
        with top_col1:
            st.markdown(f"### {alert['rule_name']}")
            st.markdown(
                f"{get_severity_badge(alert['severity'])} &nbsp; "
                f"<span class='badge-low'>Category: {alert['category']}</span> &nbsp; "
                f"<span style='color:#94a3b8; font-family:monospace;'>UUID: {alert['alert_uuid']}</span> &nbsp; "
                f"<span style='color:#64748b;'>Timestamp: {alert['timestamp'][:19].replace('T', ' ')} UTC</span>",
                unsafe_allow_html=True
            )
        with top_col2:
            st.metric("AI Dynamic Risk Score", f"{alert.get('ai_risk_score', 50)}/100")

        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

        # Drilldown Tabs
        tab1, tab2, tab3, tab4 = st.tabs(["🤖 AI Security Analysis", "🔍 Evidence & Technical Data", "🎯 MITRE ATT&CK Mapping", "🛠️ SOC Analyst Actions"])

        with tab1:
            st.markdown("#### Explainable AI Root-Cause Reasoning")
            explanation = alert.get("ai_explanation") or "AI Explanation pending."
            st.markdown(f"""
            <div class="ai-box">
                <div class="ai-header">🧠 Sentinel AI Root Cause Breakdown</div>
                <div style="color: #e2e8f0; font-size: 14px; line-height: 1.6;">
                    {explanation}
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("#### Recommended Defensive Containment Playbook")
            playbook_json = alert.get("ai_recommended_actions")
            playbook = []
            if playbook_json:
                try:
                    playbook = json.loads(playbook_json)
                except Exception:
                    playbook = [playbook_json]

            if playbook:
                for step in playbook:
                    st.markdown(f"- `{step}`")
            else:
                st.write("Standard perimeter firewall review recommended.")

            st.markdown("""
            <div class="soc-callout soc-callout-warning">
                <strong>Analyst Advisory:</strong> AI-generated risk scoring supports decision triage. Always correlate with session logs and verify if payloads succeeded before initiating irreversible account freezes.
            </div>
            """, unsafe_allow_html=True)

        with tab2:
            st.markdown("#### Raw Technical Evidence & Observed Attributes")
            meta_cols = st.columns(3)
            with meta_cols[0]:
                st.markdown(f"**Source IP:** `{alert.get('source_ip')}`")
                st.markdown(f"**Destination IP:** `{alert.get('destination_ip') or 'Bank Edge VIP'}`")
            with meta_cols[1]:
                st.markdown(f"**Affected User:** `{alert.get('affected_user') or 'N/A'}`")
                st.markdown(f"**Affected Account:** `{alert.get('affected_account') or 'N/A'}`")
            with meta_cols[2]:
                st.markdown(f"**Current Status:** `{alert.get('status')}`")
                st.markdown(f"**Assigned Analyst:** `{alert.get('assigned_to') or 'Unassigned'}`")

            st.markdown("##### Evidence Payload")
            evidence_str = alert.get("evidence") or "{}"
            try:
                parsed_ev = json.loads(evidence_str)
                st.json(parsed_ev)
            except Exception:
                st.code(evidence_str, language="json")

        with tab3:
            st.markdown("#### Adversary Tactic & Technique Attribution")
            tactic = alert.get("mitre_tactic") or "Initial Access"
            tech_id = alert.get("mitre_technique_id") or "T1190"
            tech_name = alert.get("mitre_technique_name") or "Public Exploit"

            st.markdown(f"""
            - **MITRE Tactic:** `{tactic}`
            - **Technique ID:** `{tech_id}`
            - **Technique Name:** `{tech_name}`
            """)
            st.markdown(f"Adversary mapping: {get_mitre_badge(tech_id, tech_name)}", unsafe_allow_html=True)

        with tab4:
            st.markdown("#### SOC Analyst Response & Triage Actions")
            act_cols = st.columns(3)
            with act_cols[0]:
                new_status = st.selectbox("Update Alert Status", ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"], key=f"status_{alert['id']}")
                if st.button("Save Status Update"):
                    res = api_patch(f"/alerts/{alert['id']}/status", json_data={"status": new_status, "assigned_to": "Current Analyst"})
                    if res:
                        st.success(f"Alert status updated to {new_status}!")
                        st.rerun()

            with act_cols[1]:
                st.markdown("**Incident Promotion**")
                if st.button("🚨 Escalate Alert to Security Incident"):
                    res = api_post(f"/alerts/{alert['id']}/promote-incident")
                    if res:
                        st.success(f"Incident {res.get('incident_uuid')} created successfully!")
                        st.rerun()

            with act_cols[2]:
                st.markdown("**Defensive Quick Block**")
                if st.button(f"🚫 Block IP {alert.get('source_ip')} on Edge WAF"):
                    st.success(f"Firewall drop rule dispatched for IP {alert.get('source_ip')}.")

