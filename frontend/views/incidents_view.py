import streamlit as st
import pandas as pd
from datetime import datetime
from frontend.components.ui_helpers import api_get, api_post, api_patch, get_severity_badge


def render_incident_management():
    st.markdown("### 📋 Security Incident Management & Escalation Workflows")
    st.markdown("<p style='color: #94a3b8; margin-top:-10px; font-size:13px;'>Manage case lifecycle, record analyst case notes, execute containment actions, and coordinate L1/L2 escalation.</p>", unsafe_allow_html=True)

    incidents = api_get("/incidents") or []

    # Incident Toolbar
    top_col1, top_col2 = st.columns([3, 1])
    with top_col1:
        st.markdown(f"**Open Security Cases ({len(incidents)} active)**")
    with top_col2:
        open_create = st.button("➕ Open New Incident Case", type="primary")

    if open_create:
        with st.form("new_incident_form"):
            st.markdown("#### Formal Security Incident Intake")
            title = st.text_input("Incident Title", "High-Risk Account Takeover & Wire Drain")
            desc = st.text_area("Incident Description", "Correlated brute force and unauthorized wire transfer on core banking customer.")
            c1, c2, c3 = st.columns(3)
            with c1:
                sev = st.selectbox("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
            with c2:
                assignee = st.selectbox("Assignee", [
                    "Alex Rivera (L1 SOC Analyst)",
                    "Elena Rostova (L2 Senior Incident Responder)",
                    "Marcus Chen (SOC Lead & Threat Hunter)"
                ])
            with c3:
                esc = st.selectbox("Escalation Tier", ["L1_TRIAGE", "L2_INVESTIGATION", "L3_FORENSICS_LEAD"])

            submitted = st.form_submit_button("Create Incident")
            if submitted:
                res = api_post("/incidents", json_data={
                    "title": title,
                    "description": desc,
                    "severity": sev,
                    "assigned_to": assignee,
                    "escalation_level": esc
                })
                if res:
                    st.success(f"Incident {res.get('incident_uuid')} successfully created!")
                    st.rerun()

    if not incidents:
        st.info("No security incidents currently active. Promote an alert or click 'Open New Incident Case'.")
        return

    # Select Incident for Detailed Investigation
    inc_options = {f"[{i['severity']}] {i['incident_uuid']} - {i['title']} ({i['status']})": i['id'] for i in incidents}
    sel_label = st.selectbox("Select Incident Case to Manage:", list(inc_options.keys()))
    sel_id = inc_options[sel_label]

    incident = api_get(f"/incidents/{sel_id}")
    if not incident:
        st.error("Could not load incident details.")
        return

    st.markdown("---")
    # Incident Details Header
    h_col1, h_col2 = st.columns([3, 1])
    with h_col1:
        st.markdown(f"### {incident['title']}")
        st.markdown(
            f"{get_severity_badge(incident['severity'])} &nbsp; "
            f"<span class='badge-low'>Status: {incident['status']}</span> &nbsp; "
            f"<span class='badge-mitre'>Tier: {incident['escalation_level']}</span> &nbsp; "
            f"<span style='color:#94a3b8; font-family:monospace;'>UUID: {incident['incident_uuid']}</span>",
            unsafe_allow_html=True
        )
        st.markdown(f"<p style='color:#cbd5e1; margin-top:8px;'>{incident.get('description')}</p>", unsafe_allow_html=True)
    with h_col2:
        st.markdown(f"**Assigned Lead:** `{incident['assigned_to']}`")
        st.markdown(f"**Created:** `{incident['created_at'][:19].replace('T', ' ')}`")

    # Incident Management Tabs
    tab_timeline, tab_notes, tab_actions, tab_escalate = st.tabs([
        "📜 Incident Audit Timeline",
        "📝 Analyst Notes & Logs",
        "🛡️ Containment Execution",
        "🔺 Escalate Workflow (L1 ➔ L2/L3)"
    ])

    with tab_timeline:
        st.markdown("#### Chronological Audit Trail & Event Timeline")
        timeline = incident.get("timeline_events", [])
        if timeline:
            for t in reversed(timeline):
                ts = t.get("timestamp", "")[:19].replace("T", " ")
                st.markdown(f"**`{ts} UTC`** - **{t.get('actor')}** (`{t.get('action')}`): {t.get('details')}")
        else:
            st.info("No timeline events recorded yet.")

    with tab_notes:
        st.markdown("#### Case Notes & Investigation Journal")
        notes = incident.get("notes", [])
        if notes:
            for n in notes:
                ts = n.get("timestamp", "")[:19].replace("T", " ")
                st.markdown(f"""
                <div class="soc-callout">
                    <strong>{n.get('analyst_name')}</strong> <span style="color:#64748b; font-size:11px;">({ts} UTC)</span><br>
                    {n.get('content')}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.write("No notes added yet.")

        st.markdown("##### Append Investigation Note")
        note_text = st.text_area("Analyst Findings / Action Summary", placeholder="Observed compromised session cookie match with RedLine Stealer IOC feed...")
        note_author = st.selectbox("Author", ["Alex Rivera (L1 SOC Analyst)", "Elena Rostova (L2 Senior Incident Responder)", "Marcus Chen (SOC Lead)"], key=f"author_{incident['id']}")
        if st.button("Add Note to Incident"):
            if note_text:
                api_post(f"/incidents/{incident['id']}/notes", json_data={
                    "analyst_name": note_author,
                    "content": note_text
                })
                st.success("Note recorded.")
                st.rerun()

    with tab_actions:
        st.markdown("#### Defensive Containment Controls")
        if incident.get("containment_actions"):
            st.markdown(f"**Executed Containments:**\n```\n{incident.get('containment_actions')}\n```")

        act_col1, act_col2 = st.columns(2)
        with act_col1:
            if st.button("🚫 Firewall Rule: Block Malicious IP Range"):
                api_post(f"/incidents/{incident['id']}/contain", params={
                    "action_name": "FIREWALL_DROP_RULE",
                    "details": "Added border BGP blackhole / WAF block for attacker IP range.",
                    "analyst_name": incident["assigned_to"]
                })
                st.success("Containment action logged.")
                st.rerun()

            if st.button("🔒 Revoke All Active JWT Sessions & Force MFA"):
                api_post(f"/incidents/{incident['id']}/contain", params={
                    "action_name": "SESSION_REVOCATION",
                    "details": "Invalidated all active Redis JWT session tokens and required hardware token re-auth.",
                    "analyst_name": incident["assigned_to"]
                })
                st.success("Session tokens revoked.")
                st.rerun()

        with act_col2:
            if st.button("🧊 Place Administrative Hold on Bank Ledger Account"):
                api_post(f"/incidents/{incident['id']}/contain", params={
                    "action_name": "ACCOUNT_LEDGER_FREEZE",
                    "details": "Triggered core banking SWIFT / ACH administrative debit freeze.",
                    "analyst_name": incident["assigned_to"]
                })
                st.success("Account freeze recorded.")
                st.rerun()

            new_status = st.selectbox("Transition Case Status", ["OPEN", "UNDER_INVESTIGATION", "CONTAINED", "RESOLVED", "CLOSED_FALSE_POSITIVE"], key=f"inc_st_{incident['id']}")
            if st.button("Update Incident Status"):
                api_patch(f"/incidents/{incident['id']}", json_data={"status": new_status})
                st.success(f"Status changed to {new_status}!")
                st.rerun()

    with tab_escalate:
        st.markdown("#### Tier Escalation Handoff (L1 ➔ L2 Senior Analyst / Forensics)")
        esc_tier = st.selectbox("Target Escalation Level", ["L2_INVESTIGATION", "L3_FORENSICS_LEAD", "EXECUTIVE_CRISIS"])
        target_analyst = st.selectbox("Assign Senior Specialist", [
            "Elena Rostova (L2 Senior Incident Responder)",
            "Marcus Chen (SOC Lead & Threat Hunter)",
            "Chief Information Security Officer (CISO Desk)"
        ])
        esc_reason = st.text_area("Escalation Justification", "Confirmed unauthorized outward SWIFT wire attempt; forensics memory extraction requested.")

        if st.button("🚨 Dispatch Formal Escalation", type="primary"):
            api_post(f"/incidents/{incident['id']}/escalate", params={
                "target_level": esc_tier,
                "assigned_to": target_analyst,
                "analyst_name": "Alex Rivera (L1 SOC Analyst)",
                "reason": esc_reason
            })
            st.success(f"Incident escalated to {esc_tier} and assigned to {target_analyst}!")
            st.rerun()

