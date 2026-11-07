import streamlit as st
import pandas as pd
from frontend.components.ui_helpers import api_get, api_post, get_severity_badge, get_mitre_badge
from frontend.components.charts import create_mitre_bar_chart, create_risk_score_gauge


def render_threat_intel():
    st.markdown("### 🌐 Threat Intelligence & IOC Tracker")
    st.markdown("<p style='color: #94a3b8; margin-top:-10px; font-size:13px;'>Adversary infrastructure tracking, multi-feed IP reputation scoring, and MITRE ATT&CK banking taxonomy.</p>", unsafe_allow_html=True)

    tab_lookup, tab_iocs, tab_mitre = st.tabs(["🔎 IP Reputation Lookup", "📑 IOC Threat Database", "🗺️ MITRE ATT&CK Coverage"])

    with tab_lookup:
        st.markdown("#### Real-Time IP Reputation & Attribution Engine")
        col_q1, col_q2 = st.columns([3, 1])
        with col_q1:
            test_ip = st.text_input("Enter IP Address to Inspect:", "194.26.29.112")
        with col_q2:
            st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
            run_check = st.button("Query Threat Intel", type="primary")

        if run_check and test_ip:
            with st.spinner("Checking global threat intelligence feeds and reputation database..."):
                rep = api_get(f"/threat-intel/lookup/{test_ip}")
                if rep:
                    r_col1, r_col2 = st.columns([1, 2])
                    with r_col1:
                        gauge = create_risk_score_gauge(rep.get("reputation_score", 0), title="IP Threat Score")
                        st.plotly_chart(gauge, use_container_width=True)
                        st.markdown(f"**Severity:** {get_severity_badge(rep.get('severity', 'LOW'))}", unsafe_allow_html=True)
                        st.markdown(f"**Attributed Threat Actor:** `{rep.get('threat_actor') or 'Unattributed Public Host'}`")

                    with r_col2:
                        st.markdown("##### Geographical & Network Telemetry")
                        geo = rep.get("details", {}).get("geo", {})
                        st.markdown(f"- **City / Country:** `{geo.get('city')}, {geo.get('country')}`")
                        st.markdown(f"- **ISP / Hosting Provider:** `{geo.get('isp')}`")
                        st.markdown(f"- **Coordinates:** `Lat {geo.get('lat')}, Lon {geo.get('lon')}`")
                        st.markdown(f"- **Identified Threat Categories:** {', '.join([f'`{c}`' for c in rep.get('categories', [])])}")

                        st.markdown("##### Threat Intelligence Summary")
                        st.info(rep.get("details", {}).get("summary", "No threat feed match."))

                        if rep.get("mitre_mappings"):
                            st.markdown("##### Linked MITRE Techniques")
                            for m in rep.get("mitre_mappings", []):
                                st.markdown(f"- {get_mitre_badge(m.get('technique_id'), m.get('technique_name'))}", unsafe_allow_html=True)

    with tab_iocs:
        st.markdown("#### Curated Banking Threat Indicators of Compromise (IOCs)")
        iocs = api_get("/threat-intel/iocs") or []
        if iocs:
            df_iocs = pd.DataFrame([
                {
                    "Type": i.get("ioc_type"),
                    "Value": i.get("value"),
                    "Threat Actor": i.get("threat_actor") or "Unknown",
                    "Threat Type": i.get("threat_type"),
                    "Severity": i.get("severity"),
                    "Confidence": f"{i.get('confidence')}%",
                    "Tags": i.get("tags")
                } for i in iocs
            ])
            st.dataframe(df_iocs, use_container_width=True, hide_index=True)
        else:
            st.info("No IOCs currently loaded.")

        st.markdown("---")
        with st.expander("➕ Add New Threat Indicator of Compromise (IOC)"):
            c_in1, c_in2 = st.columns(2)
            with c_in1:
                ioc_val = st.text_input("IOC Value (IP, Domain, Hash)", "198.51.100.42")
                ioc_type = st.selectbox("IOC Type", ["IP", "DOMAIN", "HASH", "USER_AGENT"])
                actor = st.text_input("Threat Actor", "Unknown APT")
            with c_in2:
                threat_type = st.text_input("Threat Type", "Banking Trojan C2")
                sev = st.selectbox("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
                tags = st.text_input("Tags (comma separated)", "trojan,c2,financial")

            desc = st.text_area("Description", "Reported by external financial ISAC threat bulletin.")
            if st.button("Submit New IOC"):
                res = api_post("/threat-intel/iocs", json_data={
                    "ioc_type": ioc_type,
                    "value": ioc_val,
                    "threat_actor": actor,
                    "threat_type": threat_type,
                    "severity": sev,
                    "confidence": 85,
                    "description": desc,
                    "tags": tags
                })
                if res:
                    st.success("IOC added to database successfully!")
                    st.rerun()

    with tab_mitre:
        st.markdown("#### MITRE ATT&CK Framework Coverage for Banking")
        alerts = api_get("/alerts", params={"limit": 100}) or []
        mitre_fig = create_mitre_bar_chart(alerts)
        st.plotly_chart(mitre_fig, use_container_width=True)

        st.markdown("""
        **MR.X BANK SOC Matrix Mapping Summary:**
        - **Initial Access:** T1190 (Exploit Public-Facing Application)
        - **Credential Access:** T1110.001 (Password Guessing), T1110.004 (Credential Stuffing)
        - **Execution:** T1059.004 (Unix Shell / PowerShell Command Injection)
        - **Persistence:** T1078.003 (Valid Accounts: Account Takeover)
        - **Privilege Escalation:** T1078.002 (Suspicious Domain Admin Access)
        - **Defense Evasion:** T1562 (Transaction Structuring / AML Evasion), T1078 (Impossible Travel)
        - **Impact:** T1499 (Large Wire Drain), T1565.001 (High Velocity Burst), T1098 (ML Outlier)
        """)

