import json
import streamlit as st
import pandas as pd
from frontend.components.ui_helpers import api_get, api_post


def render_simulator():
    st.markdown("### ⚡ Telemetry Ingestion & Bank Attack Simulator")
    st.markdown("<p style='color: #94a3b8; margin-top:-10px; font-size:13px;'>Inject synthetic banking attacks, test detection rules, and ingest custom JSON/JSONL event streams.</p>", unsafe_allow_html=True)

    tab_sim, tab_upload, tab_inspect = st.tabs([
        "🎯 One-Click Attack Scenarios",
        "📂 JSON / JSONL File Ingestion",
        "🔎 Ingested Telemetry Explorer"
    ])

    with tab_sim:
        st.markdown("#### Bank Cyber Attack & Fraud Scenario Generator")
        st.markdown("Execute realistic banking threat vectors to evaluate rule triggering and AI analyzer reasoning in real-time:")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown("##### 🔐 Authentication Threats")
            if st.button("🔥 Simulate Brute Force Wave"):
                with st.spinner("Generating automated dictionary attacks..."):
                    res = api_post("/simulate", params={"scenario": "brute_force"})
                    _show_sim_result(res)

            if st.button("👥 Simulate Credential Stuffing"):
                with st.spinner("Iterating credential dumps across bank accounts..."):
                    res = api_post("/simulate", params={"scenario": "credential_stuffing"})
                    _show_sim_result(res)

            if st.button("👤 Simulate Account Takeover (ATO)"):
                with st.spinner("Executing ATO spray and breach sequence..."):
                    res = api_post("/simulate", params={"scenario": "account_takeover"})
                    _show_sim_result(res)

            if st.button("✈️ Simulate Impossible Travel"):
                with st.spinner("Injecting logins across global timezones..."):
                    res = api_post("/simulate", params={"scenario": "impossible_travel"})
                    _show_sim_result(res)

            if st.button("🌙 Simulate Off-Hours Admin Login"):
                with st.spinner("Accessing /swift-gateway at 03:15 AM..."):
                    res = api_post("/simulate", params={"scenario": "suspicious_admin_login"})
                    _show_sim_result(res)

        with col2:
            st.markdown("##### 🌐 Web Application Attacks")
            if st.button("💉 Simulate SQL Injection (SQLi)"):
                with st.spinner("Probing banking core with UNION SELECT and SLEEP()..."):
                    res = api_post("/simulate", params={"scenario": "sql_injection"})
                    _show_sim_result(res)

            if st.button("⚔️ Simulate Web Exploit Chain"):
                with st.spinner("Injecting XSS cookie stealer, LFI, and shell commands..."):
                    res = api_post("/simulate", params={"scenario": "web_exploit_chain"})
                    _show_sim_result(res)

            st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
            st.markdown("##### 🟢 Regular Bank Operations")
            if st.button("🏦 Ingest Normal Retail Traffic (25 logs)"):
                with st.spinner("Ingesting regular customer logins and card transfers..."):
                    res = api_post("/simulate", params={"scenario": "benign_flow"})
                    _show_sim_result(res)

        with col3:
            st.markdown("##### 💰 Financial Fraud & AML")
            if st.button("💵 Simulate AML Structuring (Smurfing)"):
                with st.spinner("Executing $9,400 sub-threshold transfers..."):
                    res = api_post("/simulate", params={"scenario": "aml_structuring"})
                    _show_sim_result(res)

            if st.button("⚡ Simulate Rapid Velocity Spike"):
                with st.spinner("Firing 5 wire transfers in 90 seconds..."):
                    res = api_post("/simulate", params={"scenario": "transaction_velocity_spike"})
                    _show_sim_result(res)

            if st.button("🏛️ Simulate Large Wire Transfer ($250k)"):
                with st.spinner("Executing high-value SWIFT interbank wire..."):
                    res = api_post("/simulate", params={"scenario": "large_wire_fraud"})
                    _show_sim_result(res)

            st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
            st.markdown("##### 🌟 Complete Environment Setup")
            if st.button("🚀 Seed Full Demo Environment", type="primary"):
                with st.spinner("Initializing full threat intelligence, multi-vector attacks, and active incidents..."):
                    res = api_post("/seed-demo")
                    if res:
                        st.success("Full Banking SOC environment populated with realistic telemetry!")
                        st.rerun()

    with tab_upload:
        st.markdown("#### Upload Heterogeneous Bank Log Files (.json / .jsonl)")
        st.markdown("Upload banking authentication logs, web access logs, or transaction streams for automatic normalization and detection:")
        
        uploaded_file = st.file_uploader("Select log file", type=["json", "jsonl", "txt"])
        if uploaded_file and st.button("Ingest Uploaded File"):
            content = uploaded_file.read().decode("utf-8", errors="ignore")
            # Parse lines
            parsed = []
            for line in content.strip().splitlines():
                line = line.strip()
                if line:
                    try:
                        parsed.append(json.loads(line))
                    except Exception:
                        pass
            if not parsed:
                try:
                    obj = json.loads(content)
                    parsed = obj if isinstance(obj, list) else [obj]
                except Exception:
                    pass

            if parsed:
                res = api_post("/logs/ingest", json_data={"logs": parsed})
                if res:
                    st.success(f"Successfully normalized and ingested {res.get('ingested_count')} events! Triggered {res.get('alerts_triggered')} alert(s).")
            else:
                st.error("Could not parse valid JSON records from the uploaded file.")

    with tab_inspect:
        st.markdown("#### Ingested Telemetry Log Explorer")
        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            log_type_filter = st.selectbox("Log Type", ["ALL", "auth", "web", "transaction"])
        with filter_col2:
            only_anomalous = st.checkbox("Show Only Anomalous / Flagged Events", value=False)

        params = {"limit": 100}
        if log_type_filter != "ALL":
            params["log_type"] = log_type_filter
        if only_anomalous:
            params["is_anomalous"] = True

        logs = api_get("/logs", params=params) or []
        if logs:
            df_logs = pd.DataFrame([
                {
                    "Time (UTC)": l.get("timestamp", "").replace("T", " ")[:19],
                    "Type": l.get("log_type"),
                    "Source IP": l.get("source_ip"),
                    "User / Account": l.get("username") or l.get("source_account") or "-",
                    "Action": l.get("action"),
                    "Endpoint / Method": f"{l.get('http_method') or ''} {l.get('endpoint') or ''}".strip() or "-",
                    "Amount ($)": f"${l.get('amount'):,.2f}" if l.get("amount") is not None else "-",
                    "Flagged": "🚨 YES" if l.get("is_anomalous") else "Normal"
                } for l in logs
            ])
            st.dataframe(df_logs, use_container_width=True, hide_index=True)
        else:
            st.info("No logs found matching criteria.")


def _show_sim_result(res: dict):
    if res:
        st.success(
            f"✅ Scenario '{res.get('scenario')}' generated {res.get('logs_ingested')} logs and triggered "
            f"{res.get('alerts_generated')} alerts ({', '.join(res.get('severities', []))})!"
        )
    else:
        st.error("Simulation failed. Ensure backend API is active.")

