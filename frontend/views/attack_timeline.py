import streamlit as st
import pandas as pd
from frontend.components.ui_helpers import api_get, get_severity_badge, get_mitre_badge


def render_attack_timeline():
    st.markdown("### ⏳ Cyber Attack Timeline & Correlation Chain")
    st.markdown("<p style='color: #94a3b8; margin-top:-10px; font-size:13px;'>Reconstruct adversary kill chains, track multi-stage banking intrusions, and pivot on attacker infrastructure.</p>", unsafe_allow_html=True)

    correlations = api_get("/correlations") or []

    st.markdown("#### 🔗 Multi-Stage Attack Campaigns & Correlation Clusters")
    if correlations:
        for c in correlations:
            badge_type = "CRITICAL" if c.get("max_risk_score", 0) >= 85 else "HIGH"
            with st.expander(f"🚨 {c['title']} | Risk Score: {c['max_risk_score']}/100 ({c['alert_count']} Linked Alerts)", expanded=True):
                c_cols = st.columns([1.5, 2, 1.5])
                with c_cols[0]:
                    st.markdown(f"**Pivot Type:** `{c['pivot_type']}`")
                    st.markdown(f"**Pivot Value:** `{c['pivot_value']}`")
                with c_cols[1]:
                    st.markdown(f"**Kill Chain Progression:**")
                    st.markdown(f"`{c.get('kill_chain_summary', 'Multi-Stage Threat')}`")
                with c_cols[2]:
                    st.markdown(f"**First Seen:** `{c['earliest_event'][:19].replace('T', ' ')}`")
                    st.markdown(f"**Last Seen:** `{c['latest_event'][:19].replace('T', ' ')}`")

                st.markdown("**Correlated Threat Rules Involved:**")
                st.write(", ".join([f"`{r}`" for r in c.get("rule_names", [])]))
    else:
        st.info("No multi-stage attack correlations currently identified. Run an APT simulation to generate multi-vector campaigns.")

    st.markdown("---")
    st.markdown("#### 🕒 Chronological Security Events Feed")

    alerts = api_get("/alerts", params={"limit": 50}) or []
    if alerts:
        timeline_df = pd.DataFrame([
            {
                "Timestamp (UTC)": a.get("timestamp", "").replace("T", " ")[:19],
                "Severity": a.get("severity"),
                "Rule Name": a.get("rule_name"),
                "Source IP": a.get("source_ip"),
                "Target / Account": a.get("affected_user") or a.get("affected_account") or "Core System",
                "MITRE Technique": f"{a.get('mitre_technique_id')} - {a.get('mitre_technique_name')}",
                "Risk Score": a.get("ai_risk_score", 50)
            } for a in alerts
        ])

        st.dataframe(
            timeline_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Risk Score": st.column_config.ProgressColumn(
                    "Risk Score",
                    min_value=0,
                    max_value=100,
                    format="%d"
                )
            }
        )
    else:
        st.write("No alerts recorded.")

