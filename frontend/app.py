import streamlit as st
from datetime import datetime
from frontend.components.styles import SOC_CSS
from frontend.components.ui_helpers import api_get
from frontend.views.overview import render_security_overview
from frontend.views.alerts_view import render_live_alerts
from frontend.views.ai_analyzer_view import render_ai_analyzer
from frontend.views.attack_timeline import render_attack_timeline
from frontend.views.fraud_view import render_financial_fraud
from frontend.views.threat_intel_view import render_threat_intel
from frontend.views.incidents_view import render_incident_management
from frontend.views.simulator_view import render_simulator

# Page configuration
st.set_page_config(
    page_title="MR.X BANK SOC SENTINEL",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply Cyber SOC Dark Styling
st.markdown(SOC_CSS, unsafe_allow_html=True)


def check_api_status():
    health = api_get("/health")
    return health is not None


def main():
    api_online = check_api_status()

    # Sidebar Navigation & Session Telemetry
    with st.sidebar:
        st.markdown("""
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
            <div style="font-size:26px;">🛡️</div>
            <div>
                <div style="font-weight:800; font-size:16px; color:#f8fafc; letter-spacing:-0.5px;">MR.X BANK SOC</div>
                <div style="font-size:11px; color:#38bdf8; font-weight:600; letter-spacing:0.8px;">SENTINEL DEFENSE v2.4</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Live Backend Heartbeat Pill
        if api_online:
            st.markdown("""
            <div style="background:rgba(16, 185, 129, 0.1); border:1px solid rgba(16, 185, 129, 0.3); border-radius:6px; padding:6px 10px; font-size:11px; color:#34d399; display:flex; align-items:center; gap:8px; margin-bottom:16px;">
                <span class="soc-pulse"></span> FastAPI Backend Engine: ONLINE
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background:rgba(239, 68, 68, 0.1); border:1px solid rgba(239, 68, 68, 0.3); border-radius:6px; padding:6px 10px; font-size:11px; color:#f87171; display:flex; align-items:center; gap:8px; margin-bottom:16px;">
                ⚠️ Backend API Connecting... (Ensure FastAPI is running on port 8000)
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='font-size:11px; color:#64748b; font-weight:700; text-transform:uppercase; margin-bottom:6px;'>Navigation Console</div>", unsafe_allow_html=True)
        nav_selection = st.radio(
            "Select Section",
            [
                "🛡️ Security Overview",
                "🔔 Live Alerts (Triage L1/L2)",
                "🤖 AI Security Analyzer",
                "⏳ Attack Timeline & Chain",
                "💳 Financial Fraud Detection",
                "🌐 Threat Intelligence & IOCs",
                "📋 Incident Management",
                "⚡ Telemetry Ingestion & Simulator"
            ],
            label_visibility="collapsed"
        )

        st.markdown("---")
        st.markdown("<div style='font-size:11px; color:#64748b; font-weight:700; text-transform:uppercase; margin-bottom:6px;'>Active SOC Operator</div>", unsafe_allow_html=True)
        active_analyst = st.selectbox(
            "Logged In Analyst",
            [
                "Alex Rivera (L1 SOC Analyst)",
                "Elena Rostova (L2 Senior Incident Responder)",
                "Marcus Chen (SOC Lead & Threat Hunter)"
            ],
            label_visibility="collapsed"
        )
        st.session_state["active_analyst"] = active_analyst

        st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
        st.caption("MR.X Financial Cyber Defense Division • ISO 27001 / PCI-DSS / FFIEC Compliant")

    # Main HUD Header
    now_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    st.markdown(f"""
    <div class="soc-header">
        <div>
            <div class="soc-title">
                <span class="soc-pulse"></span> MR.X BANK SOC SENTINEL
            </div>
            <div class="soc-subtitle">
                AI-Powered Defensive Banking Intrusion Detection System & Security Operations Platform
            </div>
        </div>
        <div style="text-align:right;">
            <div style="color:#f8fafc; font-family:'JetBrains Mono', monospace; font-size:13px; font-weight:600;">
                {now_utc}
            </div>
            <div style="color:#38bdf8; font-size:11px; margin-top:2px;">
                Operator: <span style="color:#f1f5f9; font-weight:600;">{active_analyst.split('(')[0].strip()}</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Route view
    if nav_selection == "🛡️ Security Overview":
        render_security_overview()
    elif nav_selection == "🔔 Live Alerts (Triage L1/L2)":
        render_live_alerts()
    elif nav_selection == "🤖 AI Security Analyzer":
        render_ai_analyzer()
    elif nav_selection == "⏳ Attack Timeline & Chain":
        render_attack_timeline()
    elif nav_selection == "💳 Financial Fraud Detection":
        render_financial_fraud()
    elif nav_selection == "🌐 Threat Intelligence & IOCs":
        render_threat_intel()
    elif nav_selection == "📋 Incident Management":
        render_incident_management()
    elif nav_selection == "⚡ Telemetry Ingestion & Simulator":
        render_simulator()


if __name__ == "__main__":
    main()

