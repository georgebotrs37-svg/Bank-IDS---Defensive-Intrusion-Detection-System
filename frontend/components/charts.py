import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import List, Dict, Any


DARK_LAYOUT = dict(
    paper_bgcolor="rgba(15, 23, 42, 0.4)",
    plot_bgcolor="rgba(15, 23, 42, 0.2)",
    font=dict(color="#94a3b8", family="Inter, sans-serif"),
    margin=dict(l=20, r=20, t=35, b=20),
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
)

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#38bdf8",
    "INFO": "#94a3b8"
}


def create_severity_donut(alerts_data: List[Dict[str, Any]]) -> go.Figure:
    if not alerts_data:
        fig = go.Figure()
        fig.add_annotation(text="No Alert Data Available", showarrow=False, font=dict(color="#64748b", size=14))
        fig.update_layout(**DARK_LAYOUT, height=260)
        return fig

    df = pd.DataFrame(alerts_data)
    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["severity", "count"]

    colors = [SEVERITY_COLORS.get(s, "#94a3b8") for s in counts["severity"]]

    fig = go.Figure(data=[go.Pie(
        labels=counts["severity"],
        values=counts["count"],
        hole=0.62,
        marker=dict(colors=colors, line=dict(color="#0f172a", width=2)),
        textinfo="label+value",
        hoverinfo="label+value+percent"
    )])
    fig.update_layout(
        **DARK_LAYOUT,
        title=dict(text="<b>Alerts by Severity</b>", font=dict(size=14, color="#f8fafc")),
        height=260,
        showlegend=False
    )
    return fig


def create_category_bar(alerts_data: List[Dict[str, Any]]) -> go.Figure:
    if not alerts_data:
        fig = go.Figure()
        fig.add_annotation(text="No Alert Data Available", showarrow=False, font=dict(color="#64748b", size=14))
        fig.update_layout(**DARK_LAYOUT, height=260)
        return fig

    df = pd.DataFrame(alerts_data)
    cat_counts = df["category"].value_counts().reset_index()
    cat_counts.columns = ["category", "count"]

    fig = px.bar(
        cat_counts,
        x="count",
        y="category",
        orientation="h",
        color="category",
        color_discrete_sequence=["#38bdf8", "#818cf8", "#f43f5e", "#fb923c"],
        text="count"
    )
    fig.update_layout(
        **DARK_LAYOUT,
        title=dict(text="<b>Detections by Threat Vector</b>", font=dict(size=14, color="#f8fafc")),
        height=260,
        showlegend=False,
        xaxis=dict(showgrid=True, gridcolor="rgba(148, 163, 184, 0.1)"),
        yaxis=dict(autorange="reversed")
    )
    fig.update_traces(textposition="outside", cliponaxis=False)
    return fig


def create_risk_score_gauge(score: int, title: str = "AI Dynamic Risk Index") -> go.Figure:
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"<b>{title}</b>", 'font': {'size': 14, 'color': '#f8fafc'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#475569"},
            'bar': {'color': "#38bdf8", 'thickness': 0.28},
            'bgcolor': "rgba(15, 23, 42, 0.6)",
            'borderwidth': 1,
            'bordercolor': "#334155",
            'steps': [
                {'range': [0, 45], 'color': 'rgba(16, 185, 129, 0.2)'},
                {'range': [45, 70], 'color': 'rgba(234, 179, 8, 0.2)'},
                {'range': [70, 85], 'color': 'rgba(249, 115, 22, 0.25)'},
                {'range': [85, 100], 'color': 'rgba(239, 68, 68, 0.35)'}
            ],
            'threshold': {
                'line': {'color': "#ef4444", 'width': 3},
                'thickness': 0.8,
                'value': 85
            }
        }
    ))
    fig.update_layout(
        **DARK_LAYOUT,
        height=220,
        margin=dict(l=25, r=25, t=40, b=15)
    )
    return fig


def create_ml_anomaly_scatter(fraud_logs: List[Dict[str, Any]]) -> go.Figure:
    if not fraud_logs:
        fig = go.Figure()
        fig.add_annotation(text="No Transaction Data Available", showarrow=False, font=dict(color="#64748b", size=14))
        fig.update_layout(**DARK_LAYOUT, height=320)
        return fig

    df = pd.DataFrame(fraud_logs)
    if "amount" not in df.columns:
        df["amount"] = 500.0

    if "ai_risk_score" not in df.columns:
        df["ai_risk_score"] = 50

    fig = px.scatter(
        df,
        x="amount",
        y="ai_risk_score",
        color="severity",
        size="ai_risk_score",
        hover_data=["rule_name", "affected_account", "source_ip"],
        color_discrete_map=SEVERITY_COLORS,
        labels={"amount": "Transaction Amount ($)", "ai_risk_score": "Isolation Forest / Risk Score"}
    )

    fig.add_hline(y=75, line_dash="dash", line_color="#ef4444", annotation_text="High Risk Threshold (75)", annotation_position="bottom right")
    fig.add_vline(x=50000, line_dash="dot", line_color="#f97316", annotation_text="Large Tx Limit ($50k)", annotation_position="top left")

    fig.update_layout(
        **DARK_LAYOUT,
        title=dict(text="<b>Transaction Risk Clustering & ML Anomaly Outliers</b>", font=dict(size=14, color="#f8fafc")),
        height=320,
        xaxis=dict(showgrid=True, gridcolor="rgba(148, 163, 184, 0.1)"),
        yaxis=dict(showgrid=True, gridcolor="rgba(148, 163, 184, 0.1)")
    )
    return fig


def create_mitre_bar_chart(alerts_data: List[Dict[str, Any]]) -> go.Figure:
    if not alerts_data:
        fig = go.Figure()
        fig.add_annotation(text="No Alert Data", showarrow=False, font=dict(color="#64748b", size=14))
        fig.update_layout(**DARK_LAYOUT, height=280)
        return fig

    df = pd.DataFrame(alerts_data)
    techniques = df[df["mitre_technique_id"].notna()]["mitre_technique_id"] + " - " + df["mitre_technique_name"].fillna("Unknown")
    counts = techniques.value_counts().reset_index()
    counts.columns = ["technique", "count"]

    fig = px.bar(
        counts.head(7),
        x="count",
        y="technique",
        orientation="h",
        color="count",
        color_continuous_scale="Purples",
        text="count"
    )
    fig.update_layout(
        **DARK_LAYOUT,
        title=dict(text="<b>Top MITRE ATT&CK Techniques Observed</b>", font=dict(size=14, color="#f8fafc")),
        height=280,
        coloraxis_showscale=False,
        yaxis=dict(autorange="reversed"),
        xaxis=dict(showgrid=True, gridcolor="rgba(148, 163, 184, 0.1)")
    )
    fig.update_traces(textposition="outside", cliponaxis=False)
    return fig

