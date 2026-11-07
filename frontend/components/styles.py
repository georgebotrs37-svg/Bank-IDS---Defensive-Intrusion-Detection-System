"""
Professional Cybersecurity Dark Theme & Glassmorphic SOC Styles
Designed for MR.X BANK SOC SENTINEL
"""

SOC_CSS = """
<style>
/* Main Dark Theme & Fonts */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@300;400;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Code and raw evidence styling */
code, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Custom Header Banner */
.soc-header {
    background: linear-gradient(135deg, #0b1120 0%, #0f172a 50%, #1e1b4b 100%);
    border: 1px solid rgba(56, 189, 248, 0.2);
    border-radius: 12px;
    padding: 20px 28px;
    margin-bottom: 24px;
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 0 15px rgba(56, 189, 248, 0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.soc-title {
    color: #f8fafc;
    font-size: 26px;
    font-weight: 800;
    letter-spacing: -0.5px;
    margin: 0;
    display: flex;
    align-items: center;
    gap: 12px;
}

.soc-subtitle {
    color: #94a3b8;
    font-size: 13px;
    margin-top: 4px;
    letter-spacing: 0.2px;
}

.soc-pulse {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background-color: #10b981;
    box-shadow: 0 0 10px #10b981;
    animation: pulse-green 2s infinite;
}

@keyframes pulse-green {
    0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
    70% { transform: scale(1.1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
    100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}

/* Metric Cards */
.soc-metric-card {
    background: #0f172a;
    border: 1px solid rgba(148, 163, 184, 0.12);
    border-radius: 10px;
    padding: 16px 18px;
    margin-bottom: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    transition: transform 0.2s ease, border-color 0.2s ease;
}

.soc-metric-card:hover {
    transform: translateY(-2px);
    border-color: rgba(56, 189, 248, 0.3);
}

.soc-metric-title {
    color: #94a3b8;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}

.soc-metric-value {
    color: #f8fafc;
    font-size: 26px;
    font-weight: 800;
    margin: 6px 0 2px 0;
    font-family: 'JetBrains Mono', monospace;
}

.soc-metric-desc {
    color: #64748b;
    font-size: 11px;
}

/* Badges */
.badge-critical {
    background: rgba(239, 68, 68, 0.15);
    color: #f87171;
    border: 1px solid rgba(239, 68, 68, 0.4);
    padding: 3px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}

.badge-high {
    background: rgba(249, 115, 22, 0.15);
    color: #fb923c;
    border: 1px solid rgba(249, 115, 22, 0.4);
    padding: 3px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
}

.badge-medium {
    background: rgba(234, 179, 8, 0.15);
    color: #facc15;
    border: 1px solid rgba(234, 179, 8, 0.4);
    padding: 3px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
}

.badge-low {
    background: rgba(56, 189, 248, 0.15);
    color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.4);
    padding: 3px 8px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 600;
}

.badge-mitre {
    background: rgba(147, 51, 234, 0.15);
    color: #c084fc;
    border: 1px solid rgba(147, 51, 234, 0.35);
    padding: 2px 8px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 600;
}

/* Callout Box */
.soc-callout {
    background: #0f172a;
    border-left: 4px solid #38bdf8;
    padding: 14px 18px;
    border-radius: 0 8px 8px 0;
    margin: 12px 0;
    color: #cbd5e1;
    font-size: 13px;
}

.soc-callout-danger {
    border-left-color: #ef4444;
    background: rgba(239, 68, 68, 0.05);
}

.soc-callout-warning {
    border-left-color: #f59e0b;
    background: rgba(245, 158, 11, 0.05);
}

.soc-callout-success {
    border-left-color: #10b981;
    background: rgba(16, 185, 129, 0.05);
}

/* AI Explanation Box */
.ai-box {
    background: linear-gradient(180deg, #091322 0%, #0d1e38 100%);
    border: 1px solid #1e3a8a;
    border-radius: 10px;
    padding: 18px;
    margin: 14px 0;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
}

.ai-header {
    display: flex;
    align-items: center;
    gap: 8px;
    color: #60a5fa;
    font-weight: 700;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 10px;
}
</style>
"""

