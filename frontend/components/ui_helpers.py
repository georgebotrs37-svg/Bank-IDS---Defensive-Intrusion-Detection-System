import os
import json
import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime

API_BASE = os.getenv("API_BASE_URL", "http://127.0.0.1:8000/api")


def api_get(endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """Performs HTTP GET request to FastAPI backend."""
    try:
        url = f"{API_BASE}{endpoint}"
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url, params=params)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return None


def api_post(endpoint: str, json_data: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> Any:
    """Performs HTTP POST request to FastAPI backend."""
    try:
        url = f"{API_BASE}{endpoint}"
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(url, json=json_data, params=params)
            if resp.status_code in (200, 201):
                return resp.json()
    except Exception:
        pass
    return None


def api_patch(endpoint: str, json_data: Optional[Dict[str, Any]] = None) -> Any:
    """Performs HTTP PATCH request to FastAPI backend."""
    try:
        url = f"{API_BASE}{endpoint}"
        with httpx.Client(timeout=10.0) as client:
            resp = client.patch(url, json=json_data)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return None


def render_metric_card(title: str, value: Any, desc: str = "", badge: str = ""):
    badge_html = f"<span class='badge-{badge.lower()}'>{badge}</span>" if badge else ""
    return f"""
    <div class="soc-metric-card">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <div class="soc-metric-title">{title}</div>
            {badge_html}
        </div>
        <div class="soc-metric-value">{value}</div>
        <div class="soc-metric-desc">{desc}</div>
    </div>
    """


def get_severity_badge(severity: str) -> str:
    s = (severity or "INFO").upper()
    css_class = f"badge-{s.lower()}"
    return f"<span class='{css_class}'>{s}</span>"


def get_mitre_badge(technique_id: str, technique_name: str = "") -> str:
    name_str = f": {technique_name}" if technique_name else ""
    return f"<span class='badge-mitre'>[{technique_id}]{name_str}</span>"

