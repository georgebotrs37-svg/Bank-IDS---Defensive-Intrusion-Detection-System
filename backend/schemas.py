from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# ----------------- Log Schemas -----------------
class LogEntryBase(BaseModel):
    log_type: str = Field(..., description="auth, web, or transaction")
    timestamp: Optional[datetime] = None
    source_ip: str
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    action: str
    endpoint: Optional[str] = None
    http_method: Optional[str] = None
    status_code: Optional[int] = None
    payload: Optional[str] = None
    user_agent: Optional[str] = None
    
    amount: Optional[float] = None
    currency: Optional[str] = "USD"
    source_account: Optional[str] = None
    destination_account: Optional[str] = None
    transaction_type: Optional[str] = None
    
    location_city: Optional[str] = None
    location_country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    
    raw_log: Optional[str] = None


class LogEntryCreate(LogEntryBase):
    pass


class LogEntryResponse(LogEntryBase):
    id: int
    is_anomalous: bool
    processed: bool

    class Config:
        from_attributes = True


class LogBatchCreate(BaseModel):
    logs: List[LogEntryCreate]


# ----------------- Alert Schemas -----------------
class AlertBase(BaseModel):
    rule_id: str
    rule_name: str
    category: str
    severity: str
    source_ip: str
    destination_ip: Optional[str] = None
    affected_user: Optional[str] = None
    affected_account: Optional[str] = None
    description: str
    evidence: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    ai_risk_score: Optional[int] = 50
    ai_explanation: Optional[str] = None
    ai_recommended_actions: Optional[str] = None


class AlertCreate(AlertBase):
    alert_uuid: Optional[str] = None


class AlertResponse(AlertBase):
    id: int
    alert_uuid: str
    timestamp: datetime
    status: str
    assigned_to: Optional[str] = None
    incident_id: Optional[int] = None

    class Config:
        from_attributes = True


class AlertUpdateStatus(BaseModel):
    status: str
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


# ----------------- Incident Schemas -----------------
class IncidentTimelineResponse(BaseModel):
    id: int
    timestamp: datetime
    actor: str
    action: str
    details: str

    class Config:
        from_attributes = True


class IncidentNoteCreate(BaseModel):
    analyst_name: str
    content: str


class IncidentNoteResponse(BaseModel):
    id: int
    timestamp: datetime
    analyst_name: str
    content: str

    class Config:
        from_attributes = True


class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str = "HIGH"
    assigned_to: Optional[str] = "Alex Rivera (L1 SOC Analyst)"
    escalation_level: Optional[str] = "L1_TRIAGE"
    alert_ids: Optional[List[int]] = []


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    escalation_level: Optional[str] = None
    assigned_to: Optional[str] = None
    root_cause_summary: Optional[str] = None
    containment_actions: Optional[str] = None
    remediation_summary: Optional[str] = None


class IncidentResponse(BaseModel):
    id: int
    incident_uuid: str
    created_at: datetime
    updated_at: datetime
    title: str
    description: str
    severity: str
    status: str
    escalation_level: str
    assigned_to: str
    root_cause_summary: Optional[str] = None
    containment_actions: Optional[str] = None
    remediation_summary: Optional[str] = None
    alerts: List[AlertResponse] = []
    timeline_events: List[IncidentTimelineResponse] = []
    notes: List[IncidentNoteResponse] = []

    class Config:
        from_attributes = True


# ----------------- Threat Intel Schemas -----------------
class ThreatIOCCreate(BaseModel):
    ioc_type: str
    value: str
    threat_actor: Optional[str] = None
    threat_type: str
    confidence: int = 80
    severity: str = "HIGH"
    description: Optional[str] = None
    tags: Optional[str] = None


class ThreatIOCResponse(ThreatIOCCreate):
    id: int
    last_seen: datetime

    class Config:
        from_attributes = True


class ThreatLookupRequest(BaseModel):
    ip_address: str


class ThreatLookupResponse(BaseModel):
    ip_address: str
    is_malicious: bool
    reputation_score: int  # 0 (Safe) to 100 (Critical Malicious)
    categories: List[str]
    threat_actor: Optional[str] = None
    details: Dict[str, Any]
    mitre_mappings: List[Dict[str, str]]


# ----------------- AI Security Analyzer Schemas -----------------
class AIAnalyzeRequest(BaseModel):
    alert_id: Optional[int] = None
    log_id: Optional[int] = None
    event_payload: Optional[Dict[str, Any]] = None


class AIAnalyzeResponse(BaseModel):
    event_summary: str
    root_cause_explanation: str
    dynamic_risk_score: int  # 0 to 100
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    suspicious_patterns: List[str]
    attack_chain_context: str
    recommended_playbook: List[str]
    containment_priority: str
    analyst_decision_support: str


# ----------------- Fraud Schemas -----------------
class FraudAnalysisResult(BaseModel):
    account_id: str
    risk_score: float
    flagged_reasons: List[str]
    structuring_detected: bool
    structuring_transactions_count: int
    velocity_spike_detected: bool
    ml_anomaly_score: float
    is_ml_outlier: bool
    recommendations: List[str]


# ----------------- SOC Overview Stats -----------------
class SOCStatsResponse(BaseModel):
    total_events: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    active_incidents: int
    suspicious_ips: int
    transaction_anomalies: int
    threat_posture_score: int  # 0-100 system security index

