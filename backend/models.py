import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from backend.database import Base


class SeverityEnum(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertStatusEnum(str, enum.Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ESCALATED = "ESCALATED"


class IncidentStatusEnum(str, enum.Enum):
    OPEN = "OPEN"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED_FALSE_POSITIVE = "CLOSED_FALSE_POSITIVE"


class EscalationLevelEnum(str, enum.Enum):
    L1_TRIAGE = "L1_TRIAGE"
    L2_INVESTIGATION = "L2_INVESTIGATION"
    L3_FORENSICS_LEAD = "L3_FORENSICS_LEAD"
    EXECUTIVE_CRISIS = "EXECUTIVE_CRISIS"


class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    log_type = Column(String(32), index=True)  # auth, web, transaction
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(64), index=True)
    destination_ip = Column(String(64), nullable=True)
    username = Column(String(128), nullable=True, index=True)
    action = Column(String(128), index=True)  # login_failed, login_success, wire_transfer, http_get, etc.
    endpoint = Column(String(512), nullable=True)
    http_method = Column(String(16), nullable=True)
    status_code = Column(Integer, nullable=True)
    payload = Column(Text, nullable=True)
    user_agent = Column(String(512), nullable=True)
    
    # Financial fields
    amount = Column(Float, nullable=True)
    currency = Column(String(8), default="USD")
    source_account = Column(String(64), nullable=True, index=True)
    destination_account = Column(String(64), nullable=True, index=True)
    transaction_type = Column(String(64), nullable=True)
    
    # Geo location fields
    location_city = Column(String(64), nullable=True)
    location_country = Column(String(64), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    
    raw_log = Column(Text, nullable=True)
    is_anomalous = Column(Boolean, default=False)
    processed = Column(Boolean, default=False)

    __table_args__ = (
        Index("idx_log_type_ts", "log_type", "timestamp"),
        Index("idx_src_ip_ts", "source_ip", "timestamp"),
        Index("idx_user_ts", "username", "timestamp"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_uuid = Column(String(64), unique=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    rule_id = Column(String(64), index=True)
    rule_name = Column(String(256), index=True)
    category = Column(String(64), index=True)  # AUTHENTICATION, WEB_APP, FINANCIAL_FRAUD, THREAT_INTEL
    severity = Column(String(32), default=SeverityEnum.MEDIUM.value, index=True)
    
    source_ip = Column(String(64), index=True)
    destination_ip = Column(String(64), nullable=True)
    affected_user = Column(String(128), nullable=True, index=True)
    affected_account = Column(String(64), nullable=True, index=True)
    
    description = Column(Text)
    evidence = Column(Text)  # JSON formatted strings with payload / logs
    
    # MITRE ATT&CK Mapping
    mitre_tactic = Column(String(128), nullable=True)
    mitre_technique_id = Column(String(64), nullable=True)
    mitre_technique_name = Column(String(256), nullable=True)
    
    # AI Security Analyzer outputs
    ai_risk_score = Column(Integer, default=50)  # 0 to 100
    ai_explanation = Column(Text, nullable=True)
    ai_recommended_actions = Column(Text, nullable=True)  # JSON list
    
    status = Column(String(32), default=AlertStatusEnum.NEW.value, index=True)
    assigned_to = Column(String(128), nullable=True)
    
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    incident = relationship("Incident", back_populates="alerts")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_uuid = Column(String(64), unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    title = Column(String(256), index=True)
    description = Column(Text)
    severity = Column(String(32), default=SeverityEnum.HIGH.value, index=True)
    status = Column(String(32), default=IncidentStatusEnum.OPEN.value, index=True)
    escalation_level = Column(String(32), default=EscalationLevelEnum.L1_TRIAGE.value)
    
    assigned_to = Column(String(128), default="Alex Rivera (L1 SOC Analyst)")
    root_cause_summary = Column(Text, nullable=True)
    containment_actions = Column(Text, nullable=True)
    remediation_summary = Column(Text, nullable=True)
    
    alerts = relationship("Alert", back_populates="incident")
    timeline_events = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentTimeline.timestamp")
    notes = relationship("IncidentNote", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentNote.timestamp")


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    actor = Column(String(128))  # SOC Analyst or System/Rule/AI
    action = Column(String(128))  # STATUS_CHANGE, ALERT_LINKED, NOTE_ADDED, CONTAINMENT_EXECUTED
    details = Column(Text)

    incident = relationship("Incident", back_populates="timeline_events")


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    analyst_name = Column(String(128))
    content = Column(Text)

    incident = relationship("Incident", back_populates="notes")


class ThreatIOC(Base):
    __tablename__ = "threat_iocs"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String(32), index=True)  # IP, DOMAIN, HASH, USER_AGENT
    value = Column(String(256), unique=True, index=True)
    threat_actor = Column(String(128), nullable=True)
    threat_type = Column(String(128))  # Tor Exit Node, Banking C2, Web Scanner, Bulletproof Host
    confidence = Column(Integer, default=80)
    severity = Column(String(32), default=SeverityEnum.HIGH.value)
    description = Column(Text, nullable=True)
    tags = Column(String(256), nullable=True)
    last_seen = Column(DateTime, default=datetime.utcnow)


class Analyst(Base):
    __tablename__ = "analysts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), unique=True)
    role = Column(String(128))
    email = Column(String(128))

