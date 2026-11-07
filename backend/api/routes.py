import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.database import get_db
from backend.models import (
    LogEntry, Alert, Incident, IncidentTimeline, IncidentNote,
    ThreatIOC, SeverityEnum, AlertStatusEnum, IncidentStatusEnum
)
from backend.schemas import (
    LogEntryCreate, LogEntryResponse, LogBatchCreate,
    AlertResponse, AlertUpdateStatus,
    IncidentCreate, IncidentUpdate, IncidentResponse, IncidentNoteCreate, IncidentNoteResponse,
    ThreatIOCCreate, ThreatIOCResponse, ThreatLookupResponse,
    AIAnalyzeRequest, AIAnalyzeResponse, SOCStatsResponse
)
from backend.engine.log_parser import LogParser
from backend.engine.detector import DetectionEngine
from backend.engine.correlation import AttackChainCorrelator
from backend.ai_analyzer.analyzer import AISecurityAnalyzer
from backend.threat_intel.threat_service import ThreatIntelligenceService
from backend.threat_intel.mitre_map import get_mitre_mapping
from backend.incidents.incident_manager import IncidentManager
from backend.simulator.attack_simulator import BankAttackSimulator

router = APIRouter(prefix="/api")


# ----------------- HEALTH & STATS -----------------
@router.get("/health")
def get_health():
    return {
        "status": "OPERATIONAL",
        "service": "MR.X BANK SOC SENTINEL",
        "version": "2.4.0-ENTERPRISE",
        "ai_engine": "ONLINE",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/stats", response_model=SOCStatsResponse)
def get_soc_overview_stats(db: Session = Depends(get_db)):
    total_events = db.query(LogEntry).count()
    total_alerts = db.query(Alert).count()
    critical_alerts = db.query(Alert).filter(Alert.severity == "CRITICAL").count()
    high_alerts = db.query(Alert).filter(Alert.severity == "HIGH").count()
    active_incidents = db.query(Incident).filter(
        Incident.status.in_(["OPEN", "UNDER_INVESTIGATION", "CONTAINED"])
    ).count()

    suspicious_ips_count = db.query(Alert.source_ip).distinct().count()
    fraud_alerts = db.query(Alert).filter(Alert.category == "FINANCIAL_FRAUD").count()

    # Calculate Threat Posture Score (100 = perfectly secure, decreases with open critical/high threats)
    threat_deductions = (critical_alerts * 8) + (high_alerts * 4) + (active_incidents * 6)
    threat_posture = max(15, min(100, 100 - threat_deductions))

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "active_incidents": active_incidents,
        "suspicious_ips": suspicious_ips_count,
        "transaction_anomalies": fraud_alerts,
        "threat_posture_score": threat_posture
    }


# ----------------- LOG INGESTION -----------------
@router.post("/logs/ingest", response_model=Dict[str, Any])
def ingest_logs(payload: LogBatchCreate, db: Session = Depends(get_db)):
    """Ingests a batch of logs, normalizes them, and runs the Detection Engine."""
    db_entries = []
    for item in payload.logs:
        normalized = LogParser.normalize_event(item.model_dump())
        entry = LogEntry(**normalized)
        db.add(entry)
        db_entries.append(entry)

    db.commit()
    for e in db_entries:
        db.refresh(e)

    # Process logs through detection engine
    engine = DetectionEngine(db)
    created_alerts = engine.process_new_logs(db_entries)

    return {
        "status": "SUCCESS",
        "ingested_count": len(db_entries),
        "alerts_triggered": len(created_alerts),
        "alert_uuids": [a.alert_uuid for a in created_alerts]
    }


@router.post("/logs/upload-jsonl")
async def upload_jsonl_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Uploads and ingests a JSON or JSONL file of banking telemetry."""
    contents = await file.read()
    text = contents.decode("utf-8", errors="ignore")
    parsed_logs = LogParser.parse_jsonl(text)

    if not parsed_logs:
        try:
            parsed_logs = LogParser.parse_json(text)
        except Exception:
            pass

    if not parsed_logs:
        raise HTTPException(status_code=400, detail="Invalid JSON/JSONL log file format.")

    db_entries = []
    for item in parsed_logs:
        entry = LogEntry(**item)
        db.add(entry)
        db_entries.append(entry)

    db.commit()
    for e in db_entries:
        db.refresh(e)

    engine = DetectionEngine(db)
    created_alerts = engine.process_new_logs(db_entries)

    return {
        "filename": file.filename,
        "ingested_logs": len(db_entries),
        "alerts_triggered": len(created_alerts)
    }


@router.get("/logs", response_model=List[LogEntryResponse])
def get_logs(
    log_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    is_anomalous: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(LogEntry)
    if log_type:
        query = query.filter(LogEntry.log_type == log_type)
    if source_ip:
        query = query.filter(LogEntry.source_ip == source_ip)
    if username:
        query = query.filter(LogEntry.username == username)
    if is_anomalous is not None:
        query = query.filter(LogEntry.is_anomalous == is_anomalous)

    return query.order_by(desc(LogEntry.timestamp)).offset(offset).limit(limit).all()


# ----------------- ALERTS MANAGEMENT -----------------
@router.get("/alerts", response_model=List[AlertResponse])
def get_alerts(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if category:
        query = query.filter(Alert.category == category.upper())
    if status:
        query = query.filter(Alert.status == status.upper())

    return query.order_by(desc(Alert.timestamp)).limit(limit).all()


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert_by_id(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return alert


@router.patch("/alerts/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(alert_id: int, payload: AlertUpdateStatus, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    alert.status = payload.status.upper()
    if payload.assigned_to:
        alert.assigned_to = payload.assigned_to
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/alerts/{alert_id}/promote-incident", response_model=IncidentResponse)
def promote_alert_to_incident(
    alert_id: int,
    assigned_to: str = Query("Alex Rivera (L1 SOC Analyst)"),
    db: Session = Depends(get_db)
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    manager = IncidentManager(db)
    incident = manager.create_incident(
        title=f"Incident Promoted from {alert.rule_name} ({alert.alert_uuid})",
        description=f"Automated incident spawned from high-priority alert {alert.alert_uuid}.\nDescription: {alert.description}\nEvidence: {alert.evidence}",
        severity=alert.severity,
        assigned_to=assigned_to,
        escalation_level="L1_TRIAGE",
        alert_ids=[alert.id],
        creator=assigned_to
    )
    return incident


# ----------------- AI SECURITY ANALYZER -----------------
@router.post("/ai/analyze", response_model=AIAnalyzeResponse)
def analyze_with_ai(payload: AIAnalyzeRequest, db: Session = Depends(get_db)):
    evidence = {}
    rule_id = "RULE-AUTH-001"
    rule_name = "Security Event Analysis"
    category = "AUTHENTICATION"
    severity = "HIGH"
    source_ip = "127.0.0.1"
    user = None
    account = None

    if payload.alert_id:
        alert = db.query(Alert).filter(Alert.id == payload.alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found.")
        rule_id = alert.rule_id
        rule_name = alert.rule_name
        category = alert.category
        severity = alert.severity
        source_ip = alert.source_ip
        user = alert.affected_user
        account = alert.affected_account
        try:
            evidence = json.loads(alert.evidence) if alert.evidence else {}
        except Exception:
            evidence = {"raw_evidence": alert.evidence}

    elif payload.event_payload:
        p = payload.event_payload
        rule_id = p.get("rule_id", "RULE-GEN-001")
        rule_name = p.get("rule_name", "Ad-Hoc Log Inspection")
        category = p.get("category", "WEB_APPLICATION")
        severity = p.get("severity", "MEDIUM")
        source_ip = p.get("source_ip", "127.0.0.1")
        user = p.get("username")
        account = p.get("source_account")
        evidence = p

    threat_service = ThreatIntelligenceService(db)
    ip_rep = threat_service.get_ip_reputation(source_ip)

    res = AISecurityAnalyzer.analyze_event(
        rule_id=rule_id,
        rule_name=rule_name,
        category=category,
        severity=severity,
        source_ip=source_ip,
        affected_user=user,
        affected_account=account,
        evidence=evidence,
        ip_reputation=ip_rep
    )
    return res


# ----------------- THREAT INTELLIGENCE -----------------
@router.get("/threat-intel/lookup/{ip_address}")
def lookup_ip_threat(ip_address: str, db: Session = Depends(get_db)):
    threat_service = ThreatIntelligenceService(db)
    rep = threat_service.get_ip_reputation(ip_address)
    
    # Associated MITRE mappings for typical attacks from this type of IP
    mitre_list = []
    if rep.get("is_malicious"):
        for cat in rep.get("categories", []):
            if "tor" in cat.lower() or "stuffing" in cat.lower():
                mitre_list.append(get_mitre_mapping("RULE-AUTH-002"))
            elif "c2" in cat.lower() or "swift" in cat.lower():
                mitre_list.append(get_mitre_mapping("RULE-FRD-001"))
            elif "scanner" in cat.lower() or "sqli" in cat.lower():
                mitre_list.append(get_mitre_mapping("RULE-WEB-001"))

    return {
        "ip_address": ip_address,
        "is_malicious": rep.get("is_malicious", False),
        "reputation_score": rep.get("reputation_score", 0),
        "severity": rep.get("severity", "LOW"),
        "categories": rep.get("categories", []),
        "threat_actor": rep.get("threat_actor"),
        "details": rep,
        "mitre_mappings": mitre_list
    }


@router.get("/threat-intel/iocs", response_model=List[ThreatIOCResponse])
def get_all_iocs(limit: int = 100, db: Session = Depends(get_db)):
    return db.query(ThreatIOC).order_by(desc(ThreatIOC.last_seen)).limit(limit).all()


@router.post("/threat-intel/iocs", response_model=ThreatIOCResponse)
def add_new_ioc(payload: ThreatIOCCreate, db: Session = Depends(get_db)):
    ioc = ThreatIOC(**payload.model_dump())
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc


# ----------------- INCIDENTS MANAGEMENT -----------------
@router.get("/incidents", response_model=List[IncidentResponse])
def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status.upper())
    if severity:
        query = query.filter(Incident.severity == severity.upper())

    return query.order_by(desc(Incident.created_at)).limit(limit).all()


@router.post("/incidents", response_model=IncidentResponse)
def create_new_incident(payload: IncidentCreate, db: Session = Depends(get_db)):
    manager = IncidentManager(db)
    return manager.create_incident(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        assigned_to=payload.assigned_to or "Alex Rivera (L1 SOC Analyst)",
        escalation_level=payload.escalation_level or "L1_TRIAGE",
        alert_ids=payload.alert_ids or [],
        creator=payload.assigned_to or "Alex Rivera (L1 SOC Analyst)"
    )


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident_details(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident


@router.patch("/incidents/{incident_id}", response_model=IncidentResponse)
def update_incident(incident_id: int, payload: IncidentUpdate, db: Session = Depends(get_db)):
    manager = IncidentManager(db)
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    if payload.status:
        incident = manager.update_status(
            incident_id=incident_id,
            new_status=payload.status,
            analyst_name=payload.assigned_to or incident.assigned_to,
            notes=f"Updated incident fields via API."
        )

    for field, val in payload.model_dump(exclude_unset=True).items():
        if field not in ("status",):
            setattr(incident, field, val)

    db.commit()
    db.refresh(incident)
    return incident


@router.post("/incidents/{incident_id}/notes", response_model=IncidentNoteResponse)
def add_incident_note(incident_id: int, payload: IncidentNoteCreate, db: Session = Depends(get_db)):
    manager = IncidentManager(db)
    return manager.add_note(
        incident_id=incident_id,
        analyst_name=payload.analyst_name,
        content=payload.content
    )


@router.post("/incidents/{incident_id}/escalate", response_model=IncidentResponse)
def escalate_incident_endpoint(
    incident_id: int,
    target_level: str = Query("L2_INVESTIGATION"),
    assigned_to: str = Query("Elena Rostova (L2 Senior Incident Responder)"),
    analyst_name: str = Query("Alex Rivera (L1 SOC Analyst)"),
    reason: str = Query("Escalating suspicious financial movement for L2 forensic review"),
    db: Session = Depends(get_db)
):
    manager = IncidentManager(db)
    return manager.escalate(
        incident_id=incident_id,
        target_level=target_level,
        assigned_to=assigned_to,
        analyst_name=analyst_name,
        reason=reason
    )


@router.post("/incidents/{incident_id}/contain", response_model=IncidentResponse)
def apply_containment(
    incident_id: int,
    action_name: str = Query(...),
    details: str = Query(...),
    analyst_name: str = Query("Alex Rivera (L1 SOC Analyst)"),
    db: Session = Depends(get_db)
):
    manager = IncidentManager(db)
    return manager.execute_containment_action(
        incident_id=incident_id,
        action_name=action_name,
        details=details,
        analyst_name=analyst_name
    )


# ----------------- FINANCIAL FRAUD & CORRELATIONS -----------------
@router.get("/fraud/summary")
def get_fraud_summary(db: Session = Depends(get_db)):
    fraud_alerts = db.query(Alert).filter(Alert.category == "FINANCIAL_FRAUD").all()
    structuring_alerts = [a for a in fraud_alerts if a.rule_id == "RULE-FRD-003"]
    velocity_alerts = [a for a in fraud_alerts if a.rule_id == "RULE-FRD-002"]
    large_tx_alerts = [a for a in fraud_alerts if a.rule_id == "RULE-FRD-001"]
    ml_alerts = [a for a in fraud_alerts if a.rule_id == "RULE-FRD-004"]

    flagged_accounts = list({a.affected_account for a in fraud_alerts if a.affected_account})

    return {
        "total_fraud_alerts": len(fraud_alerts),
        "structuring_smurfing_count": len(structuring_alerts),
        "velocity_spikes_count": len(velocity_alerts),
        "large_transaction_count": len(large_tx_alerts),
        "ml_isolation_forest_count": len(ml_alerts),
        "flagged_accounts": flagged_accounts,
        "recent_alerts": [
            {
                "id": a.id,
                "uuid": a.alert_uuid,
                "rule": a.rule_name,
                "account": a.affected_account,
                "severity": a.severity,
                "risk_score": a.ai_risk_score,
                "timestamp": a.timestamp.isoformat()
            } for a in sorted(fraud_alerts, key=lambda x: x.timestamp, reverse=True)[:10]
        ]
    }


@router.get("/correlations")
def get_attack_correlations(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(desc(Alert.timestamp)).limit(200).all()
    return AttackChainCorrelator.correlate_alerts(alerts)


# ----------------- SIMULATOR & SEEDING -----------------
@router.post("/simulate")
def trigger_simulation(scenario: str = Query(..., description="Scenario key"), db: Session = Depends(get_db)):
    res = BankAttackSimulator.run_simulation(scenario, db)
    return res


@router.post("/seed-demo")
def seed_demo_environment(db: Session = Depends(get_db)):
    """Initializes full baseline threat intelligence and simulates diverse banking attack scenarios."""
    threat_service = ThreatIntelligenceService(db)
    threat_service.seed_initial_iocs()

    scenarios = [
        "benign_flow",
        "brute_force",
        "sql_injection",
        "aml_structuring",
        "impossible_travel",
        "account_takeover",
        "web_exploit_chain"
    ]

    results = []
    for s in scenarios:
        r = BankAttackSimulator.run_simulation(s, db)
        results.append(r)

    # Automatically create 2 initial open Incidents from top critical alerts
    critical_alerts = db.query(Alert).filter(Alert.severity == "CRITICAL").limit(2).all()
    manager = IncidentManager(db)
    
    if len(critical_alerts) >= 1:
        manager.create_incident(
            title=f"CRITICAL: {critical_alerts[0].rule_name} Investigation",
            description=f"Auto-generated incident for critical alert {critical_alerts[0].alert_uuid}. Immediate triage underway.",
            severity="CRITICAL",
            assigned_to="Alex Rivera (L1 SOC Analyst)",
            escalation_level="L1_TRIAGE",
            alert_ids=[critical_alerts[0].id],
            creator="SYSTEM_AI_SENTINEL"
        )

    return {
        "status": "INITIALIZED",
        "message": "Demo data, threat intel IOCs, and banking attack scenarios successfully seeded.",
        "simulations": results
    }

