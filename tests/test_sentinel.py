import pytest
from datetime import datetime, timedelta
from backend.database import SessionLocal, init_db
from backend.models import LogEntry, Alert, Incident, ThreatIOC
from backend.engine.log_parser import LogParser
from backend.engine.detector import DetectionEngine
from backend.engine.ml_anomaly import TransactionAnomalyDetector
from backend.ai_analyzer.analyzer import AISecurityAnalyzer
from backend.threat_intel.threat_service import ThreatIntelligenceService
from backend.threat_intel.mitre_map import get_mitre_mapping
from backend.incidents.incident_manager import IncidentManager
from backend.simulator.attack_simulator import BankAttackSimulator


@pytest.fixture(scope="module")
def setup_db():
    init_db()
    db = SessionLocal()
    threat_service = ThreatIntelligenceService(db)
    threat_service.seed_initial_iocs()
    yield db
    db.close()


def test_log_normalization():
    raw_event = {
        "type": "web",
        "ip": "203.0.113.19",
        "url": "/api/v1/transfer?id=1' OR '1'='1",
        "method": "GET",
        "response_code": "500",
        "time": "2026-11-07T10:00:00Z"
    }
    normalized = LogParser.normalize_event(raw_event)
    assert normalized["log_type"] == "web"
    assert normalized["source_ip"] == "203.0.113.19"
    assert normalized["http_method"] == "GET"
    assert normalized["status_code"] == 500
    assert "1' OR '1'='1" in normalized["endpoint"]


def test_brute_force_detection(setup_db):
    db = setup_db
    engine = DetectionEngine(db)
    
    # Generate 6 failed logins for same user within 2 minutes
    now = datetime.utcnow()
    logs = []
    for i in range(6):
        entry = LogEntry(
            log_type="auth",
            timestamp=now - timedelta(seconds=120 - (i * 15)),
            source_ip="198.51.100.99",
            username="victim.user",
            action="login_failed",
            endpoint="/auth/login",
            status_code=401
        )
        db.add(entry)
        logs.append(entry)
    db.commit()
    for l in logs:
        db.refresh(l)

    alerts = engine.process_new_logs(logs)
    rule_ids = [a.rule_id for a in alerts]
    assert "RULE-AUTH-001" in rule_ids


def test_sql_injection_detection(setup_db):
    db = setup_db
    engine = DetectionEngine(db)
    
    entry = LogEntry(
        log_type="web",
        timestamp=datetime.utcnow(),
        source_ip="198.51.100.100",
        endpoint="/customer/cards?id=1' UNION SELECT credit_card_num, cvv, pin FROM bank_cards--",
        http_method="GET",
        status_code=500,
        payload="UNION SELECT credit_card_num, cvv, pin"
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    alerts = engine.process_new_logs([entry])
    rule_ids = [a.rule_id for a in alerts]
    assert "RULE-WEB-001" in rule_ids


def test_aml_structuring_detection(setup_db):
    db = setup_db
    engine = DetectionEngine(db)
    
    now = datetime.utcnow()
    logs = []
    # 4 transfers of $9,500 within 4 hours
    for i in range(4):
        entry = LogEntry(
            log_type="transaction",
            timestamp=now - timedelta(hours=4 - i),
            source_ip="198.51.100.105",
            source_account="ACC-STRUCT-999",
            destination_account=f"MULE-{i}",
            amount=9500.00,
            currency="USD",
            action="wire_transfer"
        )
        db.add(entry)
        logs.append(entry)
    db.commit()
    for l in logs:
        db.refresh(l)

    alerts = engine.process_new_logs(logs)
    rule_ids = [a.rule_id for a in alerts]
    assert "RULE-FRD-003" in rule_ids


def test_ml_isolation_forest():
    detector = TransactionAnomalyDetector()
    
    # Normal transaction: $85 at 14:00
    normal_entry = LogEntry(amount=85.0, timestamp=datetime(2026, 11, 7, 14, 0, 0))
    is_ano_normal, score_normal, _ = detector.predict(normal_entry, recent_tx_count=1)
    
    # Extreme outlier transaction: $180,000 at 03:00 AM with velocity burst 12
    extreme_entry = LogEntry(amount=180000.0, timestamp=datetime(2026, 11, 7, 3, 15, 0))
    is_ano_ext, score_ext, _ = detector.predict(extreme_entry, recent_tx_count=12)

    assert score_ext > score_normal
    assert bool(is_ano_ext) is True


def test_ai_security_analyzer():
    res = AISecurityAnalyzer.analyze_event(
        rule_id="RULE-FRD-003",
        rule_name="Transaction Structuring (Smurfing)",
        category="FINANCIAL_FRAUD",
        severity="CRITICAL",
        source_ip="185.220.101.5",
        affected_account="ACC-882910",
        evidence={"smurfing_transaction_count": 4, "total_structured_amount": 38000.0}
    )
    assert res["dynamic_risk_score"] >= 80
    assert "Smurfing" in res["root_cause_explanation"] or "Structuring" in res["root_cause_explanation"]
    assert len(res["recommended_playbook"]) >= 3
    assert "BSA" in res["root_cause_explanation"] or "FinCEN" in res["root_cause_explanation"] or "structuring" in res["root_cause_explanation"].lower()


def test_incident_lifecycle(setup_db):
    db = setup_db
    manager = IncidentManager(db)
    
    inc = manager.create_incident(
        title="Unauthorized SWIFT Gateway Tampering",
        description="Core banking admin interface touched from Tor exit node.",
        severity="CRITICAL",
        assigned_to="Alex Rivera (L1 SOC Analyst)"
    )
    assert inc.status == "OPEN"
    assert inc.incident_uuid.startswith("INC-")

    # Add Note
    note = manager.add_note(inc.id, "Alex Rivera", "Verified with shift supervisor; no approved maintenance.")
    assert note.content == "Verified with shift supervisor; no approved maintenance."

    # Execute containment
    inc = manager.execute_containment_action(inc.id, "BORDER_IP_BLOCK", "Blocked 185.220.101.5 on edge firewall", "Alex Rivera")
    assert "BORDER_IP_BLOCK" in inc.containment_actions

    # Escalate to L2
    inc = manager.escalate(inc.id, "L2_INVESTIGATION", "Elena Rostova", "Alex Rivera", "Immediate forensic memory dump requested")
    assert inc.escalation_level == "L2_INVESTIGATION"
    assert inc.assigned_to == "Elena Rostova"
