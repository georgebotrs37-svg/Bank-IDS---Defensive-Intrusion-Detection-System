import uuid
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from backend.models import LogEntry, Alert, SeverityEnum, AlertStatusEnum
from backend.rules.auth_rules import (
    BruteForceRule, CredentialStuffingRule, AccountTakeoverRule,
    ImpossibleTravelRule, SuspiciousAdminLoginRule
)
from backend.rules.web_rules import (
    SQLInjectionRule, XSSRule, PathTraversalRule, CommandInjectionRule
)
from backend.rules.fraud_rules import (
    LargeTransactionRule, TransactionVelocityRule, TransactionStructuringRule,
    IsolationForestAnomalyRule
)
from backend.threat_intel.threat_service import ThreatIntelligenceService
from backend.threat_intel.mitre_map import get_mitre_mapping
from backend.ai_analyzer.analyzer import AISecurityAnalyzer


class DetectionEngine:
    """
    Unified Detection Engine orchestrating 12 Banking Security and Fraud detection rules,
    AI Security Analyzer integration, and Threat Intelligence scoring.
    """
    def __init__(self, db: Session):
        self.db = db
        self.threat_service = ThreatIntelligenceService(db)
        
        # Instantiate all detection rules
        self.rules = [
            # Authentication & Credential Attacks
            BruteForceRule(),
            CredentialStuffingRule(),
            AccountTakeoverRule(),
            ImpossibleTravelRule(),
            SuspiciousAdminLoginRule(),
            # Web Application Attacks
            SQLInjectionRule(),
            XSSRule(),
            PathTraversalRule(),
            CommandInjectionRule(),
            # Financial Fraud & AML
            LargeTransactionRule(),
            TransactionVelocityRule(),
            TransactionStructuringRule(),
            IsolationForestAnomalyRule()
        ]

    def process_new_logs(self, new_logs: List[LogEntry]) -> List[Alert]:
        """
        Takes freshly ingested LogEntry objects, evaluates them across all rules
        against the recent contextual history, and persists any triggered alerts.
        """
        if not new_logs:
            return []

        # Retrieve recent contextual history (past 24 hours)
        earliest_time = min(l.timestamp for l in new_logs) - timedelta(hours=24)
        history_logs = self.db.query(LogEntry).filter(
            LogEntry.timestamp >= earliest_time,
            LogEntry.id.notin_([l.id for l in new_logs if l.id is not None])
        ).all()

        triggered_alerts_data = []

        # Evaluate through each rule
        for rule in self.rules:
            try:
                rule_alerts = rule.evaluate(new_logs=new_logs, history_logs=history_logs)
                if rule_alerts:
                    triggered_alerts_data.extend(rule_alerts)
            except Exception as e:
                print(f"[DetectionEngine Error] Rule {rule.rule_id} failed: {e}")

        created_alerts = []

        # Process each generated alert
        for a_data in triggered_alerts_data:
            # Threat Intel lookup
            threat_info = self.threat_service.get_ip_reputation(a_data.source_ip)
            
            # AI Security Analyzer deep dive
            ai_analysis = AISecurityAnalyzer.analyze_event(
                rule_id=a_data.rule_id,
                rule_name=a_data.rule_name,
                category=a_data.category,
                severity=a_data.severity,
                source_ip=a_data.source_ip,
                affected_user=a_data.affected_user,
                affected_account=a_data.affected_account,
                evidence=a_data.evidence,
                ip_reputation=threat_info
            )

            # MITRE taxonomy
            mitre_info = get_mitre_mapping(a_data.rule_id)

            alert_uuid = f"ALT-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

            alert_obj = Alert(
                alert_uuid=alert_uuid,
                timestamp=a_data.timestamp,
                rule_id=a_data.rule_id,
                rule_name=a_data.rule_name,
                category=a_data.category,
                severity=a_data.severity,
                source_ip=a_data.source_ip,
                destination_ip=a_data.destination_ip,
                affected_user=a_data.affected_user,
                affected_account=a_data.affected_account,
                description=a_data.description,
                evidence=json.dumps(a_data.evidence or {}, default=str),
                mitre_tactic=mitre_info.get("tactic"),
                mitre_technique_id=mitre_info.get("technique_id"),
                mitre_technique_name=mitre_info.get("technique_name"),
                ai_risk_score=ai_analysis.get("dynamic_risk_score", 50),
                ai_explanation=ai_analysis.get("root_cause_explanation"),
                ai_recommended_actions=json.dumps(ai_analysis.get("recommended_playbook", [])),
                status=AlertStatusEnum.NEW.value,
                assigned_to=None
            )

            self.db.add(alert_obj)
            created_alerts.append(alert_obj)

        # Mark new logs as processed and flag anomalous ones
        anomalous_ips = {a.source_ip for a in triggered_alerts_data}
        anomalous_users = {a.affected_user for a in triggered_alerts_data if a.affected_user}
        anomalous_accs = {a.affected_account for a in triggered_alerts_data if a.affected_account}

        for l in new_logs:
            l.processed = True
            if (l.source_ip in anomalous_ips or 
                l.username in anomalous_users or 
                l.source_account in anomalous_accs):
                l.is_anomalous = True

        self.db.commit()

        for a in created_alerts:
            self.db.refresh(a)

        return created_alerts

