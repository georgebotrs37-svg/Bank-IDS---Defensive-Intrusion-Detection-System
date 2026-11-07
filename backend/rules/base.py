from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime


class AlertData:
    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        category: str,
        severity: str,
        source_ip: str,
        description: str,
        destination_ip: Optional[str] = None,
        affected_user: Optional[str] = None,
        affected_account: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        ai_risk_score: int = 50,
        ai_explanation: Optional[str] = None,
        ai_recommended_actions: Optional[List[str]] = None
    ):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.category = category
        self.severity = severity
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.affected_user = affected_user
        self.affected_account = affected_account
        self.description = description
        self.evidence = evidence or {}
        self.timestamp = timestamp or datetime.utcnow()
        self.ai_risk_score = ai_risk_score
        self.ai_explanation = ai_explanation
        self.ai_recommended_actions = ai_recommended_actions or []


class BaseDetectionRule(ABC):
    def __init__(self, rule_id: str, name: str, category: str, default_severity: str):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.default_severity = default_severity

    @abstractmethod
    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        """
        Evaluate new incoming logs against historical contextual logs.
        Returns a list of AlertData instances when criteria are satisfied.
        """
        pass

