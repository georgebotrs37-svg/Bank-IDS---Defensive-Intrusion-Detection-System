from typing import List, Dict, Any
from backend.models import Alert


class AttackChainCorrelator:
    """
    Correlates disparate security alerts into end-to-end multi-stage cyber kill chains.
    Links web application attacks, authentication compromise, and financial fraud.
    """

    STAGE_WEIGHTS = {
        "WEB_APPLICATION": 1,
        "AUTHENTICATION": 2,
        "FINANCIAL_FRAUD": 3
    }

    @classmethod
    def correlate_alerts(cls, alerts: List[Alert]) -> List[Dict[str, Any]]:
        """
        Groups alerts by Source IP, Affected User, or Affected Account
        to uncover linked attack campaigns.
        """
        chains_by_ip: Dict[str, List[Alert]] = {}
        chains_by_user: Dict[str, List[Alert]] = {}

        for alert in alerts:
            if alert.source_ip and alert.source_ip != "127.0.0.1":
                chains_by_ip.setdefault(alert.source_ip, []).append(alert)
            if alert.affected_user and alert.affected_user not in ("MULTIPLE_USERS", "MULTIPLE_ACCOUNTS"):
                chains_by_user.setdefault(alert.affected_user, []).append(alert)

        campaigns = []

        # Analyze IP-based campaigns
        for ip, group in chains_by_ip.items():
            if len(group) >= 2:
                categories = {a.category for a in group}
                rules = [a.rule_name for a in group]
                severities = [a.severity for a in group]
                
                # Check if campaign spans multiple kill-chain stages
                is_multi_stage = len(categories) >= 2 or len(group) >= 3
                campaign_title = f"Multi-Vector Campaign from IP {ip}" if is_multi_stage else f"Repeated Attack Activity from {ip}"
                
                max_score = max(a.ai_risk_score or 50 for a in group)
                if is_multi_stage:
                    max_score = min(100, max_score + 10)

                campaigns.append({
                    "pivot_type": "SOURCE_IP",
                    "pivot_value": ip,
                    "title": campaign_title,
                    "alert_count": len(group),
                    "is_multi_stage": is_multi_stage,
                    "categories_involved": list(categories),
                    "rule_names": list(set(rules)),
                    "max_risk_score": max_score,
                    "earliest_event": min(a.timestamp for a in group).isoformat(),
                    "latest_event": max(a.timestamp for a in group).isoformat(),
                    "alert_ids": [a.id for a in group],
                    "kill_chain_summary": " -> ".join(sorted(list(categories), key=lambda c: cls.STAGE_WEIGHTS.get(c, 0)))
                })

        # Analyze User-based campaigns (compromised accounts)
        for user, group in chains_by_user.items():
            if len(group) >= 2:
                categories = {a.category for a in group}
                has_auth = "AUTHENTICATION" in categories
                has_fraud = "FINANCIAL_FRAUD" in categories

                if has_auth and has_fraud:
                    campaigns.append({
                        "pivot_type": "AFFECTED_USER",
                        "pivot_value": user,
                        "title": f"Account Compromise & Unauthorized Fraud on user '{user}'",
                        "alert_count": len(group),
                        "is_multi_stage": True,
                        "categories_involved": list(categories),
                        "rule_names": list(set(a.rule_name for a in group)),
                        "max_risk_score": 98,
                        "earliest_event": min(a.timestamp for a in group).isoformat(),
                        "latest_event": max(a.timestamp for a in group).isoformat(),
                        "alert_ids": [a.id for a in group],
                        "kill_chain_summary": "Credential Attack -> Account Access -> Fraudulent Outflow"
                    })

        # Sort by highest risk score descending
        campaigns.sort(key=lambda x: x["max_risk_score"], reverse=True)
        return campaigns

