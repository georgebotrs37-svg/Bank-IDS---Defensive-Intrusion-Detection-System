from datetime import datetime, timedelta
from typing import List, Dict, Any
from backend.rules.base import BaseDetectionRule, AlertData
from backend.config import THRESHOLDS
from backend.engine.ml_anomaly import TransactionAnomalyDetector

ml_detector = TransactionAnomalyDetector()


class LargeTransactionRule(BaseDetectionRule):
    """
    Detects Large Financial Transactions:
    Any individual wire transfer, debit, or payment exceeding bank risk policy threshold ($50,000+).
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-FRD-001",
            name="Large High-Risk Financial Transaction Exceeded",
            category="FINANCIAL_FRAUD",
            default_severity="HIGH"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        limit = THRESHOLDS["LARGE_TRANSACTION_LIMIT"]

        for log in new_logs:
            if getattr(log, "log_type", "") != "transaction":
                continue

            amount = float(getattr(log, "amount", 0.0) or 0.0)
            if amount >= limit:
                src_acc = getattr(log, "source_account", "N/A")
                dst_acc = getattr(log, "destination_account", "N/A")
                severity = "CRITICAL" if amount >= (limit * 2.5) else "HIGH"
                risk_score = 95 if amount >= (limit * 2.5) else 80

                alerts.append(AlertData(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=severity,
                    source_ip=getattr(log, "source_ip", "unknown"),
                    affected_user=getattr(log, "username", None),
                    affected_account=src_acc,
                    description=f"Transaction of ${amount:,.2f} {getattr(log, 'currency', 'USD')} from account {src_acc} to {dst_acc} exceeds high-value threshold (${limit:,.2f}).",
                    evidence={
                        "amount": amount,
                        "currency": getattr(log, "currency", "USD"),
                        "threshold": limit,
                        "source_account": src_acc,
                        "destination_account": dst_acc,
                        "transaction_type": getattr(log, "transaction_type", "wire_transfer"),
                        "source_ip": getattr(log, "source_ip", "unknown")
                    },
                    timestamp=getattr(log, "timestamp"),
                    ai_risk_score=risk_score
                ))

        return alerts


class TransactionVelocityRule(BaseDetectionRule):
    """
    Detects Transaction Velocity Spikes:
    >= 4 transactions on the same account within a 3-minute window (indicative of automated drain).
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-FRD-002",
            name="Abnormal Transaction Velocity Spike",
            category="FINANCIAL_FRAUD",
            default_severity="HIGH"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        all_logs = sorted(history_logs + new_logs, key=lambda x: x.timestamp)
        window_sec = THRESHOLDS["VELOCITY_WINDOW_SEC"]
        max_tx = THRESHOLDS["VELOCITY_MAX_TX"]

        acc_map: Dict[str, List[Any]] = {}
        for log in all_logs:
            if getattr(log, "log_type", "") == "transaction":
                acc = getattr(log, "source_account", None)
                if acc:
                    acc_map.setdefault(acc, []).append(log)

        for acc, logs in acc_map.items():
            for i in range(len(logs)):
                window_start = logs[i].timestamp
                window_end = window_start + timedelta(seconds=window_sec)
                subset = [l for l in logs[i:] if l.timestamp <= window_end]

                has_new = any(getattr(l, "id", None) in [getattr(nl, "id", None) for nl in new_logs] for l in subset)
                if len(subset) >= max_tx and has_new:
                    total_amount = sum(float(getattr(l, "amount", 0.0) or 0.0) for l in subset)
                    dest_accs = list({getattr(l, "destination_account", "N/A") for l in subset})
                    alerts.append(AlertData(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=self.default_severity,
                        source_ip=getattr(subset[-1], "source_ip", "unknown"),
                        affected_user=getattr(subset[-1], "username", None),
                        affected_account=acc,
                        description=f"Rapid velocity spike: {len(subset)} transactions totaling ${total_amount:,.2f} executed within {window_sec}s from account {acc}.",
                        evidence={
                            "account_id": acc,
                            "transaction_count": len(subset),
                            "cumulative_amount": total_amount,
                            "destination_accounts": dest_accs[:5],
                            "time_span_seconds": (subset[-1].timestamp - subset[0].timestamp).total_seconds(),
                            "timestamps": [l.timestamp.isoformat() for l in subset]
                        },
                        timestamp=subset[-1].timestamp,
                        ai_risk_score=86
                    ))
                    break

        return alerts


class TransactionStructuringRule(BaseDetectionRule):
    """
    Detects Transaction Structuring (Smurfing):
    Multiple transactions intentionally placed just beneath the $10,000 regulatory reporting threshold
    ($9,000 - $9,999.99) within a 24-hour window to circumvent AML Bank Secrecy Act / CTR laws.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-FRD-003",
            name="Suspected AML Transaction Structuring (Smurfing)",
            category="FINANCIAL_FRAUD",
            default_severity="CRITICAL"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        all_logs = sorted(history_logs + new_logs, key=lambda x: x.timestamp)
        lower = THRESHOLDS["STRUCTURING_LOWER"]
        upper = THRESHOLDS["STRUCTURING_UPPER"]
        window_hours = THRESHOLDS["STRUCTURING_WINDOW_HOURS"]
        min_count = THRESHOLDS["STRUCTURING_MIN_COUNT"]

        # Group by source account and destination account
        acc_txs: Dict[str, List[Any]] = {}
        for log in all_logs:
            if getattr(log, "log_type", "") == "transaction":
                amt = float(getattr(log, "amount", 0.0) or 0.0)
                if lower <= amt <= upper:
                    acc = getattr(log, "source_account", None)
                    if acc:
                        acc_txs.setdefault(acc, []).append(log)

        for acc, logs in acc_txs.items():
            for i in range(len(logs)):
                w_start = logs[i].timestamp
                w_end = w_start + timedelta(hours=window_hours)
                subset = [l for l in logs[i:] if l.timestamp <= w_end]

                has_new = any(getattr(l, "id", None) in [getattr(nl, "id", None) for nl in new_logs] for l in subset)
                if len(subset) >= min_count and has_new:
                    total_sum = sum(float(getattr(l, "amount", 0.0) or 0.0) for l in subset)
                    sample_amts = [f"${float(getattr(l, 'amount', 0.0)):,.2f}" for l in subset]
                    alerts.append(AlertData(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=self.default_severity,
                        source_ip=getattr(subset[-1], "source_ip", "unknown"),
                        affected_user=getattr(subset[-1], "username", None),
                        affected_account=acc,
                        description=f"AML Structuring Pattern: {len(subset)} transfers between ${lower:,.0f} and ${upper:,.0f} totaling ${total_sum:,.2f} detected on account {acc} within {window_hours}h.",
                        evidence={
                            "source_account": acc,
                            "smurfing_transaction_count": len(subset),
                            "total_structured_amount": total_sum,
                            "sample_amounts": sample_amts,
                            "window_hours": window_hours,
                            "regulatory_context": "BSA 31 U.S.C. 5324 / FinCEN Anti-Structuring Rules",
                            "timestamps": [l.timestamp.isoformat() for l in subset]
                        },
                        timestamp=subset[-1].timestamp,
                        ai_risk_score=94
                    ))
                    break

        return alerts


class IsolationForestAnomalyRule(BaseDetectionRule):
    """
    Detects Machine Learning Transaction Anomalies:
    Unsupervised Isolation Forest flags transactions deviating significantly
    from retail banking baselines across multiple dimensions.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-FRD-004",
            name="ML Isolation Forest Anomaly Flagged",
            category="FINANCIAL_FRAUD",
            default_severity="MEDIUM"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        for log in new_logs:
            if getattr(log, "log_type", "") != "transaction":
                continue

            acc = getattr(log, "source_account", None)
            ts = getattr(log, "timestamp", datetime.utcnow())

            # Count recent transactions for this account in last 10 minutes
            recent_count = len([
                l for l in history_logs
                if getattr(l, "source_account", "") == acc
                and (ts - getattr(l, "timestamp", ts)).total_seconds() <= 600
            ]) + 1

            is_anomaly, score, breakdown = ml_detector.predict(log, recent_count)

            if is_anomaly:
                sev = "CRITICAL" if score >= 88 else ("HIGH" if score >= 75 else "MEDIUM")
                alerts.append(AlertData(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    category=self.category,
                    severity=sev,
                    source_ip=getattr(log, "source_ip", "unknown"),
                    affected_user=getattr(log, "username", None),
                    affected_account=acc,
                    description=f"Transaction of ${breakdown['amount']:,.2f} on account {acc} flagged by Isolation Forest with anomaly score {score:.1f}/100.",
                    evidence=breakdown,
                    timestamp=ts,
                    ai_risk_score=int(score)
                ))

        return alerts

