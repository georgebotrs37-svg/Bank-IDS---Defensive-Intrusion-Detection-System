import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.threat_intel.mitre_map import get_mitre_mapping


class AISecurityAnalyzer:
    """
    AI Security Analyst Assistant for L1/L2 Banking SOC Operations.
    Provides explainable threat reasoning, evidence-based risk scoring,
    pattern correlation, investigation summaries, and defensive containment playbooks.
    
    Adheres strictly to the SOC Decision-Support principle:
    Assists analysts with contextual hypotheses without prematurely auto-closing
    or unilaterally declaring attacks confirmed.
    """

    @classmethod
    def analyze_event(
        cls,
        rule_id: str,
        rule_name: str,
        category: str,
        severity: str,
        source_ip: str,
        affected_user: Optional[str] = None,
        affected_account: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        ip_reputation: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        evidence = evidence or {}
        ip_reputation = ip_reputation or {}
        mitre_data = get_mitre_mapping(rule_id)

        # 1. Explain why alert was generated (Root Cause)
        explanation = cls._generate_root_cause_explanation(
            rule_id=rule_id,
            evidence=evidence,
            source_ip=source_ip,
            affected_user=affected_user,
            affected_account=affected_account
        )

        # 2. Dynamic Risk Scoring Breakdown (0 to 100)
        risk_score, risk_factors = cls._calculate_dynamic_risk_score(
            rule_id=rule_id,
            severity=severity,
            category=category,
            evidence=evidence,
            ip_reputation=ip_reputation
        )

        # 3. Identify Suspicious Patterns
        suspicious_patterns = cls._identify_patterns(
            category=category,
            rule_id=rule_id,
            evidence=evidence,
            ip_reputation=ip_reputation
        )

        # 4. Generate Investigation Summary
        summary = cls._generate_investigation_summary(
            rule_name=rule_name,
            source_ip=source_ip,
            affected_user=affected_user,
            affected_account=affected_account,
            risk_score=risk_score,
            mitre_data=mitre_data
        )

        # 5. Recommend Defensive SOC Playbook Actions
        recommended_playbook = cls._build_defensive_playbook(
            category=category,
            rule_id=rule_id,
            severity=severity,
            source_ip=source_ip,
            affected_user=affected_user,
            affected_account=affected_account
        )

        # 6. Analyst Decision Support Guideline
        analyst_support = cls._build_analyst_guidance(
            category=category,
            severity=severity,
            risk_score=risk_score
        )

        return {
            "event_summary": summary,
            "root_cause_explanation": explanation,
            "dynamic_risk_score": risk_score,
            "risk_level": "CRITICAL" if risk_score >= 85 else ("HIGH" if risk_score >= 70 else ("MEDIUM" if risk_score >= 45 else "LOW")),
            "mitre_tactic": mitre_data.get("tactic", "Unknown"),
            "mitre_technique_id": mitre_data.get("technique_id", "Unknown"),
            "mitre_technique_name": mitre_data.get("technique_name", "Unknown"),
            "suspicious_patterns": suspicious_patterns,
            "attack_chain_context": mitre_data.get("description", ""),
            "recommended_playbook": recommended_playbook,
            "containment_priority": "P1 (Immediate Action Required)" if risk_score >= 85 else ("P2 (Triage in <30 min)" if risk_score >= 70 else "P3 (Standard Queue)"),
            "analyst_decision_support": analyst_support,
            "risk_factors": risk_factors
        }

    @staticmethod
    def _generate_root_cause_explanation(
        rule_id: str,
        evidence: Dict[str, Any],
        source_ip: str,
        affected_user: Optional[str],
        affected_account: Optional[str]
    ) -> str:
        if rule_id == "RULE-AUTH-001":
            count = evidence.get("attempt_count", "Multiple")
            targets = ", ".join(evidence.get("target_users", [])) or affected_user or "unknown"
            return (
                f"The Sentinel Detection Engine observed {count} consecutive authentication failures originating from IP {source_ip} "
                f"targeting account(s): [{targets}]. This threshold violation suggests automated credential brute forcing or dictionary attack."
            )
        elif rule_id == "RULE-AUTH-002":
            accounts = evidence.get("unique_accounts_targeted", [])
            return (
                f"Distributed credential stuffing detected. IP {source_ip} iterated across {len(accounts)} distinct customer bank usernames "
                f"in rapid succession, matching typical credential-dump replay signatures."
            )
        elif rule_id == "RULE-AUTH-003":
            fails = evidence.get("prior_failed_count", 0)
            return (
                f"High-confidence Account Takeover indicator: User '{affected_user}' authenticated successfully immediately after {fails} failed attempts "
                f"from IP {source_ip}. Threat actors frequently use spray-and-penetrate tactics before session hijacking."
            )
        elif rule_id == "RULE-AUTH-004":
            origin = evidence.get("origin_location", "Origin")
            dest = evidence.get("destination_location", "Destination")
            dist = evidence.get("calculated_distance_km", 0)
            speed = evidence.get("implied_speed_kmh", 0)
            mins = evidence.get("elapsed_minutes", 0)
            return (
                f"Impossible physical velocity detected: User '{affected_user}' authenticated from {origin} and then {dest} ({dist:,.0f} km apart) "
                f"within {mins} minutes, requiring an impossible velocity of {speed:,.0f} km/h (commercial jet cruising speed is ~850 km/h)."
            )
        elif rule_id == "RULE-AUTH-005":
            endpoint = evidence.get("endpoint", "/admin")
            hour = evidence.get("login_hour_local", "off-hours")
            return (
                f"Privileged core banking access detected at {endpoint} at hour {hour}:00 local time from IP {source_ip}. "
                f"Administrative sessions outside authorized operating windows present severe insider threat or compromised privileged credential risk."
            )
        elif rule_id == "RULE-WEB-001":
            token = evidence.get("matched_token", "SQL syntax")
            endpoint = evidence.get("endpoint", "banking portal")
            return (
                f"SQL Injection attack vector detected: Malicious query token '{token}' was submitted to endpoint {endpoint}. "
                f"Payload appears designed to manipulate database query logic or bypass authentication filters."
            )
        elif rule_id == "RULE-WEB-002":
            token = evidence.get("matched_token", "<script>")
            return (
                f"Stored/Reflected XSS script payload '{token}' intercepted in HTTP parameters. "
                f"Adversary may be attempting to steal banking session cookies or CSRF security tokens from customer web sessions."
            )
        elif rule_id == "RULE-WEB-003":
            token = evidence.get("matched_token", "../")
            return (
                f"Path traversal sequence '{token}' submitted in request URL/query parameters. "
                f"Attacker attempted to break out of webroot directory to retrieve sensitive OS configuration or credential store files."
            )
        elif rule_id == "RULE-WEB-004":
            token = evidence.get("matched_token", ";")
            return (
                f"Command injection payload with execution delimiter '{token}' detected. "
                f"Attacker attempted to chain unauthorized operating system shell commands to the web application process."
            )
        elif rule_id == "RULE-FRD-001":
            amt = evidence.get("amount", 0.0)
            curr = evidence.get("currency", "USD")
            return (
                f"High-Value Financial Transaction alert: Outward wire transfer of ${amt:,.2f} {curr} from account {affected_account} "
                f"exceeded institutional risk oversight limits. Immediate multi-eye validation is required."
            )
        elif rule_id == "RULE-FRD-002":
            count = evidence.get("transaction_count", 0)
            amt = evidence.get("cumulative_amount", 0.0)
            sec = evidence.get("time_span_seconds", 0)
            return (
                f"Transaction velocity threshold breached: {count} transactions totaling ${amt:,.2f} were dispatched within {sec:.0f} seconds "
                f"from account {affected_account}. High-frequency bursts frequently indicate automated account draining malware."
            )
        elif rule_id == "RULE-FRD-003":
            count = evidence.get("smurfing_transaction_count", 0)
            total = evidence.get("total_structured_amount", 0.0)
            return (
                f"Suspected AML Smurfing / Structuring scheme: Account {affected_account} generated {count} transfers structured just below the $10,000 "
                f"statutory Currency Transaction Report (CTR) threshold, totaling ${total:,.2f}. This is a direct indicator of money laundering evasion."
            )
        elif rule_id == "RULE-FRD-004":
            amt = evidence.get("amount", 0.0)
            score = evidence.get("normalized_risk_score", 0.0)
            return (
                f"Scikit-learn Isolation Forest flagged transaction of ${amt:,.2f} on account {affected_account} as an anomalous multi-dimensional outlier "
                f"(Anomaly Score: {score}/100) based on abnormal hour, velocity deviation, and amount clustering."
            )
        return "Anomalous event pattern detected requiring analyst assessment."

    @staticmethod
    def _calculate_dynamic_risk_score(
        rule_id: str,
        severity: str,
        category: str,
        evidence: Dict[str, Any],
        ip_reputation: Dict[str, Any]
    ) -> (int, List[str]):
        score = 50
        factors = []

        # Severity Base
        sev_map = {"CRITICAL": 35, "HIGH": 25, "MEDIUM": 15, "LOW": 5}
        base_sev = sev_map.get(severity, 15)
        score += base_sev
        factors.append(f"Base Severity ({severity}): +{base_sev}")

        # Category Weight
        if category == "FINANCIAL_FRAUD":
            score += 15
            factors.append("Financial Impact Vector (Core Banking Ledger): +15")
        elif category == "AUTHENTICATION":
            score += 10
            factors.append("Credential Compromise Vector: +10")

        # Threat Intel Reputation Penalty
        rep_score = ip_reputation.get("reputation_score", 0)
        if rep_score > 60:
            boost = int((rep_score - 50) * 0.4)
            score += boost
            factors.append(f"Threat Intelligence IOC / Malicious IP Penalty ({rep_score}/100): +{boost}")

        # Rule-specific modifiers
        if rule_id in ("RULE-AUTH-003", "RULE-WEB-004", "RULE-FRD-003"):
            score += 10
            factors.append("High-Consequence Rule Profile: +10")

        final_score = max(5, min(99, score))
        return final_score, factors

    @staticmethod
    def _identify_patterns(
        category: str,
        rule_id: str,
        evidence: Dict[str, Any],
        ip_reputation: Dict[str, Any]
    ) -> List[str]:
        patterns = []
        if ip_reputation.get("is_malicious"):
            patterns.append(f"Source IP recognized in Global Threat Intel Feed ({ip_reputation.get('threat_actor', 'Malicious Infrastructure')})")
        
        if category == "AUTHENTICATION":
            patterns.append("Automated high-frequency request cadence indicative of attack tooling (Hydra/SentryMBA)")
            patterns.append("Session state transition from unauthenticated probe to authenticated session")
        elif category == "WEB_APPLICATION":
            patterns.append("Syntax injection targeting backend query logic / input validation bypass")
            patterns.append("Reconnaissance seeking administrative or database metadata disclosure")
        elif category == "FINANCIAL_FRAUD":
            patterns.append("Deliberate sub-threshold structuring pattern circumventing BSA/FinCEN CTR limits")
            patterns.append("High velocity automated disbursement draining account balance to multiple destination hops")
        
        return patterns

    @staticmethod
    def _generate_investigation_summary(
        rule_name: str,
        source_ip: str,
        affected_user: Optional[str],
        affected_account: Optional[str],
        risk_score: int,
        mitre_data: Dict[str, Any]
    ) -> str:
        return (
            f"MR.X BANK SOC SENTINEL AI Incident Advisory: Rule '{rule_name}' triggered with dynamic risk score {risk_score}/100. "
            f"Adversary telemetry centers around Source IP {source_ip}, targeting Account/User '{affected_user or affected_account or 'Perimeter'}'. "
            f"Activity maps to MITRE ATT&CK {mitre_data.get('technique_id')} ({mitre_data.get('technique_name')}) under Tactic '{mitre_data.get('tactic')}'. "
            f"Analyst action recommended."
        )

    @staticmethod
    def _build_defensive_playbook(
        category: str,
        rule_id: str,
        severity: str,
        source_ip: str,
        affected_user: Optional[str],
        affected_account: Optional[str]
    ) -> List[str]:
        steps = []
        # General Containment Step
        steps.append(f"[Step 1 - Perimeter Defense] Enforce immediate IP block for {source_ip} on Perimeter Firewalls (Palo Alto / Fortinet edge).")

        if category == "AUTHENTICATION":
            if affected_user and affected_user != "MULTIPLE_USERS":
                steps.append(f"[Step 2 - Identity Containment] Invalidate all active JWT/OAuth web sessions for user '{affected_user}'.")
                steps.append(f"[Step 3 - Credential Hygiene] Force mandatory password reset with Out-Of-Band (OOB) SMS/Hardware token re-enrollment.")
            else:
                steps.append("[Step 2 - Rate Limiting] Engage Edge WAF reCAPTCHA challenge on authentication endpoints.")
            steps.append("[Step 3 - Audit Review] Query SIEM for any other successful authentications from this ASN within 48 hours.")

        elif category == "WEB_APPLICATION":
            steps.append("[Step 2 - WAF Hardening] Enable strict Core Rule Set (CRS) blocking rule for the affected URI on Web Application Firewall.")
            steps.append("[Step 3 - AppSec Escalation] Open P1 AppSec Jira ticket to review parameterized query sanitization for this endpoint.")
            steps.append("[Step 4 - Log Inspection] Check web server access logs for HTTP 200 responses to verify if injection succeeded.")

        elif category == "FINANCIAL_FRAUD":
            if affected_account:
                steps.append(f"[Step 2 - Ledger Safeguard] Place temporary administrative hold on outward wire transfers for account '{affected_account}'.")
                steps.append("[Step 3 - Recipient Triage] Freeze corresponding credit in destination account and contact receiving financial institution via SWIFT RMA message.")
            steps.append("[Step 4 - AML Compliance Alert] Notify Internal Bank AML Officer and prepare FinCEN SAR (Suspicious Activity Report) draft.")
            steps.append("[Step 5 - Customer Verification] Initiate out-of-band biometric/voice callback with the verified account holder.")

        steps.append("[Step 6 - Escalation] Document all actions in Sentinel Incident Case Notes and elevate to L2 Senior Analyst if true positive.")
        return steps

    @staticmethod
    def _build_analyst_guidance(category: str, severity: str, risk_score: int) -> str:
        return (
            "⚠️ DECISION SUPPORT DIRECTIVE FOR L1/L2 ANALYST:\n"
            "This AI security evaluation provides contextual correlation and evidence analysis. "
            "It does NOT automatically confirm a breach. Review raw payloads, verify whether the HTTP response code indicates success "
            "or failure (e.g. 403 Forbidden vs 200 OK), verify user travel tickets for impossible travel, and confirm with Fraud Operations "
            "prior to executing permanent ledger freezes."
        )

