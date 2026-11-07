import math
from datetime import datetime, timedelta
from typing import List, Dict, Any
from backend.rules.base import BaseDetectionRule, AlertData
from backend.config import THRESHOLDS, ADMIN_ENDPOINTS, INTERNAL_SUBNETS


def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great circle distance between two points in kilometers."""
    R = 6371.0  # Earth radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


class BruteForceRule(BaseDetectionRule):
    """
    Detects Brute Force Attacks:
    >= 5 failed logins within 5 minutes against the same user or originating from the same IP.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-AUTH-001",
            name="Brute Force Password Guessing Detected",
            category="AUTHENTICATION",
            default_severity="HIGH"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        all_logs = history_logs + new_logs
        window_seconds = THRESHOLDS["BRUTE_FORCE_WINDOW_SEC"]
        threshold = THRESHOLDS["BRUTE_FORCE_FAILS"]

        # Group failed logins by IP and User
        ip_fails: Dict[str, List[Any]] = {}
        user_fails: Dict[str, List[Any]] = {}

        for log in all_logs:
            if getattr(log, "log_type", "") == "auth" and getattr(log, "action", "") == "login_failed":
                ip = getattr(log, "source_ip", None)
                user = getattr(log, "username", None)
                if ip:
                    ip_fails.setdefault(ip, []).append(log)
                if user:
                    user_fails.setdefault(user, []).append(log)

        # Check IP-level brute force
        for ip, logs in ip_fails.items():
            logs_sorted = sorted(logs, key=lambda x: x.timestamp)
            for i in range(len(logs_sorted)):
                window_start = logs_sorted[i].timestamp
                window_end = window_start + timedelta(seconds=window_seconds)
                subset = [l for l in logs_sorted[i:] if l.timestamp <= window_end]
                
                # Check if subset contains at least one of the new_logs to avoid duplicate legacy firing
                has_new = any(getattr(l, "id", None) in [getattr(nl, "id", None) for nl in new_logs] for l in subset)
                if len(subset) >= threshold and has_new:
                    sample_users = list({getattr(l, "username", "unknown") for l in subset})
                    alerts.append(AlertData(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=self.default_severity,
                        source_ip=ip,
                        affected_user=sample_users[0] if len(sample_users) == 1 else "MULTIPLE_USERS",
                        description=f"Source IP {ip} triggered {len(subset)} consecutive failed login attempts within {window_seconds//60} minutes.",
                        evidence={
                            "attempt_count": len(subset),
                            "target_users": sample_users[:5],
                            "time_window_sec": window_seconds,
                            "sample_timestamps": [l.timestamp.isoformat() for l in subset[:5]]
                        },
                        timestamp=subset[-1].timestamp,
                        ai_risk_score=78
                    ))
                    break  # Avoid firing multiple alerts for the same window

        return alerts


class CredentialStuffingRule(BaseDetectionRule):
    """
    Detects Credential Stuffing:
    Single source IP attempting failed logins targeting >= 3 different usernames in <= 5 minutes.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-AUTH-002",
            name="Distributed Credential Stuffing Wave",
            category="AUTHENTICATION",
            default_severity="CRITICAL"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        all_logs = history_logs + new_logs
        window_seconds = THRESHOLDS["CREDENTIAL_STUFFING_WINDOW_SEC"]
        user_threshold = THRESHOLDS["CREDENTIAL_STUFFING_USERS"]

        ip_map: Dict[str, List[Any]] = {}
        for log in all_logs:
            if getattr(log, "log_type", "") == "auth" and getattr(log, "action", "") == "login_failed":
                ip = getattr(log, "source_ip", None)
                if ip:
                    ip_map.setdefault(ip, []).append(log)

        for ip, logs in ip_map.items():
            logs_sorted = sorted(logs, key=lambda x: x.timestamp)
            for i in range(len(logs_sorted)):
                window_start = logs_sorted[i].timestamp
                window_end = window_start + timedelta(seconds=window_seconds)
                subset = [l for l in logs_sorted[i:] if l.timestamp <= window_end]
                unique_users = {getattr(l, "username", "") for l in subset if getattr(l, "username", "")}
                
                has_new = any(getattr(l, "id", None) in [getattr(nl, "id", None) for nl in new_logs] for l in subset)
                if len(unique_users) >= user_threshold and has_new:
                    alerts.append(AlertData(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=self.default_severity,
                        source_ip=ip,
                        affected_user="MULTIPLE_ACCOUNTS",
                        description=f"Source IP {ip} attempted automated credential stuffing across {len(unique_users)} distinct customer accounts in {window_seconds//60} minutes.",
                        evidence={
                            "unique_accounts_targeted": list(unique_users)[:8],
                            "total_failed_requests": len(subset),
                            "attack_duration_seconds": (subset[-1].timestamp - subset[0].timestamp).total_seconds()
                        },
                        timestamp=subset[-1].timestamp,
                        ai_risk_score=92
                    ))
                    break

        return alerts


class AccountTakeoverRule(BaseDetectionRule):
    """
    Detects Account Takeover (ATO):
    A successful login immediately after >= 3 failed attempts within 15 minutes,
    especially when followed by high-risk actions (password reset or wire transfer).
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-AUTH-003",
            name="Suspected Account Takeover (ATO) in Progress",
            category="AUTHENTICATION",
            default_severity="CRITICAL"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        all_logs = sorted(history_logs + new_logs, key=lambda x: x.timestamp)

        # Check for successful logins in new_logs
        for new_log in new_logs:
            if getattr(new_log, "log_type", "") == "auth" and getattr(new_log, "action", "") == "login_success":
                user = getattr(new_log, "username", None)
                ts = getattr(new_log, "timestamp", datetime.utcnow())
                if not user:
                    continue

                # Look back 15 minutes in all_logs for failed attempts on this user
                lookback = ts - timedelta(minutes=15)
                prior_fails = [
                    l for l in all_logs
                    if getattr(l, "username", "") == user
                    and getattr(l, "action", "") == "login_failed"
                    and lookback <= l.timestamp < ts
                ]

                if len(prior_fails) >= 3:
                    fail_ips = list({getattr(l, "source_ip", "") for l in prior_fails})
                    success_ip = getattr(new_log, "source_ip", "unknown")
                    alerts.append(AlertData(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=self.default_severity,
                        source_ip=success_ip,
                        affected_user=user,
                        description=f"Account '{user}' successfully authenticated immediately after {len(prior_fails)} failed login attempts from IP {success_ip}.",
                        evidence={
                            "user": user,
                            "prior_failed_count": len(prior_fails),
                            "failed_source_ips": fail_ips,
                            "successful_source_ip": success_ip,
                            "successful_login_time": ts.isoformat()
                        },
                        timestamp=ts,
                        ai_risk_score=95
                    ))

        return alerts


class ImpossibleTravelRule(BaseDetectionRule):
    """
    Detects Impossible Travel:
    Sequential logins for the same account from distinct geographic locations
    exceeding commercial flight speeds (>850 km/h).
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-AUTH-004",
            name="Impossible Travel Anomaly Detected",
            category="AUTHENTICATION",
            default_severity="HIGH"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        speed_limit = THRESHOLDS["IMPOSSIBLE_TRAVEL_SPEED_KMH"]

        all_logs = sorted(history_logs + new_logs, key=lambda x: x.timestamp)

        for new_log in new_logs:
            if getattr(new_log, "log_type", "") == "auth" and getattr(new_log, "action", "") in ("login_success", "auth_token"):
                user = getattr(new_log, "username", None)
                lat2 = getattr(new_log, "latitude", None)
                lon2 = getattr(new_log, "longitude", None)
                ts2 = getattr(new_log, "timestamp", datetime.utcnow())

                if not user or lat2 is None or lon2 is None:
                    continue

                # Find the most recent previous login for this user in history_logs or prior in batch
                prev_logs = [
                    l for l in all_logs
                    if getattr(l, "username", "") == user
                    and getattr(l, "action", "") in ("login_success", "auth_token")
                    and getattr(l, "latitude", None) is not None
                    and l.timestamp < ts2
                    and (getattr(l, "id", None) != getattr(new_log, "id", None) or getattr(l, "source_ip", "") != getattr(new_log, "source_ip", ""))
                ]

                if not prev_logs:
                    continue

                # Check against distinct recent locations in all_logs
                for prev_log in sorted(prev_logs, key=lambda x: x.timestamp, reverse=True)[:5]:
                    lat1 = getattr(prev_log, "latitude", None)
                    lon1 = getattr(prev_log, "longitude", None)
                    ts1 = getattr(prev_log, "timestamp")

                    time_diff_hours = (ts2 - ts1).total_seconds() / 3600.0
                    if time_diff_hours <= 0.001:  # Near instantaneous
                        time_diff_hours = 0.001

                    distance_km = haversine_distance_km(lat1, lon1, lat2, lon2)
                    effective_speed = distance_km / time_diff_hours

                    # If distance > 100km and effective speed > 850 km/h
                    if distance_km > 100 and effective_speed > speed_limit:
                        alerts.append(AlertData(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            category=self.category,
                            severity=self.default_severity,
                            source_ip=getattr(new_log, "source_ip", "unknown"),
                            affected_user=user,
                            description=f"User '{user}' logged in from {getattr(prev_log, 'location_city', 'City1')} and {getattr(new_log, 'location_city', 'City2')} ({distance_km:.0f} km apart) in only {time_diff_hours*60:.1f} minutes ({effective_speed:.0f} km/h).",
                            evidence={
                                "origin_location": f"{getattr(prev_log, 'location_city', 'Unknown')}, {getattr(prev_log, 'location_country', 'Unknown')}",
                                "origin_ip": getattr(prev_log, "source_ip", "unknown"),
                                "origin_time": ts1.isoformat(),
                                "destination_location": f"{getattr(new_log, 'location_city', 'Unknown')}, {getattr(new_log, 'location_country', 'Unknown')}",
                                "destination_ip": getattr(new_log, "source_ip", "unknown"),
                                "destination_time": ts2.isoformat(),
                                "calculated_distance_km": round(distance_km, 2),
                                "elapsed_minutes": round(time_diff_hours * 60, 2),
                                "implied_speed_kmh": round(effective_speed, 2)
                            },
                            timestamp=ts2,
                            ai_risk_score=88
                        ))
                        break

        return alerts


class SuspiciousAdminLoginRule(BaseDetectionRule):
    """
    Detects Suspicious Admin Logins:
    Authentication to privileged banking endpoints (/admin, /ebanking-core, etc.)
    outside normal working hours (10:00 PM - 5:00 AM) or originating from non-allowlisted IPs.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-AUTH-005",
            name="Suspicious Off-Hours Privileged Admin Access",
            category="AUTHENTICATION",
            default_severity="HIGH"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        off_hours_start, off_hours_end = THRESHOLDS["SUSPICIOUS_ADMIN_HOURS"]

        for log in new_logs:
            endpoint = (getattr(log, "endpoint", "") or "").lower()
            is_admin_endpoint = any(admin_path in endpoint for admin_path in ADMIN_ENDPOINTS)
            user = (getattr(log, "username", "") or "").lower()
            is_admin_user = "admin" in user or "root" in user or "secops" in user or is_admin_endpoint

            if is_admin_user or is_admin_endpoint:
                ts = getattr(log, "timestamp", datetime.utcnow())
                hour = ts.hour
                is_off_hours = (hour >= off_hours_start or hour < off_hours_end)
                ip = getattr(log, "source_ip", "")
                is_internal = any(ip.startswith(prefix) for prefix in INTERNAL_SUBNETS)

                # Flag if off-hours OR external IP accessing core admin
                if is_off_hours or not is_internal:
                    reason = "Off-hours login" if is_off_hours else "External untrusted network access"
                    if is_off_hours and not is_internal:
                        reason = "Off-hours access from external un-trusted IP"

                    severity = "CRITICAL" if (is_off_hours and not is_internal) else "HIGH"
                    risk_score = 94 if severity == "CRITICAL" else 75

                    alerts.append(AlertData(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=severity,
                        source_ip=ip,
                        affected_user=getattr(log, "username", "admin"),
                        description=f"Privileged core banking access to '{endpoint or '/admin'}' by '{getattr(log, 'username', 'admin')}' flagged: {reason}.",
                        evidence={
                            "endpoint": endpoint,
                            "user": getattr(log, "username", "admin"),
                            "source_ip": ip,
                            "timestamp": ts.isoformat(),
                            "login_hour_local": hour,
                            "is_internal_network": is_internal,
                            "is_off_hours": is_off_hours
                        },
                        timestamp=ts,
                        ai_risk_score=risk_score
                    ))

        return alerts
