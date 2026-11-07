import re
from typing import List, Any
from backend.rules.base import BaseDetectionRule, AlertData

# Compiled regular expressions for Web Application Attack Detection
SQLI_PATTERNS = [
    re.compile(r"(\bUNION\b.*\bSELECT\b)", re.IGNORECASE),
    re.compile(r"(\bor\b\s+['\"0-9a-z]+\s*=\s*['\"0-9a-z]+)", re.IGNORECASE),
    re.compile(r"(--|#|/\*.*?\*/)", re.IGNORECASE),
    re.compile(r"(\bSLEEP\s*\(\s*\d+\s*\))", re.IGNORECASE),
    re.compile(r"(\bBENCHMARK\s*\(\s*\d+\s*,)", re.IGNORECASE),
    re.compile(r"(\bWAITFOR\s+DELAY\b)", re.IGNORECASE),
    re.compile(r"(\bxp_cmdshell\b)", re.IGNORECASE),
    re.compile(r"(\bINFORMATION_SCHEMA\b)", re.IGNORECASE),
    re.compile(r"(\bDROP\s+TABLE\b|\bINSERT\s+INTO\b.*\bVALUES\b)", re.IGNORECASE),
    re.compile(r"(;\s*EXEC\s*\(|;\s*EXECUTE\s*\()", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"(<script\b[^>]*>.*?</script>)", re.IGNORECASE),
    re.compile(r"(<script\b[^>]*>)", re.IGNORECASE),
    re.compile(r"(javascript\s*:\s*[^\s]+)", re.IGNORECASE),
    re.compile(r"(onerror\s*=\s*['\"0-9a-z\(\)]+)", re.IGNORECASE),
    re.compile(r"(onload\s*=\s*['\"0-9a-z\(\)]+)", re.IGNORECASE),
    re.compile(r"(<svg\b[^>]*onload=)", re.IGNORECASE),
    re.compile(r"(<img\b[^>]*onerror=)", re.IGNORECASE),
    re.compile(r"(\bdocument\.cookie\b|\bwindow\.location\b)", re.IGNORECASE),
    re.compile(r"(\beval\s*\(.*\))", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c)", re.IGNORECASE),
    re.compile(r"(/etc/passwd|/etc/shadow|/etc/hosts)", re.IGNORECASE),
    re.compile(r"(c:\\windows\\system32|win\.ini|boot\.ini)", re.IGNORECASE),
    re.compile(r"(%252e%252e%252f)", re.IGNORECASE),
]

COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(;\s*(cat|id|whoami|uname|ls|netstat|nc|curl|wget)\b)", re.IGNORECASE),
    re.compile(r"(\|\s*(cat|id|whoami|uname|ls|netstat|nc|curl|wget)\b)", re.IGNORECASE),
    re.compile(r"(&&\s*(cat|id|whoami|uname|ls|netstat|nc|curl|wget|powershell|cmd)\b)", re.IGNORECASE),
    re.compile(r"(`.*(id|whoami|cat|ls|uname).*`)", re.IGNORECASE),
    re.compile(r"(\$\(.*\b(id|whoami|cat|uname)\b.*\))", re.IGNORECASE),
    re.compile(r"(\bpowershell(?:\.exe)?\s+-[eE](?:nc(?:odedcommand)?)?)", re.IGNORECASE),
    re.compile(r"(\bcmd(?:\.exe)?\s+/c\b)", re.IGNORECASE),
]


class SQLInjectionRule(BaseDetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE-WEB-001",
            name="SQL Injection (SQLi) Attempt Detected",
            category="WEB_APPLICATION",
            default_severity="CRITICAL"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        for log in new_logs:
            if getattr(log, "log_type", "") != "web":
                continue

            content = f"{getattr(log, 'endpoint', '') or ''} {getattr(log, 'payload', '') or ''}"
            for pattern in SQLI_PATTERNS:
                match = pattern.search(content)
                if match:
                    matched_token = match.group(0)
                    alerts.append(AlertData(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=self.default_severity,
                        source_ip=getattr(log, "source_ip", "unknown"),
                        destination_ip=getattr(log, "destination_ip", None),
                        affected_user=getattr(log, "username", None),
                        description=f"SQL injection syntax '{matched_token}' detected in HTTP request to {getattr(log, 'endpoint', '')}.",
                        evidence={
                            "matched_pattern": pattern.pattern,
                            "matched_token": matched_token,
                            "endpoint": getattr(log, "endpoint", ""),
                            "http_method": getattr(log, "http_method", ""),
                            "payload": getattr(log, "payload", ""),
                            "user_agent": getattr(log, "user_agent", "")
                        },
                        timestamp=getattr(log, "timestamp"),
                        ai_risk_score=92
                    ))
                    break  # Avoid duplicate alerts for same log
        return alerts


class XSSRule(BaseDetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE-WEB-002",
            name="Cross-Site Scripting (XSS) Injection Detected",
            category="WEB_APPLICATION",
            default_severity="HIGH"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        for log in new_logs:
            if getattr(log, "log_type", "") != "web":
                continue

            content = f"{getattr(log, 'endpoint', '') or ''} {getattr(log, 'payload', '') or ''}"
            for pattern in XSS_PATTERNS:
                match = pattern.search(content)
                if match:
                    matched_token = match.group(0)
                    alerts.append(AlertData(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=self.default_severity,
                        source_ip=getattr(log, "source_ip", "unknown"),
                        affected_user=getattr(log, "username", None),
                        description=f"Client-side script payload '{matched_token[:50]}' detected targeting online banking endpoint {getattr(log, 'endpoint', '')}.",
                        evidence={
                            "matched_token": matched_token,
                            "endpoint": getattr(log, "endpoint", ""),
                            "http_method": getattr(log, "http_method", ""),
                            "payload": getattr(log, "payload", ""),
                            "user_agent": getattr(log, "user_agent", "")
                        },
                        timestamp=getattr(log, "timestamp"),
                        ai_risk_score=82
                    ))
                    break
        return alerts


class PathTraversalRule(BaseDetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE-WEB-003",
            name="Path Traversal / Local File Inclusion (LFI)",
            category="WEB_APPLICATION",
            default_severity="HIGH"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        for log in new_logs:
            if getattr(log, "log_type", "") != "web":
                continue

            content = f"{getattr(log, 'endpoint', '') or ''} {getattr(log, 'payload', '') or ''}"
            for pattern in PATH_TRAVERSAL_PATTERNS:
                match = pattern.search(content)
                if match:
                    matched_token = match.group(0)
                    alerts.append(AlertData(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=self.default_severity,
                        source_ip=getattr(log, "source_ip", "unknown"),
                        affected_user=getattr(log, "username", None),
                        description=f"Directory traversal sequence '{matched_token}' detected attempting unauthorized access to system files.",
                        evidence={
                            "matched_token": matched_token,
                            "endpoint": getattr(log, "endpoint", ""),
                            "payload": getattr(log, "payload", ""),
                            "http_method": getattr(log, "http_method", "")
                        },
                        timestamp=getattr(log, "timestamp"),
                        ai_risk_score=85
                    ))
                    break
        return alerts


class CommandInjectionRule(BaseDetectionRule):
    def __init__(self):
        super().__init__(
            rule_id="RULE-WEB-004",
            name="Remote Command Injection Attempt",
            category="WEB_APPLICATION",
            default_severity="CRITICAL"
        )

    def evaluate(self, new_logs: List[Any], history_logs: List[Any]) -> List[AlertData]:
        alerts = []
        for log in new_logs:
            if getattr(log, "log_type", "") != "web":
                continue

            content = f"{getattr(log, 'endpoint', '') or ''} {getattr(log, 'payload', '') or ''}"
            for pattern in COMMAND_INJECTION_PATTERNS:
                match = pattern.search(content)
                if match:
                    matched_token = match.group(0)
                    alerts.append(AlertData(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        category=self.category,
                        severity=self.default_severity,
                        source_ip=getattr(log, "source_ip", "unknown"),
                        affected_user=getattr(log, "username", None),
                        description=f"Operating system shell command separator or execution token '{matched_token}' detected in banking server request.",
                        evidence={
                            "matched_token": matched_token,
                            "endpoint": getattr(log, "endpoint", ""),
                            "payload": getattr(log, "payload", ""),
                            "user_agent": getattr(log, "user_agent", "")
                        },
                        timestamp=getattr(log, "timestamp"),
                        ai_risk_score=97
                    ))
                    break
        return alerts

