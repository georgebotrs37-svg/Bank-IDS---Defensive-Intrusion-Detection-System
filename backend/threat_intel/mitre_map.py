"""
MITRE ATT&CK Framework Mapping for Banking & SOC Sentinel Operations
Maps detection rule types, tactics, technique IDs, descriptions, and defensive mitigations.
"""

MITRE_RULES_MAPPING = {
    "RULE-AUTH-001": {
        "name": "Brute Force Password Guessing",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "subtechnique": "T1110.001",
        "description": "Adversaries may use brute force techniques to attempt authentication against a single bank customer or admin account using automated dictionaries.",
        "defensive_mitigation": "M1036 (Account Use Policies), M1032 (Multi-factor Authentication), Account Lockout Policy."
    },
    "RULE-AUTH-002": {
        "name": "Credential Stuffing Attack",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique_id": "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "subtechnique": "T1110.004",
        "description": "Adversaries utilize large lists of previously compromised credentials across multiple banking accounts to gain unauthorized access.",
        "defensive_mitigation": "M1032 (MFA), CAPTCHA enforcement on banking portal, Rate limiting per ASN/IP."
    },
    "RULE-AUTH-003": {
        "name": "Account Takeover (ATO) Pattern",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "technique_id": "T1078.003",
        "technique_name": "Valid Accounts: Local/Cloud Accounts",
        "subtechnique": "T1078.003",
        "description": "Adversaries hijack a legitimate account following failed attempts or anomalous device/location shift, then immediately modify profiles or initiate fund transfers.",
        "defensive_mitigation": "M1030 (Network Segmentation), Step-up authentication for high-risk actions, Out-of-band transaction signing."
    },
    "RULE-AUTH-004": {
        "name": "Impossible Travel Anomaly",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts: Geographically Disjointed Access",
        "subtechnique": "T1078",
        "description": "Successive authentications from two geographically distinct locations separated by a distance physically impossible to travel within the elapsed time window.",
        "defensive_mitigation": "Geofencing, Conditional Access Policies, Immediate session invalidation and force re-authentication."
    },
    "RULE-AUTH-005": {
        "name": "Suspicious Off-Hours Privileged Admin Login",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique_id": "T1078.002",
        "technique_name": "Valid Accounts: Domain/Privileged Accounts",
        "subtechnique": "T1078.002",
        "description": "Privileged banking portal or core ledger administrative access occurred outside authorized working shifts from a non-allowlisted network.",
        "defensive_mitigation": "PAM (Privileged Access Management), Dual-custody authorization for core banking consoles, Hardware security keys."
    },
    "RULE-WEB-001": {
        "name": "SQL Injection (SQLi) Attempt",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: SQLi",
        "subtechnique": "T1190",
        "description": "Malicious SQL syntax injected into web forms, API parameters, or headers aiming to extract ledger data or bypass authentication controls.",
        "defensive_mitigation": "M1050 (Exploit Protection), Parameterized queries, Web Application Firewall (WAF) SQLi blocking rules."
    },
    "RULE-WEB-002": {
        "name": "Cross-Site Scripting (XSS) Injection",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "subtechnique": "T1059.007",
        "description": "Client-side script tags injected into online banking user inputs targeting customer browser sessions and CSRF token extraction.",
        "defensive_mitigation": "M1038 (Execution Prevention), Strict Content Security Policy (CSP), Contextual HTML escaping."
    },
    "RULE-WEB-003": {
        "name": "Path Traversal / Local File Inclusion (LFI)",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: Path Traversal",
        "subtechnique": "T1190",
        "description": "Directory navigation patterns (../, win.ini, /etc/passwd) sent to banking web endpoints to disclose confidential configuration files.",
        "defensive_mitigation": "Strict input whitelisting, Chroot jail/container isolation, disable direct file serving by query params."
    },
    "RULE-WEB-004": {
        "name": "Command Injection Attempt",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique_id": "T1059.004",
        "technique_name": "Command and Scripting Interpreter: Unix Shell / PowerShell",
        "subtechnique": "T1059.004",
        "description": "Shell execution meta-characters (| ; & ` $) observed in web parameters attempting to execute arbitrary system commands on banking web tier.",
        "defensive_mitigation": "M1042 (Disable or Restrict Tools), Safe process execution APIs without shell interpolation, AppArmor/SELinux."
    },
    "RULE-FRD-001": {
        "name": "High-Value Transaction Threshold Exceeded",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service / Financial Theft Exfiltration",
        "subtechnique": "T1499",
        "description": "Single wire or ledger transfer exceeding institutional risk policy ($50,000+) requiring immediate fraud verification.",
        "defensive_mitigation": "Hold transfer for manual L2/Fraud Ops phone confirmation, SWIFT sanction list screening."
    },
    "RULE-FRD-002": {
        "name": "High Velocity Transaction Spike",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique_id": "T1565.001",
        "technique_name": "Data Manipulation: Stored Data Manipulation",
        "subtechnique": "T1565.001",
        "description": "Rapid succession of debit or wire operations within seconds/minutes indicative of automated account drain bots.",
        "defensive_mitigation": "Automated ledger cooling period, velocity circuit breaker, biometric step-up challenge."
    },
    "RULE-FRD-003": {
        "name": "Transaction Structuring (Smurfing Pattern)",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "technique_id": "T1562",
        "technique_name": "Impair Defenses: Evade Mandatory Financial Reporting",
        "subtechnique": "T1562",
        "description": "Multiple sub-threshold deposits or transfers structured intentionally between $9,000 and $9,999 to circumvent anti-money laundering (AML) CTR requirements.",
        "defensive_mitigation": "FinCEN Form 111 SAR (Suspicious Activity Report) filing, compliance freeze on recipient accounts."
    },
    "RULE-FRD-004": {
        "name": "Machine Learning Transaction Anomaly (Isolation Forest)",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "technique_id": "T1098",
        "technique_name": "Account Manipulation: Unsupervised Anomaly Outlier",
        "subtechnique": "T1098",
        "description": "Multi-dimensional anomaly identified by Isolation Forest model examining transaction size, velocity, time-of-day, and deviation from historical cluster.",
        "defensive_mitigation": "Analyst manual review, temporary freeze on outward international wires, customer contact."
    }
}


def get_mitre_mapping(rule_id: str) -> dict:
    return MITRE_RULES_MAPPING.get(rule_id, {
        "name": "Unknown Security Event",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique_id": "T1190",
        "technique_name": "General Exploit",
        "subtechnique": "T1190",
        "description": "Unclassified security event requiring manual analyst triage.",
        "defensive_mitigation": "Follow standard L1 SOC Incident Response triage SOP."
    })

