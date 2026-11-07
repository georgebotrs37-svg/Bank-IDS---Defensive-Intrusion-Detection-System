import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'bank_sentinel.db'}")

# Detection Engine Thresholds
THRESHOLDS = {
    # Auth attacks
    "BRUTE_FORCE_FAILS": 5,           # Failed attempts
    "BRUTE_FORCE_WINDOW_SEC": 300,    # 5 minutes
    "CREDENTIAL_STUFFING_USERS": 3,   # Different usernames tried from 1 IP
    "CREDENTIAL_STUFFING_WINDOW_SEC": 300,
    "IMPOSSIBLE_TRAVEL_SPEED_KMH": 850.0, # Faster than commercial jet
    "SUSPICIOUS_ADMIN_HOURS": (22, 5),   # 10 PM to 5 AM local time
    
    # Financial Fraud & AML
    "LARGE_TRANSACTION_LIMIT": 50000.00,  # $50,000 threshold
    "VELOCITY_MAX_TX": 4,                 # max tx count in window
    "VELOCITY_WINDOW_SEC": 180,           # 3 minutes
    "STRUCTURING_LOWER": 9000.00,         # Smurfing range: $9,000 - $9,999
    "STRUCTURING_UPPER": 9999.99,
    "STRUCTURING_WINDOW_HOURS": 24,
    "STRUCTURING_MIN_COUNT": 3,
    "ML_ANOMALY_CONTAMINATION": 0.05      # 5% outlier expectation
}

# Protected / High-Risk Banking Endpoints
ADMIN_ENDPOINTS = [
    "/admin",
    "/admin/login",
    "/api/v1/admin",
    "/ebanking-core",
    "/swift-gateway",
    "/core-ledger",
    "/wire-settlement",
    "/compliance-audit",
    "/vault-secrets"
]

# Known internal trusted IP blocks (for baseline verification)
INTERNAL_SUBNETS = [
    "10.0.",
    "172.16.",
    "192.168."
]

# SOC Analyst Defaults
DEFAULT_ANALYSTS = [
    {"name": "Alex Rivera", "role": "L1 SOC Analyst", "email": "a.rivera@mrxbank.internal"},
    {"name": "Elena Rostova", "role": "L2 Senior Incident Responder", "email": "e.rostova@mrxbank.internal"},
    {"name": "Marcus Chen", "role": "SOC Lead & Threat Hunter", "email": "m.chen@mrxbank.internal"}
]

