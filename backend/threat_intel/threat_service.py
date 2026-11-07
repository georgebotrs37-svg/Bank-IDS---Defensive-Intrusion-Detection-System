import ipaddress
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.models import ThreatIOC, SeverityEnum

# Curated High-Fidelity Banking Threat Intelligence Seed Dataset
DEFAULT_IOCS = [
    {
        "ioc_type": "IP",
        "value": "185.220.101.5",
        "threat_actor": "Tor Project Relay / Exit Node",
        "threat_type": "Tor Exit Node",
        "confidence": 95,
        "severity": "HIGH",
        "description": "Known Tor Exit Node frequently utilized for anonymized banking portal credential stuffing.",
        "tags": "tor,anonymizer,credential_stuffing"
    },
    {
        "ioc_type": "IP",
        "value": "194.26.29.112",
        "threat_actor": "FIN7 / Carbanak Financial Syndicate",
        "threat_type": "Banking Trojan C2",
        "confidence": 98,
        "severity": "CRITICAL",
        "description": "Active Command & Control node for Carbanak / Cobalt Strike targeting SWIFT banking infrastructure.",
        "tags": "c2,fin7,carbanak,swift_target"
    },
    {
        "ioc_type": "IP",
        "value": "45.154.255.88",
        "threat_actor": "Lazarus Group (HIDDEN COBRA)",
        "threat_type": "State-Sponsored Financial Cybercrime",
        "confidence": 99,
        "severity": "CRITICAL",
        "description": "Identified staging infrastructure used in fraudulent interbank wire transfer injection.",
        "tags": "apt38,lazarus,wire_fraud"
    },
    {
        "ioc_type": "IP",
        "value": "91.240.118.232",
        "threat_actor": "RedLine Stealer Infrastructure",
        "threat_type": "Infostealer Gateway",
        "confidence": 90,
        "severity": "HIGH",
        "description": "Stolen e-banking session cookie exfiltration endpoint.",
        "tags": "stealer,infostealer,cookie_hijack"
    },
    {
        "ioc_type": "IP",
        "value": "103.145.13.44",
        "threat_actor": "Mirai / SQLi Botnet Tier",
        "threat_type": "Automated Web Exploit Bot",
        "confidence": 85,
        "severity": "MEDIUM",
        "description": "Continuous scanner probing banking web portals for SQL injection and path traversal vulnerabilities.",
        "tags": "scanner,sqli_bot,recon"
    },
    {
        "ioc_type": "IP",
        "value": "178.62.204.10",
        "threat_actor": "Commercial VPN / Proxy Service",
        "threat_type": "Commercial Proxy",
        "confidence": 75,
        "severity": "MEDIUM",
        "description": "Commercial VPN server used for geofence evasion and impossible travel testing.",
        "tags": "vpn,proxy,anonymizer"
    }
]

# Simulated GeoIP Location Database for Realistic Travel & Geo Attribution
SIMULATED_GEOIP_DB = {
    "185.220.101.5": {"city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lon": 8.6821, "isp": "Tor Exit Network"},
    "194.26.29.112": {"city": "Moscow", "country": "Russia", "lat": 55.7558, "lon": 37.6173, "isp": "Bulletproof Hosting Services"},
    "45.154.255.88": {"city": "Vladivostok", "country": "Russia", "lat": 43.1155, "lon": 131.8855, "isp": "Offshore Transit ASN"},
    "91.240.118.232": {"city": "Kyiv", "country": "Ukraine", "lat": 50.4501, "lon": 30.5234, "isp": "Autonomous Server Provider"},
    "103.145.13.44": {"city": "Ho Chi Minh City", "country": "Vietnam", "lat": 10.8231, "lon": 106.6297, "isp": "Datacenter Hosting Corp"},
    "178.62.204.10": {"city": "Amsterdam", "country": "Netherlands", "lat": 52.3676, "lon": 4.9041, "isp": "Digital Ocean VPN"},
    "192.168.1.100": {"city": "New York", "country": "United States", "lat": 40.7128, "lon": -74.0060, "isp": "MR.X Bank HQ Internal LAN"},
    "10.0.4.15": {"city": "New York", "country": "United States", "lat": 40.7128, "lon": -74.0060, "isp": "Core Banking Tier DMZ"},
    "64.233.160.1": {"city": "Mountain View", "country": "United States", "lat": 37.3861, "lon": -122.0839, "isp": "Google Cloud Transit"},
}

HIGH_RISK_COUNTRIES = {"Russia", "North Korea", "Iran", "Belarus", "Myanmar"}


class ThreatIntelligenceService:
    def __init__(self, db: Session):
        self.db = db

    def seed_initial_iocs(self):
        """Pre-populate the ThreatIOC database with initial banking threat actors if empty."""
        count = self.db.query(ThreatIOC).count()
        if count == 0:
            for item in DEFAULT_IOCS:
                ioc = ThreatIOC(
                    ioc_type=item["ioc_type"],
                    value=item["value"],
                    threat_actor=item["threat_actor"],
                    threat_type=item["threat_type"],
                    confidence=item["confidence"],
                    severity=item["severity"],
                    description=item["description"],
                    tags=item["tags"],
                    last_seen=datetime.utcnow()
                )
                self.db.add(ioc)
            self.db.commit()

    def get_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Calculates multi-vector reputation score (0-100) for a given IP."""
        # 1. Check direct database IOC hit
        ioc_hit = self.db.query(ThreatIOC).filter(
            ThreatIOC.ioc_type == "IP",
            ThreatIOC.value == ip_address
        ).first()

        geo = self.lookup_geo(ip_address)
        
        # Check private subnet
        is_private = False
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            is_private = ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            pass

        if is_private:
            return {
                "ip_address": ip_address,
                "is_malicious": False,
                "reputation_score": 5,
                "severity": "LOW",
                "categories": ["Internal RFC1918 Network", "Trusted Banking LAN"],
                "threat_actor": None,
                "geo": geo,
                "confidence": 100,
                "summary": "Internal private IP address within bank perimeter."
            }

        if ioc_hit:
            score_map = {"CRITICAL": 98, "HIGH": 85, "MEDIUM": 65, "LOW": 30}
            base_score = score_map.get(ioc_hit.severity, 75)
            return {
                "ip_address": ip_address,
                "is_malicious": True,
                "reputation_score": max(base_score, ioc_hit.confidence),
                "severity": ioc_hit.severity,
                "categories": [ioc_hit.threat_type] + ([t.strip() for t in ioc_hit.tags.split(",")] if ioc_hit.tags else []),
                "threat_actor": ioc_hit.threat_actor,
                "geo": geo,
                "confidence": ioc_hit.confidence,
                "summary": f"Known Threat Actor Match: {ioc_hit.threat_actor} ({ioc_hit.description})"
            }

        # Calculate heuristic reputation score for unknown external IP
        score = 15
        categories = ["External Public IP"]
        if geo.get("country") in HIGH_RISK_COUNTRIES:
            score += 45
            categories.append(f"High-Risk Jurisdiction: {geo.get('country')}")

        if "vpn" in geo.get("isp", "").lower() or "hosting" in geo.get("isp", "").lower():
            score += 25
            categories.append("Commercial Hosting / Proxy Infrastructure")

        is_mal = score >= 60
        severity = "HIGH" if score >= 80 else ("MEDIUM" if score >= 50 else "LOW")

        return {
            "ip_address": ip_address,
            "is_malicious": is_mal,
            "reputation_score": min(score, 100),
            "severity": severity,
            "categories": categories,
            "threat_actor": None,
            "geo": geo,
            "confidence": 70,
            "summary": "Heuristic evaluation based on autonomous network and geographic origin."
        }

    @staticmethod
    def lookup_geo(ip_address: str) -> Dict[str, Any]:
        """Provides simulated or resolved geographic coordinates and ASN details."""
        if ip_address in SIMULATED_GEOIP_DB:
            return SIMULATED_GEOIP_DB[ip_address]
        
        # Generic deterministic fallback for realistic rendering
        parts = [int(p) for p in ip_address.split(".") if p.isdigit()]
        if len(parts) == 4:
            lat = 20.0 + (parts[0] % 40) + (parts[1] / 10.0)
            lon = -30.0 + (parts[2] % 120) + (parts[3] / 10.0)
            return {
                "city": f"Node-{parts[0]}",
                "country": "International Gateway",
                "lat": round(lat, 4),
                "lon": round(lon, 4),
                "isp": f"Tier-1 Transit AS{parts[0]*100}"
            }
        
        return {
            "city": "Unknown",
            "country": "Unknown",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Unspecified Provider"
        }

