import json
from datetime import datetime
from typing import List, Dict, Any, Union
from dateutil import parser as date_parser
from backend.threat_intel.threat_service import ThreatIntelligenceService


class LogParser:
    """
    Log Ingestion & Normalization Engine for MR.X BANK SOC SENTINEL.
    Parses JSON and JSONL logs, standardizes timestamps, normalizes fields,
    and enriches events with geographic telemetry.
    """

    @staticmethod
    def parse_timestamp(ts_value: Any) -> datetime:
        """Robust timestamp parser handling ISO 8601, UNIX epochs, and standard strings."""
        if not ts_value:
            return datetime.utcnow()
        if isinstance(ts_value, datetime):
            return ts_value
        if isinstance(ts_value, (int, float)):
            # Epoch milliseconds vs seconds
            if ts_value > 1e11:
                return datetime.utcfromtimestamp(ts_value / 1000.0)
            return datetime.utcfromtimestamp(ts_value)
        if isinstance(ts_value, str):
            try:
                return date_parser.parse(ts_value)
            except Exception:
                return datetime.utcnow()
        return datetime.utcnow()

    @classmethod
    def normalize_event(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Maps diverse heterogeneous bank log formats into canonical LogEntry schema."""
        raw_copy = dict(raw)
        
        # 1. Determine log type
        log_type = raw.get("log_type") or raw.get("type") or raw.get("category")
        if not log_type:
            if "amount" in raw or "source_account" in raw or "transaction_id" in raw:
                log_type = "transaction"
            elif "endpoint" in raw or "http_method" in raw or "url" in raw or "status_code" in raw:
                log_type = "web"
            elif "action" in raw and ("login" in str(raw.get("action", "")).lower() or "auth" in str(raw.get("action", "")).lower()):
                log_type = "auth"
            else:
                log_type = "web"
        log_type = str(log_type).lower()

        # 2. Timestamp
        raw_ts = raw.get("timestamp") or raw.get("time") or raw.get("@timestamp") or raw.get("event_time")
        timestamp = cls.parse_timestamp(raw_ts)

        # 3. Source IP
        src_ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("ip") or raw.get("client_ip") or "127.0.0.1"
        dst_ip = raw.get("destination_ip") or raw.get("dst_ip") or raw.get("server_ip")

        # 4. Username / Account
        username = raw.get("username") or raw.get("user") or raw.get("user_id") or raw.get("account_user")
        
        # 5. Action
        action = raw.get("action") or raw.get("event") or raw.get("event_type") or "unknown_event"

        # 6. Web parameters
        endpoint = raw.get("endpoint") or raw.get("url") or raw.get("path")
        http_method = raw.get("http_method") or raw.get("method") or ("GET" if endpoint else None)
        status_code = raw.get("status_code") or raw.get("response_code") or raw.get("code")
        if status_code is not None:
            try:
                status_code = int(status_code)
            except ValueError:
                status_code = None

        payload = raw.get("payload") or raw.get("request_body") or raw.get("query_string")
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        user_agent = raw.get("user_agent") or raw.get("agent")

        # 7. Financial parameters
        amount = raw.get("amount") or raw.get("transaction_amount")
        if amount is not None:
            try:
                amount = float(amount)
            except ValueError:
                amount = None
        currency = raw.get("currency") or "USD"
        source_account = raw.get("source_account") or raw.get("src_account") or raw.get("from_account")
        destination_account = raw.get("destination_account") or raw.get("dst_account") or raw.get("to_account")
        transaction_type = raw.get("transaction_type") or raw.get("tx_type")

        # 8. Geo telemetry enrichment
        city = raw.get("location_city") or raw.get("city")
        country = raw.get("location_country") or raw.get("country")
        lat = raw.get("latitude") or raw.get("lat")
        lon = raw.get("longitude") or raw.get("lon")

        if lat is not None and lon is not None:
            try:
                lat = float(lat)
                lon = float(lon)
            except ValueError:
                lat, lon = None, None
        else:
            geo_info = ThreatIntelligenceService.lookup_geo(src_ip)
            city = city or geo_info.get("city")
            country = country or geo_info.get("country")
            lat = geo_info.get("lat")
            lon = geo_info.get("lon")

        return {
            "log_type": log_type,
            "timestamp": timestamp,
            "source_ip": str(src_ip).strip(),
            "destination_ip": str(dst_ip).strip() if dst_ip else None,
            "username": str(username).strip() if username else None,
            "action": str(action).strip(),
            "endpoint": str(endpoint).strip() if endpoint else None,
            "http_method": str(http_method).upper() if http_method else None,
            "status_code": status_code,
            "payload": str(payload) if payload else None,
            "user_agent": str(user_agent) if user_agent else None,
            "amount": amount,
            "currency": str(currency).upper(),
            "source_account": str(source_account).strip() if source_account else None,
            "destination_account": str(destination_account).strip() if destination_account else None,
            "transaction_type": str(transaction_type) if transaction_type else None,
            "location_city": city,
            "location_country": country,
            "latitude": lat,
            "longitude": lon,
            "raw_log": json.dumps(raw_copy, default=str)
        }

    @classmethod
    def parse_jsonl(cls, text_data: str) -> List[Dict[str, Any]]:
        """Parses multi-line JSONL string into a list of normalized log dictionaries."""
        results = []
        for line in text_data.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw_dict = json.loads(line)
                results.append(cls.normalize_event(raw_dict))
            except json.JSONDecodeError:
                continue
        return results

    @classmethod
    def parse_json(cls, json_payload: Union[str, Dict[str, Any], List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Parses a single JSON object or array of JSON objects."""
        if isinstance(json_payload, str):
            json_payload = json.loads(json_payload)

        if isinstance(json_payload, dict):
            return [cls.normalize_event(json_payload)]
        elif isinstance(json_payload, list):
            return [cls.normalize_event(item) for item in json_payload if isinstance(item, dict)]
        return []

