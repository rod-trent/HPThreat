"""AbuseIPDB API client with in-memory TTL cache."""

import re
import time
from typing import Optional

import requests

from config import ABUSEIPDB_API_KEY, CACHE_TTL_SECONDS

_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


class AbuseIPDBClient:
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self):
        self._cache: dict[str, tuple[dict, float]] = {}

    def check_ip(self, ip: str, max_age_days: int = 30) -> dict:
        if not self._is_valid_ip(ip):
            return {"error": f"Invalid IP address: {ip}"}

        # Cache hit
        if ip in self._cache:
            result, ts = self._cache[ip]
            if time.time() - ts < CACHE_TTL_SECONDS:
                return {**result, "cached": True}

        if not ABUSEIPDB_API_KEY:
            return self._mock_result(ip)

        try:
            resp = requests.get(
                f"{self.BASE_URL}/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": False},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result = {
                    "ip": ip,
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "last_reported": data.get("lastReportedAt", ""),
                    "source": "abuseipdb",
                }
                self._cache[ip] = (result, time.time())
                return result
            elif resp.status_code == 401:
                return {"error": "Invalid AbuseIPDB API key", "ip": ip}
            elif resp.status_code == 422:
                return {"error": f"Invalid IP: {ip}", "ip": ip}
            elif resp.status_code == 429:
                return {"error": "AbuseIPDB rate limit exceeded", "ip": ip}
            else:
                return {"error": f"AbuseIPDB HTTP {resp.status_code}", "ip": ip}
        except requests.RequestException as e:
            return {"error": f"AbuseIPDB request failed: {e}", "ip": ip}

    def _mock_result(self, ip: str) -> dict:
        """Return a mock result when no API key is configured."""
        return {
            "ip": ip,
            "abuse_score": 0,
            "total_reports": 0,
            "country_code": "XX",
            "isp": "Unknown (no API key)",
            "domain": "",
            "is_tor": False,
            "is_whitelisted": False,
            "last_reported": "",
            "source": "abuseipdb_mock",
            "note": "Set ABUSEIPDB_API_KEY env var for real data",
        }

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        if not _IPV4_RE.match(ip):
            return False
        return all(0 <= int(octet) <= 255 for octet in ip.split("."))
