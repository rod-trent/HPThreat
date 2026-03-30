"""Feodo Tracker C2 IP blocklist client with disk cache."""

import json
import time
from pathlib import Path
from typing import Optional

import requests

from config import CACHE_DIR, CACHE_TTL_SECONDS, FEODO_URL

_CACHE_FILE = CACHE_DIR / "feodo_cache.json"


class FeodoTrackerClient:
    def __init__(self):
        self._data: Optional[list[dict]] = None
        self._cached_at: float = 0.0

    def fetch(self) -> list[dict]:
        """Return the Feodo Tracker blocklist, using disk cache when fresh."""
        # Try memory cache first
        if self._data and time.time() - self._cached_at < CACHE_TTL_SECONDS:
            return self._data

        # Try disk cache
        if _CACHE_FILE.exists():
            try:
                cached = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
                if time.time() - cached.get("cached_at", 0) < CACHE_TTL_SECONDS:
                    self._data = cached["data"]
                    self._cached_at = cached["cached_at"]
                    return self._data
            except (json.JSONDecodeError, KeyError):
                pass

        # Fetch fresh
        try:
            resp = requests.get(FEODO_URL, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            self._data = data
            self._cached_at = time.time()
            _CACHE_FILE.write_text(
                json.dumps({"cached_at": self._cached_at, "data": data}, indent=2),
                encoding="utf-8",
            )
            return data
        except Exception as e:
            # Return empty list but don't crash
            return []

    def is_known_c2(self, ip: str) -> Optional[dict]:
        """Check if an IP is in the Feodo Tracker C2 list."""
        data = self.fetch()
        for entry in data:
            if entry.get("ip_address") == ip:
                return {
                    "ip": ip,
                    "port": entry.get("port"),
                    "malware": entry.get("malware"),
                    "country": entry.get("country"),
                    "first_seen": entry.get("first_seen"),
                    "last_online": entry.get("last_online"),
                    "source": "feodo_tracker",
                    "is_c2": True,
                }
        return None

    def get_stats(self) -> dict:
        data = self.fetch()
        malware_counts: dict[str, int] = {}
        for entry in data:
            m = entry.get("malware", "unknown")
            malware_counts[m] = malware_counts.get(m, 0) + 1
        return {
            "total_c2_ips": len(data),
            "malware_families": malware_counts,
            "source": "feodo_tracker",
        }
