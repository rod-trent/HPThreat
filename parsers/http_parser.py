"""Parse custom HTTP honeypot NDJSON logs."""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

_SUSPICIOUS_PATHS = re.compile(
    r"(\.\./|/etc/passwd|/etc/shadow|/wp-admin|/phpmyadmin|/\.env|/\.git|"
    r"/actuator|/console|/shell\.php|/cmd\.php|/\.aws|/config\.php|/xmlrpc)",
    re.IGNORECASE,
)
_INJECTION_PATTERNS = re.compile(
    r"(<script|UNION\s+SELECT|exec\s*\(|eval\s*\(|/bin/bash|/bin/sh|base64_decode|"
    r"system\s*\(|passthru|shell_exec|\bxp_cmdshell\b)",
    re.IGNORECASE,
)
_SCANNER_UAS = re.compile(
    r"(masscan|zgrab|nikto|sqlmap|nmap|shodan|censys|nessus|openvas|"
    r"dirbuster|gobuster|wfuzz|burpsuite|acunetix)",
    re.IGNORECASE,
)


class HTTPParser:
    def parse_file(self, log_path: Path, hours: int = 24) -> list[dict]:
        if not log_path.exists():
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        events = []
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    ts = self._parse_ts(obj.get("timestamp", ""))
                    if ts and ts >= cutoff:
                        obj["_suspicious"] = self._classify(obj)
                        events.append(obj)
                except json.JSONDecodeError:
                    continue
        return events

    def _classify(self, event: dict) -> list[str]:
        flags = []
        path = event.get("path", "")
        body = event.get("body", "")
        ua = event.get("user_agent", "")

        if _SUSPICIOUS_PATHS.search(path):
            flags.append("suspicious_path")
        if _INJECTION_PATTERNS.search(path) or _INJECTION_PATTERNS.search(body):
            flags.append("injection_attempt")
        if _SCANNER_UAS.search(ua):
            flags.append("scanner")
        if event.get("method") in ("DELETE", "PUT", "TRACE", "OPTIONS"):
            flags.append("unusual_method")
        return flags

    def summarize(self, events: list[dict]) -> dict:
        unique_ips: set = set()
        paths: dict[str, int] = {}
        suspicious_count = 0
        scanner_count = 0
        for e in events:
            if e.get("src_ip"):
                unique_ips.add(e["src_ip"])
            path = e.get("path", "")
            paths[path] = paths.get(path, 0) + 1
            flags = e.get("_suspicious", [])
            if flags:
                suspicious_count += 1
            if "scanner" in flags:
                scanner_count += 1
        top_paths = sorted(paths.items(), key=lambda x: x[1], reverse=True)[:10]
        return {
            "total_requests": len(events),
            "unique_ips": len(unique_ips),
            "suspicious_requests": suspicious_count,
            "scanner_requests": scanner_count,
            "top_paths": [{"path": p, "count": c} for p, c in top_paths],
        }

    @staticmethod
    def _parse_ts(ts_str: str) -> Optional[datetime]:
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str)
        except ValueError:
            return None
