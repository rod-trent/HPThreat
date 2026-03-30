"""Parse Cowrie SSH/Telnet honeypot NDJSON logs."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


class CowrieParser:
    KNOWN_EVENTS = {
        "cowrie.session.connect",
        "cowrie.session.closed",
        "cowrie.login.failed",
        "cowrie.login.success",
        "cowrie.command.input",
        "cowrie.command.failed",
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
        "cowrie.client.version",
        "cowrie.direct-tcpip.request",
    }

    def parse_file(self, log_path: Path, since: Optional[datetime] = None) -> list[dict]:
        if not log_path.exists():
            return []
        events = []
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = self.parse_line(line)
                if event is None:
                    continue
                if since:
                    ts = self._parse_ts(event.get("timestamp", ""))
                    if ts and ts < since:
                        continue
                events.append(event)
        return events

    def parse_line(self, line: str) -> Optional[dict]:
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                return None
            return obj
        except json.JSONDecodeError:
            return None

    def filter_by_timeframe(self, events: list[dict], hours: int) -> list[dict]:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        result = []
        for e in events:
            ts = self._parse_ts(e.get("timestamp", ""))
            if ts and ts >= cutoff:
                result.append(e)
        return result

    def get_sessions(self, events: list[dict]) -> dict[str, list[dict]]:
        sessions: dict[str, list[dict]] = {}
        for e in events:
            sid = e.get("session", "unknown")
            sessions.setdefault(sid, []).append(e)
        return sessions

    def summarize(self, events: list[dict]) -> dict:
        connects = [e for e in events if e.get("eventid") == "cowrie.session.connect"]
        failed_logins = [e for e in events if e.get("eventid") == "cowrie.login.failed"]
        success_logins = [e for e in events if e.get("eventid") == "cowrie.login.success"]
        commands = [e for e in events if e.get("eventid") == "cowrie.command.input"]
        downloads = [e for e in events if e.get("eventid") == "cowrie.session.file_download"]

        unique_ips = {e.get("src_ip") for e in events if e.get("src_ip")}
        top_ips = self._top_values([e.get("src_ip", "") for e in connects], 10)
        top_users = self._top_values([e.get("username", "") for e in failed_logins + success_logins], 10)
        top_passwords = self._top_values([e.get("password", "") for e in failed_logins + success_logins], 10)

        return {
            "total_events": len(events),
            "unique_ips": len(unique_ips),
            "connection_attempts": len(connects),
            "failed_logins": len(failed_logins),
            "successful_logins": len(success_logins),
            "commands_executed": len(commands),
            "files_downloaded": len(downloads),
            "top_source_ips": top_ips,
            "top_usernames": top_users,
            "top_passwords": top_passwords,
        }

    @staticmethod
    def _parse_ts(ts_str: str) -> Optional[datetime]:
        if not ts_str:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        try:
            # ISO 8601 with +00:00
            return datetime.fromisoformat(ts_str)
        except ValueError:
            return None

    @staticmethod
    def _top_values(values: list[str], n: int) -> list[dict]:
        counts: dict[str, int] = {}
        for v in values:
            if v:
                counts[v] = counts.get(v, 0) + 1
        return [
            {"value": k, "count": v}
            for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
        ]
