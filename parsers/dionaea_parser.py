"""Parse Dionaea multi-protocol honeypot logs (JSON and SQLite)."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


class DionaeaParser:
    def parse(self, log_dir: Path, hours: int = 24) -> list[dict]:
        """Try JSON log first, fall back to SQLite."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        json_log = log_dir / "dionaea.json"
        sqlite_db = log_dir / "dionaea.sqlite"

        if json_log.exists():
            return self._parse_json(json_log, cutoff)
        if sqlite_db.exists():
            return self._parse_sqlite(sqlite_db, cutoff)
        return []

    def _parse_json(self, path: Path, cutoff: datetime) -> list[dict]:
        events = []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    ts = self._parse_ts(obj.get("timestamp", ""))
                    if ts and ts >= cutoff:
                        events.append(obj)
                except json.JSONDecodeError:
                    continue
        return events

    def _parse_sqlite(self, path: Path, cutoff: datetime) -> list[dict]:
        events = []
        try:
            conn = sqlite3.connect(str(path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Connections
            try:
                cur.execute(
                    "SELECT connection_timestamp, remote_host, remote_port, local_port, protocol "
                    "FROM connections WHERE connection_timestamp >= ?",
                    (cutoff.timestamp(),),
                )
                for row in cur.fetchall():
                    events.append({
                        "eventid": f"dionaea.connection.{row['protocol']}",
                        "timestamp": datetime.fromtimestamp(row["connection_timestamp"], tz=timezone.utc).isoformat(),
                        "src_ip": row["remote_host"],
                        "src_port": row["remote_port"],
                        "dst_port": row["local_port"],
                        "protocol": row["protocol"],
                    })
            except sqlite3.OperationalError:
                pass

            # Downloads
            try:
                cur.execute(
                    "SELECT download_timestamp, url, md5hash FROM downloads "
                    "WHERE download_timestamp >= ?",
                    (cutoff.timestamp(),),
                )
                for row in cur.fetchall():
                    events.append({
                        "eventid": "dionaea.download.complete",
                        "timestamp": datetime.fromtimestamp(row["download_timestamp"], tz=timezone.utc).isoformat(),
                        "url": row["url"],
                        "md5hash": row["md5hash"],
                    })
            except sqlite3.OperationalError:
                pass

            # Credentials
            try:
                cur.execute("SELECT credential_username, credential_password FROM credentials")
                for row in cur.fetchall():
                    events.append({
                        "eventid": "dionaea.login.attempt",
                        "username": row["credential_username"],
                        "password": row["credential_password"],
                    })
            except sqlite3.OperationalError:
                pass

            conn.close()
        except Exception:
            pass
        return events

    def summarize(self, events: list[dict]) -> dict:
        protocols: dict[str, int] = {}
        unique_ips: set = set()
        downloads = []
        for e in events:
            proto = e.get("protocol", "unknown")
            protocols[proto] = protocols.get(proto, 0) + 1
            if e.get("src_ip"):
                unique_ips.add(e["src_ip"])
            if e.get("eventid") == "dionaea.download.complete":
                downloads.append(e)
        return {
            "total_events": len(events),
            "unique_ips": len(unique_ips),
            "protocols": protocols,
            "malware_downloads": len(downloads),
        }

    @staticmethod
    def _parse_ts(ts_str: str) -> Optional[datetime]:
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str)
        except ValueError:
            return None
