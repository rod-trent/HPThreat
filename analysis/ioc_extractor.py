"""Extract Indicators of Compromise from honeypot events."""

import re
from dataclasses import dataclass, field, asdict
from typing import Optional

# Regex patterns
_IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_HASH_MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
_HASH_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
_URL_RE = re.compile(r'https?://[^\s\'"<>]+')
_B64_RE = re.compile(r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
_REVERSE_SHELL_RE = re.compile(r'/dev/tcp/([0-9.]+)/(\d+)')
_PRIVATE_IP_RE = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|::1)'
)


@dataclass
class IOC:
    type: str           # ip, hash_md5, hash_sha256, url, credential, command, reverse_shell
    value: str
    source: str         # honeypot name
    first_seen: str
    last_seen: str
    count: int = 1
    context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class IOCExtractor:
    def extract_all(self, events: list[dict], source_name: str) -> list[IOC]:
        iocs: dict[tuple, IOC] = {}

        def _add(ioc_type: str, value: str, ts: str, ctx: dict):
            key = (ioc_type, value)
            if key in iocs:
                existing = iocs[key]
                existing.count += 1
                if ts > existing.last_seen:
                    existing.last_seen = ts
                if ts < existing.first_seen:
                    existing.first_seen = ts
            else:
                iocs[key] = IOC(
                    type=ioc_type, value=value, source=source_name,
                    first_seen=ts, last_seen=ts, context=ctx
                )

        for event in events:
            ts = event.get("timestamp", "")
            eventid = event.get("eventid", "")

            # Source IPs
            src_ip = event.get("src_ip", "")
            if src_ip and not _PRIVATE_IP_RE.match(src_ip):
                _add("ip", src_ip, ts, {"protocol": event.get("protocol", ""), "eventid": eventid})

            # File hashes
            for hash_field in ("shasum", "sha512hash"):
                h = event.get(hash_field, "")
                if h and _HASH_SHA256_RE.fullmatch(h):
                    _add("hash_sha256", h, ts, {"url": event.get("url", ""), "file": event.get("outfile", "")})
            for hash_field in ("md5hash", "md5sum"):
                h = event.get(hash_field, "")
                if h and _HASH_MD5_RE.fullmatch(h):
                    _add("hash_md5", h, ts, {"url": event.get("url", "")})

            # Download URLs
            url = event.get("url", "")
            if url:
                _add("url", url, ts, {"eventid": eventid})

            # Credentials
            username = event.get("username", "")
            password = event.get("password", "")
            if username:
                _add("credential", f"{username}:{password}", ts, {"eventid": eventid})

            # Commands - extract from cowrie command events
            cmd = event.get("input", "")
            if cmd:
                _add("command", cmd, ts, {"session": event.get("session", ""), "src_ip": src_ip})
                # Extract URLs from commands
                for found_url in _URL_RE.findall(cmd):
                    _add("url", found_url, ts, {"from_command": cmd[:100]})
                # Detect reverse shells
                for match in _REVERSE_SHELL_RE.finditer(cmd):
                    c2_ip = match.group(1)
                    c2_port = match.group(2)
                    if not _PRIVATE_IP_RE.match(c2_ip):
                        _add("ip", c2_ip, ts, {"role": "c2", "port": c2_port})
                        _add("reverse_shell", f"{c2_ip}:{c2_port}", ts, {"command": cmd[:200]})

            # HTTP honeypot paths
            path = event.get("path", "")
            if path and event.get("_suspicious"):
                body = event.get("body", "")
                text = path + " " + body
                for found_url in _URL_RE.findall(text):
                    _add("url", found_url, ts, {"path": path})

        return list(iocs.values())

    def extract_ips(self, events: list[dict]) -> list[str]:
        ips = set()
        for e in events:
            if e.get("src_ip") and not _PRIVATE_IP_RE.match(e["src_ip"]):
                ips.add(e["src_ip"])
            # Also scan command strings
            for cmd_field in ("input", "body"):
                for ip in _IP_RE.findall(e.get(cmd_field, "")):
                    if not _PRIVATE_IP_RE.match(ip):
                        ips.add(ip)
        return sorted(ips)

    def extract_hashes(self, events: list[dict]) -> list[dict]:
        hashes = []
        seen = set()
        for e in events:
            for f in ("shasum", "md5hash", "md5sum", "sha512hash"):
                h = e.get(f, "")
                if h and h not in seen:
                    seen.add(h)
                    hashes.append({"hash": h, "type": "sha256" if len(h) == 64 else "md5", "url": e.get("url", "")})
        return hashes

    def extract_credentials(self, events: list[dict]) -> list[dict]:
        creds: dict[str, int] = {}
        for e in events:
            u = e.get("username", "")
            p = e.get("password", "")
            if u:
                key = f"{u}:{p}"
                creds[key] = creds.get(key, 0) + 1
        return [{"username": k.split(":", 1)[0], "password": k.split(":", 1)[1], "count": v}
                for k, v in sorted(creds.items(), key=lambda x: x[1], reverse=True)]
