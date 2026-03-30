"""Emerging Threats open ruleset client - fetches and parses Snort rules."""

import json
import re
import time
from pathlib import Path
from typing import Optional

import requests

from config import CACHE_DIR, CACHE_TTL_SECONDS, ET_RULE_CATEGORIES, ET_RULES_BASE_URL

_CACHE_FILE = CACHE_DIR / "et_rules_cache.json"
_MSG_RE = re.compile(r'msg:"([^"]+)"')
_SID_RE = re.compile(r'sid:(\d+)')
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_METADATA_RE = re.compile(r'metadata:([^;]+)')
_ATTACK_RE = re.compile(r'attack_target\s+([^,]+)', re.IGNORECASE)


class EmergingThreatsClient:
    def __init__(self):
        self._rules: Optional[list[dict]] = None
        self._cached_at: float = 0.0

    def fetch_rules(self) -> list[dict]:
        """Fetch and parse ET open rules, cached to disk."""
        if self._rules and time.time() - self._cached_at < CACHE_TTL_SECONDS:
            return self._rules

        if _CACHE_FILE.exists():
            try:
                cached = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
                if time.time() - cached.get("cached_at", 0) < CACHE_TTL_SECONDS:
                    self._rules = cached["rules"]
                    self._cached_at = cached["cached_at"]
                    return self._rules
            except (json.JSONDecodeError, KeyError):
                pass

        rules = []
        for category in ET_RULE_CATEGORIES:
            url = ET_RULES_BASE_URL.format(category)
            try:
                resp = requests.get(url, timeout=20)
                if resp.status_code == 200:
                    parsed = self._parse_rules(resp.text, category)
                    rules.extend(parsed)
            except Exception:
                continue

        self._rules = rules
        self._cached_at = time.time()
        try:
            _CACHE_FILE.write_text(
                json.dumps({"cached_at": self._cached_at, "rules": rules}, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass
        return rules

    def match_ip(self, ip: str) -> list[str]:
        """Return list of rule messages that reference this IP."""
        rules = self.fetch_rules()
        matches = []
        for rule in rules:
            if ip in rule.get("ip_refs", []):
                matches.append(rule.get("msg", ""))
        return matches

    def search_keyword(self, keyword: str) -> list[dict]:
        """Search rules by keyword in message."""
        rules = self.fetch_rules()
        kw = keyword.lower()
        return [r for r in rules if kw in r.get("msg", "").lower()]

    def _parse_rules(self, text: str, category: str) -> list[dict]:
        parsed = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            msg_m = _MSG_RE.search(line)
            sid_m = _SID_RE.search(line)
            if not msg_m:
                continue
            ip_refs = list(set(_IP_RE.findall(line)))
            parsed.append({
                "sid": sid_m.group(1) if sid_m else "",
                "msg": msg_m.group(1),
                "category": category,
                "ip_refs": ip_refs,
            })
        return parsed

    def get_stats(self) -> dict:
        rules = self.fetch_rules()
        by_category: dict[str, int] = {}
        for r in rules:
            c = r.get("category", "unknown")
            by_category[c] = by_category.get(c, 0) + 1
        return {
            "total_rules": len(rules),
            "by_category": by_category,
            "source": "emerging_threats_open",
        }
