"""Generate Sigma detection rules from honeypot attack data."""

import uuid
from datetime import datetime, timezone

import yaml


class SigmaGenerator:
    _SEVERITY_MAP = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }

    _LOGSOURCE_MAP = {
        "cowrie": {"product": "linux", "service": "cowrie"},
        "dionaea": {"product": "network", "service": "dionaea"},
        "http": {"product": "webserver", "service": "http"},
    }

    def generate(self, attack_data: dict) -> dict:
        """Generate a Sigma rule from attack data dict.

        Expected keys:
          technique_id, technique_name, tactic_name, iocs (list of strings),
          honeypot_type (cowrie/dionaea/http), source_name, severity
        """
        technique_id = attack_data.get("technique_id", "T0000")
        technique_name = attack_data.get("technique_name", "Unknown Technique")
        tactic_name = attack_data.get("tactic_name", "unknown")
        iocs = attack_data.get("iocs", [])
        honeypot_type = attack_data.get("honeypot_type", "cowrie")
        source_name = attack_data.get("source_name", "unknown-honeypot")
        severity = self._SEVERITY_MAP.get(attack_data.get("severity", "medium"), "medium")

        rule_id = str(uuid.uuid4())
        today = datetime.now(timezone.utc).strftime("%Y/%m/%d")

        # Build tags
        tech_tag = f"attack.{technique_id.lower().replace('.', '_')}"
        tactic_tag = f"attack.{tactic_name.lower().replace(' ', '_')}"
        tags = [tech_tag, tactic_tag]

        logsource = self._LOGSOURCE_MAP.get(honeypot_type, {"product": "linux", "service": "honeypot"})

        # Build detection block
        detection: dict = {}
        if iocs:
            # Categorize IOCs
            ips = [i for i in iocs if self._looks_like_ip(i)]
            keywords = [i for i in iocs if not self._looks_like_ip(i)]
            if ips:
                detection["src_ips"] = {"src_ip": ips}
            if keywords:
                detection["keywords"] = keywords
            parts = list(detection.keys())
            detection["condition"] = " or ".join(parts) if parts else "all of them"
        else:
            detection["keywords"] = [technique_name]
            detection["condition"] = "keywords"

        rule = {
            "title": f"Honeypot Detection: {technique_name}",
            "id": rule_id,
            "status": "experimental",
            "description": (
                f"Auto-generated Sigma rule from HPThreat honeypot '{source_name}'. "
                f"ATT&CK Technique: {technique_id} - {technique_name}."
            ),
            "references": [
                "https://github.com/rod-trent/HPThreat",
                f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            ],
            "author": "HPThreat MCP Server",
            "date": today,
            "modified": today,
            "tags": tags,
            "logsource": logsource,
            "detection": detection,
            "falsepositives": ["Legitimate administrative access (honeypot environment only)"],
            "level": severity,
        }

        sigma_yaml = yaml.dump(rule, default_flow_style=False, allow_unicode=True, sort_keys=False)
        return {
            "rule_id": rule_id,
            "sigma_yaml": sigma_yaml,
            "technique_id": technique_id,
            "severity": severity,
        }

    def generate_bulk(self, ttps: list[dict], source_name: str, honeypot_type: str) -> list[dict]:
        results = []
        for ttp in ttps:
            iocs = [e.get("src_ip", "") for e in ttp.get("evidence_samples", []) if e.get("src_ip")]
            attack_data = {
                "technique_id": ttp["technique_id"],
                "technique_name": ttp["technique_name"],
                "tactic_name": ttp["tactic_name"],
                "iocs": iocs,
                "honeypot_type": honeypot_type,
                "source_name": source_name,
                "severity": ttp.get("severity", "medium"),
            }
            results.append(self.generate(attack_data))
        return results

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        import re
        return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value))
