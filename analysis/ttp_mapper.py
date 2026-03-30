"""Map honeypot events to MITRE ATT&CK techniques."""

from typing import Callable


def _count_event(events: list[dict], eventid: str) -> int:
    return sum(1 for e in events if e.get("eventid") == eventid)


def _cmd_contains(events: list[dict], *patterns: str) -> bool:
    for e in events:
        cmd = (e.get("input", "") + e.get("path", "") + e.get("body", "")).lower()
        if any(p.lower() in cmd for p in patterns):
            return True
    return False


def _detect_spray(events: list[dict]) -> bool:
    """Many unique usernames, few unique passwords = password spray."""
    failed = [e for e in events if e.get("eventid") == "cowrie.login.failed"]
    if len(failed) < 10:
        return False
    users = {e.get("username") for e in failed}
    passwords = {e.get("password") for e in failed}
    return len(users) > 5 and len(passwords) <= 3


# Each rule: technique metadata + a condition lambda
TTP_RULES: list[dict] = [
    {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "severity": "medium",
        "condition": lambda e: _count_event(e, "cowrie.login.failed") > 5,
        "evidence_fn": lambda e: [x for x in e if x.get("eventid") == "cowrie.login.failed"][:3],
    },
    {
        "technique_id": "T1110.003",
        "technique_name": "Brute Force: Password Spraying",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "severity": "medium",
        "condition": _detect_spray,
        "evidence_fn": lambda e: [x for x in e if x.get("eventid") == "cowrie.login.failed"][:3],
    },
    {
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic": "TA0008",
        "tactic_name": "Lateral Movement",
        "severity": "high",
        "condition": lambda e: _count_event(e, "cowrie.login.success") > 0,
        "evidence_fn": lambda e: [x for x in e if x.get("eventid") == "cowrie.login.success"][:3],
    },
    {
        "technique_id": "T1059.004",
        "technique_name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "TA0002",
        "tactic_name": "Execution",
        "severity": "high",
        "condition": lambda e: _cmd_contains(e, "bash", "sh -c", "/bin/sh", "zsh"),
        "evidence_fn": lambda e: [x for x in e if x.get("eventid") == "cowrie.command.input"
                                  and any(p in x.get("input","").lower() for p in ["bash","sh -c","/bin/sh"])][:3],
    },
    {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "TA0011",
        "tactic_name": "Command and Control",
        "severity": "high",
        "condition": lambda e: _count_event(e, "cowrie.session.file_download") > 0
                               or _cmd_contains(e, "wget", "curl"),
        "evidence_fn": lambda e: [x for x in e if x.get("eventid") == "cowrie.session.file_download"
                                  or (x.get("eventid") == "cowrie.command.input" and
                                      any(p in x.get("input","") for p in ["wget","curl"]))][:3],
    },
    {
        "technique_id": "T1548.001",
        "technique_name": "Abuse Elevation Control: Setuid/Setgid",
        "tactic": "TA0004",
        "tactic_name": "Privilege Escalation",
        "severity": "high",
        "condition": lambda e: _cmd_contains(e, "chmod +s", "chmod 4755", "chmod u+s"),
        "evidence_fn": lambda e: [x for x in e if "chmod" in x.get("input","")][:3],
    },
    {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "severity": "low",
        "condition": lambda e: _cmd_contains(e, "uname", "cat /proc", "lscpu", "dmidecode"),
        "evidence_fn": lambda e: [x for x in e if any(p in x.get("input","") for p in
                                                        ["uname","/proc","lscpu","dmidecode"])][:3],
    },
    {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "severity": "medium",
        "condition": lambda e: _cmd_contains(e, "cat /etc/passwd", "cat /etc/shadow", "id", "whoami"),
        "evidence_fn": lambda e: [x for x in e if any(p in x.get("input","") for p in
                                                        ["/etc/passwd","/etc/shadow","whoami"])][:3],
    },
    {
        "technique_id": "T1070.003",
        "technique_name": "Indicator Removal: Clear Command History",
        "tactic": "TA0005",
        "tactic_name": "Defense Evasion",
        "severity": "medium",
        "condition": lambda e: _cmd_contains(e, "history -c", "unset HISTFILE", ".bash_history"),
        "evidence_fn": lambda e: [x for x in e if any(p in x.get("input","") for p in
                                                        ["history -c","HISTFILE",".bash_history"])][:3],
    },
    {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "TA0002",
        "tactic_name": "Execution",
        "severity": "high",
        "condition": lambda e: _cmd_contains(e, "powershell", "pwsh"),
        "evidence_fn": lambda e: [x for x in e if "powershell" in x.get("input","").lower()][:3],
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "severity": "critical",
        "condition": lambda e: any("/../" in e.get("path","") or "etc/passwd" in e.get("path","")
                                   for e in e if isinstance(e, dict)),
        "evidence_fn": lambda e: [x for x in e if "/../" in x.get("path","") or
                                   "etc/passwd" in x.get("path","")][:3],
    },
    {
        "technique_id": "T1595.002",
        "technique_name": "Active Scanning: Vulnerability Scanning",
        "tactic": "TA0043",
        "tactic_name": "Reconnaissance",
        "severity": "low",
        "condition": lambda e: any(x.get("_suspicious") and "scanner" in x.get("_suspicious", [])
                                   for x in e),
        "evidence_fn": lambda e: [x for x in e if x.get("_suspicious") and "scanner" in x.get("_suspicious", [])][:3],
    },
    {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "TA0010",
        "tactic_name": "Exfiltration",
        "severity": "high",
        "condition": lambda e: _cmd_contains(e, "/dev/tcp", "nc -e", "ncat", "ncat -e"),
        "evidence_fn": lambda e: [x for x in e if any(p in x.get("input","") for p in
                                                        ["/dev/tcp","nc -e","ncat"])][:3],
    },
    {
        "technique_id": "T1016",
        "technique_name": "System Network Configuration Discovery",
        "tactic": "TA0007",
        "tactic_name": "Discovery",
        "severity": "low",
        "condition": lambda e: _cmd_contains(e, "ifconfig", "ip route", "netstat", "ss -"),
        "evidence_fn": lambda e: [x for x in e if any(p in x.get("input","") for p in
                                                        ["ifconfig","ip route","netstat","ss -"])][:3],
    },
    {
        "technique_id": "T1053.003",
        "technique_name": "Scheduled Task/Job: Cron",
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "severity": "high",
        "condition": lambda e: _cmd_contains(e, "crontab", "cron.d", "/etc/cron"),
        "evidence_fn": lambda e: [x for x in e if "cron" in x.get("input","").lower()][:3],
    },
]


class TTPMapper:
    def map_ttps(self, events: list[dict]) -> list[dict]:
        matched = []
        for rule in TTP_RULES:
            try:
                if rule["condition"](events):
                    evidence = rule["evidence_fn"](events)
                    matched.append({
                        "technique_id": rule["technique_id"],
                        "technique_name": rule["technique_name"],
                        "tactic": rule["tactic"],
                        "tactic_name": rule["tactic_name"],
                        "severity": rule["severity"],
                        "evidence_count": len(evidence),
                        "evidence_samples": evidence,
                        "attack_url": f"https://attack.mitre.org/techniques/{rule['technique_id'].replace('.', '/')}/",
                    })
            except Exception:
                continue
        return matched

    def build_navigator_layer(self, ttps: list[dict], honeypot_name: str) -> dict:
        """Build ATT&CK Navigator JSON layer."""
        techniques = []
        color_map = {"critical": "#ff0000", "high": "#ff6600", "medium": "#ffcc00", "low": "#99ff99"}
        for ttp in ttps:
            techniques.append({
                "techniqueID": ttp["technique_id"],
                "tactic": ttp["tactic_name"].lower().replace(" ", "-"),
                "color": color_map.get(ttp["severity"], "#ffffff"),
                "comment": f"Detected by honeypot: {honeypot_name}",
                "enabled": True,
                "score": {"critical": 100, "high": 75, "medium": 50, "low": 25}.get(ttp["severity"], 0),
            })
        return {
            "name": f"HPThreat - {honeypot_name}",
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"TTPs detected by HPThreat honeypot: {honeypot_name}",
            "techniques": techniques,
            "gradient": {"colors": ["#ffffff", "#ff0000"], "minValue": 0, "maxValue": 100},
            "legendItems": [{"label": s, "color": c} for s, c in color_map.items()],
        }
