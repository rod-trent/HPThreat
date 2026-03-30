"""Cross-honeypot TTP correlation and kill chain analysis."""

from collections import defaultdict


KILL_CHAIN_ORDER = [
    "TA0043",  # Reconnaissance
    "TA0042",  # Resource Development
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0003",  # Persistence
    "TA0004",  # Privilege Escalation
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0011",  # Command and Control
    "TA0010",  # Exfiltration
    "TA0040",  # Impact
]

KILL_CHAIN_NAMES = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}


class TTPCorrelator:
    def correlate(self, ttps: list[dict]) -> dict:
        """Organize TTPs by kill chain stage and calculate attack sophistication."""
        by_tactic: dict[str, list[dict]] = defaultdict(list)
        for ttp in ttps:
            by_tactic[ttp["tactic"]].append(ttp)

        kill_chain_stages = []
        covered_tactics = set(by_tactic.keys())
        for tactic_id in KILL_CHAIN_ORDER:
            if tactic_id in by_tactic:
                kill_chain_stages.append({
                    "stage": KILL_CHAIN_NAMES.get(tactic_id, tactic_id),
                    "tactic_id": tactic_id,
                    "techniques": by_tactic[tactic_id],
                })

        # Sophistication score: 0-100 based on number of distinct kill chain stages covered
        max_stages = len(KILL_CHAIN_ORDER)
        sophistication_pct = round(len(covered_tactics) / max_stages * 100)
        sophistication_label = (
            "APT-level" if sophistication_pct >= 50 else
            "Intermediate" if sophistication_pct >= 25 else
            "Script-kiddie"
        )

        # Critical path: highest-severity techniques in order
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        critical_path = sorted(ttps, key=lambda t: severity_order.get(t.get("severity", "low"), 3))[:5]

        return {
            "kill_chain_stages": kill_chain_stages,
            "tactics_covered": len(covered_tactics),
            "total_techniques": len(ttps),
            "sophistication_score": sophistication_pct,
            "sophistication_label": sophistication_label,
            "critical_path": critical_path,
            "unique_tactics": [KILL_CHAIN_NAMES.get(t, t) for t in sorted(covered_tactics, key=lambda x: KILL_CHAIN_ORDER.index(x) if x in KILL_CHAIN_ORDER else 99)],
        }
