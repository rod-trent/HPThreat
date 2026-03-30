import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = DATA_DIR / "logs"
REPORTS_DIR = DATA_DIR / "reports"
CACHE_DIR = DATA_DIR / "cache"
STATE_FILE = DATA_DIR / "state.json"

# Ensure directories exist
for _d in [DATA_DIR, LOG_DIR, REPORTS_DIR, CACHE_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
ET_RULE_CATEGORIES = ["emerging-trojan", "emerging-scan", "emerging-exploit"]
ET_RULES_BASE_URL = "https://rules.emergingthreats.net/open/snort-2.9.0/rules/{}.rules"
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))
LOG_RETENTION_HOURS = int(os.getenv("LOG_RETENTION_HOURS", "168"))

HONEYPOT_IMAGES = {
    "cowrie": "cowrie/cowrie:latest",
    "dionaea": "dinotools/dionaea:latest",
    "http": "honeypot-http:local",
}

DEFAULT_PORTS = {
    "cowrie": 2222,
    "dionaea": 8445,
    "http": 8080,
}

COWRIE_LOG_SUBPATH = "cowrie.json"
DIONAEA_LOG_SUBPATH = "dionaea.json"
HTTP_LOG_SUBPATH = "http_honeypot.json"

SIMULATION_MODE = os.getenv("HONEYPOT_SIMULATION", "false").lower() == "true"

# ATT&CK Navigator base URL
ATTACK_NAVIGATOR_URL = "https://mitre-attack.github.io/attack-navigator/"

GITHUB_REPO = "https://github.com/rod-trent/HPThreat"
