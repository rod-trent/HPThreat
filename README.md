# HPThreat - Honeypot Orchestration & Threat Intel MCP Server

**Turns Claude into a blue-team force-multiplier for early-warning threat intelligence.**

Deploy and monitor custom honeypots, capture attacker TTPs and IOCs, correlate with live threat feeds, and auto-generate Sigma detection rules — all through natural conversation with Claude.

## What It Does

| Capability | Details |
|---|---|
| **Deploy honeypots** | Cowrie (SSH/Telnet), Dionaea (multi-protocol), custom HTTP decoy via Docker |
| **Capture TTPs** | Maps attacker behavior to 15+ MITRE ATT&CK techniques automatically |
| **Extract IOCs** | IPs, file hashes, credentials, commands, reverse shells, C2 URLs |
| **Threat correlation** | AbuseIPDB, Feodo Tracker C2 blocklist, Emerging Threats rules |
| **Sigma rules** | Auto-generates YAML Sigma detection rules from captured attack patterns |
| **Reports** | Markdown and JSON threat intel reports with ATT&CK Navigator layers |
| **Simulation mode** | Fully functional without Docker — generates realistic mock attack data |

## Quick Start

### 1. Install

```bash
cd C:\Code\Honeypot
pip install -r requirements.txt
```

### 2. Configure (optional)

```bash
cp .env.example .env
# Edit .env to add your AbuseIPDB API key
```

### 3. Add to Claude Desktop

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "honeypot": {
      "command": "python",
      "args": ["C:\\Code\\Honeypot\\server.py"],
      "env": {
        "ABUSEIPDB_API_KEY": "your_key_here"
      }
    }
  }
}
```

### 4. Use with Claude

```
Deploy an SSH honeypot named "ssh-trap-01" on port 2222
```
```
Analyze what ssh-trap-01 has captured in the last 24 hours
```
```
Generate a threat intel report for ssh-trap-01
```
```
Export IOCs from ssh-trap-01 in STIX format
```

## MCP Tools

| Tool | Description |
|---|---|
| `deploy_honeypot` | Deploy a cowrie/dionaea/http honeypot container |
| `list_honeypots` | List all deployments with live status |
| `stop_honeypot` | Stop a honeypot (logs preserved) |
| `get_honeypot_logs` | Retrieve recent parsed log events |
| `analyze_capture` | IOC counts, top IPs, TTP summary |
| `export_ioc` | Export IOCs as JSON / CSV / STIX 2.1 |
| `generate_sigma_rule` | Generate Sigma YAML from attack data |
| `fetch_threat_intel` | Correlate IP/hash against threat feeds |
| `generate_report` | Full Markdown or JSON threat intel report |
| `correlate_ttps` | MITRE ATT&CK mapping + Navigator layer |

## Honeypot Types

### Cowrie (SSH/Telnet)
- Captures brute-force attempts, successful logins, commands executed, file downloads
- Docker image: `cowrie/cowrie:latest`
- Best for: credential spray detection, Linux malware capture

### Dionaea (Multi-protocol)
- Simulates FTP, HTTP, SMB, MSSQL, MySQL services
- Docker image: `dinotools/dionaea:latest`
- Best for: malware samples, exploit attempts, lateral movement detection

### HTTP Decoy
- Custom Flask-based web honeypot
- Logs path traversal, injection attempts, scanner fingerprints
- Best for: web application attack detection, recon activity

## Simulation Mode

No Docker? No problem. Set `HONEYPOT_SIMULATION=true` in `.env` or the environment.
The server generates realistic attack data (brute-force attempts, malware downloads,
reverse shells, scanner activity) so all 10 tools work fully for demos and testing.

## Requirements

- Python 3.11+
- Docker Desktop (optional — simulation mode works without it)
- AbuseIPDB API key (optional — free tier at abuseipdb.com)

## Architecture

```
server.py                  # FastMCP entry point, 10 tools
├── core/
│   ├── docker_manager.py  # Container lifecycle + simulation fallback
│   ├── state.py           # JSON-persisted honeypot registry
│   └── simulation.py      # Realistic mock event generator
├── parsers/               # Cowrie, Dionaea, HTTP log parsers
├── analysis/              # IOC extraction, TTP mapping, Sigma generation
├── intel/                 # AbuseIPDB, Feodo Tracker, Emerging Threats clients
├── exporters/             # JSON/CSV/STIX IOC export + report generation
└── docker/                # Docker Compose configs for each honeypot type
```

## License

MIT — See [HPThreat on GitHub](https://github.com/rod-trent/HPThreat)
