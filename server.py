"""
HPThreat - Honeypot Orchestration & Threat Intel MCP Server
https://github.com/rod-trent/HPThreat

Exposes 10 tools via MCP for deploying honeypots, capturing attacker TTPs/IOCs,
correlating with threat feeds, and generating Sigma rules and reports.
"""

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

from analysis.correlator import TTPCorrelator
from analysis.ioc_extractor import IOCExtractor
from analysis.sigma_generator import SigmaGenerator
from analysis.ttp_mapper import TTPMapper
from config import LOG_DIR
from core.docker_manager import DockerManager
from core.state import StateManager
from exporters.ioc_exporter import IOCExporter
from exporters.report_generator import ReportGenerator
from intel.abuseipdb import AbuseIPDBClient
from intel.emerging_threats import EmergingThreatsClient
from intel.feodo_tracker import FeodoTrackerClient
from parsers.cowrie_parser import CowrieParser
from parsers.dionaea_parser import DionaeaParser
from parsers.http_parser import HTTPParser


@dataclass
class AppContext:
    docker: DockerManager
    state: StateManager


@asynccontextmanager
async def lifespan(server: FastMCP):
    state = StateManager()
    state.load()
    docker = DockerManager(state=state)
    yield AppContext(docker=docker, state=state)
    state.save()


mcp = FastMCP(
    "Honeypot Orchestration & Threat Intel",
    lifespan=lifespan,
    instructions=(
        "MCP server for deploying and monitoring honeypots, capturing attacker TTPs/IOCs, "
        "correlating with threat feeds, and generating Sigma rules and reports. "
        "Source: https://github.com/rod-trent/HPThreat"
    ),
)

# ── Module singletons ────────────────────────────────────────────────────────
_ioc_extractor = IOCExtractor()
_ttp_mapper = TTPMapper()
_sigma_gen = SigmaGenerator()
_correlator = TTPCorrelator()
_ioc_exporter = IOCExporter()
_report_gen = ReportGenerator()
_abuseipdb = AbuseIPDBClient()
_feodo = FeodoTrackerClient()
_et = EmergingThreatsClient()
_cowrie_parser = CowrieParser()
_dionaea_parser = DionaeaParser()
_http_parser = HTTPParser()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_events(hp_entry: dict, timeframe_hours: int) -> list[dict]:
    hp_type = hp_entry["type"]
    name = hp_entry["name"]

    if hp_type == "cowrie":
        log_file = LOG_DIR / "cowrie" / name / "cowrie.json"
        events = _cowrie_parser.parse_file(log_file)
        return _cowrie_parser.filter_by_timeframe(events, timeframe_hours)
    elif hp_type == "dionaea":
        log_dir = LOG_DIR / "dionaea" / name
        return _dionaea_parser.parse(log_dir, timeframe_hours)
    elif hp_type == "http":
        log_file = LOG_DIR / "http" / name / "http_honeypot.json"
        return _http_parser.parse_file(log_file, timeframe_hours)
    return []


def _summarize(hp_entry: dict, events: list[dict]) -> dict:
    hp_type = hp_entry["type"]
    if hp_type == "cowrie":
        return _cowrie_parser.summarize(events)
    elif hp_type == "dionaea":
        return _dionaea_parser.summarize(events)
    elif hp_type == "http":
        return _http_parser.summarize(events)
    return {"total_events": len(events)}


# ── Tool 1: deploy_honeypot ──────────────────────────────────────────────────

@mcp.tool()
def deploy_honeypot(
    honeypot_type: str,
    name: str,
    port: int = 2222,
    options: str = "{}",
) -> dict:
    """Deploy a honeypot container.

    Args:
        honeypot_type: 'cowrie' (SSH/Telnet brute-force), 'dionaea' (multi-protocol malware),
                       or 'http' (web application decoy).
        name: Unique identifier for this instance (e.g., 'ssh-prod-01').
        port: Primary host port to bind (default 2222 for cowrie, 8445 for dionaea, 8080 for http).
        options: JSON string of additional options. Supported keys:
                 - cowrie: {"hostname": "svr04"}
                 - http: {"banner": "Apache/2.4"}
    Returns deployment details including container_id, log_path, and simulation flag.
    Works in simulation mode when Docker is unavailable.
    """
    ctx: AppContext = mcp.get_context().request_context.lifespan_context

    if not name or not name.replace("-", "").replace("_", "").isalnum():
        return {"error": "Invalid name. Use alphanumeric characters, hyphens, and underscores only."}

    if ctx.state.get(name):
        return {"error": f"Honeypot '{name}' already exists. Stop it first or choose a different name."}

    try:
        opts = json.loads(options)
    except json.JSONDecodeError:
        return {"error": f"Invalid JSON in options: {options}"}

    result = ctx.docker.deploy(honeypot_type, name, port, opts)
    if "error" in result:
        return result

    entry = {
        "name": name,
        "type": honeypot_type,
        "container_id": result.get("container_id", ""),
        "port": port,
        "status": "running",
        "deployed_at": result.get("deployed_at", datetime.now(timezone.utc).isoformat()),
        "log_path": result.get("log_path", ""),
        "options": opts,
        "simulation": result.get("simulation", False),
    }
    ctx.state.register(entry)
    return result


# ── Tool 2: list_honeypots ───────────────────────────────────────────────────

@mcp.tool()
def list_honeypots() -> dict:
    """List all deployed honeypots with their status, type, port, and deployment time.
    Reconciles the state file with live Docker container status.
    Returns a list of honeypot entries plus a count summary."""
    ctx: AppContext = mcp.get_context().request_context.lifespan_context
    entries = ctx.state.list_all()

    # Refresh status from Docker for running entries
    for entry in entries:
        if entry.get("status") == "running" and not entry.get("simulation"):
            live_status = ctx.docker.get_container_status(entry["name"], entry.get("container_id", ""))
            if live_status != entry.get("status"):
                ctx.state.update_status(entry["name"], live_status)
                entry["status"] = live_status

    simulation_mode = ctx.docker.is_simulation
    return {
        "honeypots": entries,
        "count": len(entries),
        "running": sum(1 for e in entries if e.get("status") == "running"),
        "simulation_mode": simulation_mode,
        "docker_available": not simulation_mode,
    }


# ── Tool 3: stop_honeypot ────────────────────────────────────────────────────

@mcp.tool()
def stop_honeypot(name: str) -> dict:
    """Stop and remove a running honeypot container.
    Preserves all log files for post-analysis.
    Args:
        name: The honeypot name as provided during deploy.
    """
    ctx: AppContext = mcp.get_context().request_context.lifespan_context
    entry = ctx.state.get(name)
    if not entry:
        return {"error": f"Honeypot '{name}' not found. Use list_honeypots to see active deployments."}

    result = ctx.docker.stop(name, entry.get("container_id", ""))
    if "error" in result:
        return result

    ctx.state.update_status(name, "stopped")
    return {
        "name": name,
        "status": "stopped",
        "log_path": entry.get("log_path", ""),
        "message": f"Honeypot '{name}' stopped. Logs preserved at {entry.get('log_path', 'data/logs/')}",
    }


# ── Tool 4: get_honeypot_logs ────────────────────────────────────────────────

@mcp.tool()
def get_honeypot_logs(name: str, lines: int = 50) -> dict:
    """Retrieve the most recent log entries from a honeypot as parsed JSON events.
    Args:
        name: Honeypot name.
        lines: Number of most-recent log lines to return (default 50, max 500).
    """
    ctx: AppContext = mcp.get_context().request_context.lifespan_context
    entry = ctx.state.get(name)
    if not entry:
        return {"error": f"Honeypot '{name}' not found."}

    lines = min(lines, 500)
    raw_lines = ctx.docker.get_logs(entry["type"], name, lines)

    parsed = []
    for line in raw_lines:
        if not line.strip():
            continue
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            parsed.append({"raw": line})

    return {
        "name": name,
        "type": entry["type"],
        "event_count": len(parsed),
        "events": parsed,
    }


# ── Tool 5: analyze_capture ──────────────────────────────────────────────────

@mcp.tool()
def analyze_capture(name: str, timeframe_hours: int = 24) -> dict:
    """Analyze honeypot capture data: IOC counts, top IPs, TTP summary, attack timeline.
    Args:
        name: Honeypot name.
        timeframe_hours: How many hours back to analyze (default 24).
    Returns structured analysis without full IOC export (use export_ioc for that).
    """
    ctx: AppContext = mcp.get_context().request_context.lifespan_context
    entry = ctx.state.get(name)
    if not entry:
        return {"error": f"Honeypot '{name}' not found."}

    events = _get_events(entry, timeframe_hours)
    if not events:
        return {
            "name": name,
            "timeframe_hours": timeframe_hours,
            "message": "No events found in the specified timeframe.",
            "summary": {},
        }

    summary = _summarize(entry, events)
    iocs = _ioc_extractor.extract_all(events, name)
    ttps = _ttp_mapper.map_ttps(events)

    return {
        "name": name,
        "type": entry["type"],
        "timeframe_hours": timeframe_hours,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "ttp_count": len(ttps),
        "ttps_detected": [{"id": t["technique_id"], "name": t["technique_name"], "severity": t["severity"]} for t in ttps],
        "ioc_counts": {
            "total": len(iocs),
            "ips": sum(1 for i in iocs if i.type == "ip"),
            "hashes": sum(1 for i in iocs if i.type.startswith("hash")),
            "credentials": sum(1 for i in iocs if i.type == "credential"),
            "commands": sum(1 for i in iocs if i.type == "command"),
            "urls": sum(1 for i in iocs if i.type == "url"),
            "reverse_shells": sum(1 for i in iocs if i.type == "reverse_shell"),
        },
        "top_source_ips": summary.get("top_source_ips", [])[:10],
    }


# ── Tool 6: export_ioc ───────────────────────────────────────────────────────

@mcp.tool()
def export_ioc(name: str, format: str = "json", timeframe_hours: int = 24) -> dict:
    """Export extracted IOCs from a honeypot in the specified format.
    Args:
        name: Honeypot name.
        format: Output format - 'json' (default), 'csv', or 'stix' (STIX 2.1 Bundle).
        timeframe_hours: How many hours back to include (default 24).
    Returns the IOC data inline. Large exports are also saved to data/reports/.
    """
    ctx: AppContext = mcp.get_context().request_context.lifespan_context
    entry = ctx.state.get(name)
    if not entry:
        return {"error": f"Honeypot '{name}' not found."}

    if format not in ("json", "csv", "stix"):
        return {"error": "Invalid format. Choose: json, csv, stix"}

    events = _get_events(entry, timeframe_hours)
    iocs = _ioc_extractor.extract_all(events, name)

    if format == "json":
        content = _ioc_exporter.export_json(iocs)
    elif format == "csv":
        content = _ioc_exporter.export_csv(iocs)
    else:  # stix
        content = _ioc_exporter.export_stix(iocs, name)

    # Save to reports dir
    save_path = _report_gen.save(content, f"{name}_iocs", format)

    return {
        "name": name,
        "format": format,
        "ioc_count": len(iocs),
        "timeframe_hours": timeframe_hours,
        "saved_to": str(save_path),
        "content": content,
    }


# ── Tool 7: generate_sigma_rule ──────────────────────────────────────────────

@mcp.tool()
def generate_sigma_rule(attack_data_json: str) -> dict:
    """Generate a Sigma detection rule from attack data.
    Args:
        attack_data_json: JSON string with fields:
            - technique_id (str): e.g. "T1110.001"
            - technique_name (str): e.g. "Brute Force: Password Guessing"
            - tactic_name (str): e.g. "Credential Access"
            - iocs (list of str): IP addresses or keywords
            - honeypot_type (str): "cowrie", "dionaea", or "http"
            - source_name (str): honeypot name
            - severity (str): "critical", "high", "medium", or "low"
    Returns the Sigma rule as YAML plus a rule_id UUID.
    """
    try:
        attack_data = json.loads(attack_data_json)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}

    return _sigma_gen.generate(attack_data)


# ── Tool 8: fetch_threat_intel ───────────────────────────────────────────────

@mcp.tool()
def fetch_threat_intel(ioc: str, ioc_type: str = "ip") -> dict:
    """Correlate an IOC against AbuseIPDB, Feodo Tracker C2 list, and Emerging Threats.
    Args:
        ioc: The indicator value - IP address, file hash, or keyword.
        ioc_type: 'ip' (default), 'hash', or 'keyword'.
    Requires ABUSEIPDB_API_KEY environment variable for AbuseIPDB lookups.
    Returns aggregated reputation data from all sources.
    """
    result: dict = {"ioc": ioc, "ioc_type": ioc_type, "sources": {}}

    if ioc_type == "ip":
        # AbuseIPDB
        abuse_result = _abuseipdb.check_ip(ioc)
        result["sources"]["abuseipdb"] = abuse_result

        # Feodo Tracker
        feodo_result = _feodo.is_known_c2(ioc)
        result["sources"]["feodo_tracker"] = feodo_result or {"is_c2": False, "ip": ioc}

        # Emerging Threats
        et_matches = _et.match_ip(ioc)
        result["sources"]["emerging_threats"] = {
            "ip": ioc,
            "matching_rules": et_matches[:10],
            "match_count": len(et_matches),
        }

        # Overall verdict
        abuse_score = abuse_result.get("abuse_score", 0) if "error" not in abuse_result else 0
        is_c2 = feodo_result is not None
        et_matches_count = len(et_matches)
        if is_c2 or abuse_score >= 75 or et_matches_count >= 3:
            verdict = "MALICIOUS"
        elif abuse_score >= 25 or et_matches_count >= 1:
            verdict = "SUSPICIOUS"
        else:
            verdict = "UNKNOWN"
        result["verdict"] = verdict

    elif ioc_type == "hash":
        et_matches = _et.search_keyword(ioc[:20])
        result["sources"]["emerging_threats"] = {
            "hash": ioc,
            "matching_rules": et_matches[:5],
            "match_count": len(et_matches),
        }
        result["verdict"] = "SUSPICIOUS" if et_matches else "UNKNOWN"

    elif ioc_type == "keyword":
        et_matches = _et.search_keyword(ioc)
        result["sources"]["emerging_threats"] = {
            "keyword": ioc,
            "matching_rules": et_matches[:10],
            "match_count": len(et_matches),
        }
        result["verdict"] = "FOUND" if et_matches else "NOT_FOUND"

    else:
        return {"error": f"Unknown ioc_type '{ioc_type}'. Choose: ip, hash, keyword"}

    return result


# ── Tool 9: generate_report ──────────────────────────────────────────────────

@mcp.tool()
def generate_report(name: str, timeframe_hours: int = 24, format: str = "markdown") -> dict:
    """Generate a comprehensive threat intelligence report for a honeypot.
    Includes IOCs, TTPs, kill chain analysis, threat feed correlation, and Sigma rules.
    Args:
        name: Honeypot name.
        timeframe_hours: Report coverage window in hours (default 24).
        format: 'markdown' (default, human-readable) or 'json' (machine-readable).
    Report is saved to data/reports/ and content returned inline.
    """
    ctx: AppContext = mcp.get_context().request_context.lifespan_context
    entry = ctx.state.get(name)
    if not entry:
        return {"error": f"Honeypot '{name}' not found."}

    if format not in ("markdown", "json"):
        return {"error": "Invalid format. Choose: markdown, json"}

    events = _get_events(entry, timeframe_hours)
    summary = _summarize(entry, events) if events else {}
    iocs = _ioc_extractor.extract_all(events, name)
    ttps = _ttp_mapper.map_ttps(events)
    correlation = _correlator.correlate(ttps)
    sigma_rules = _sigma_gen.generate_bulk(ttps[:5], name, entry["type"])

    # Correlate top IPs with threat feeds
    unique_ips = list({i.value for i in iocs if i.type == "ip"})[:10]
    ip_results = []
    for ip in unique_ips:
        abuse = _abuseipdb.check_ip(ip)
        feodo = _feodo.is_known_c2(ip)
        ip_results.append({
            "ip": ip,
            "country_code": abuse.get("country_code", ""),
            "isp": abuse.get("isp", ""),
            "abuse_score": abuse.get("abuse_score", 0),
            "feodo_c2": feodo is not None,
            "feodo_malware": feodo.get("malware", "") if feodo else "",
        })

    report_data = {
        "honeypot_name": name,
        "honeypot_type": entry["type"],
        "timeframe_hours": timeframe_hours,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "ttps": ttps,
        "iocs": [i.to_dict() for i in iocs],
        "correlation": correlation,
        "sigma_rules": sigma_rules,
        "threat_intel": {"ip_results": ip_results},
    }

    if format == "markdown":
        content = _report_gen.generate_markdown(report_data)
    else:
        content = _report_gen.generate_json(report_data)

    save_path = _report_gen.save(content, name, format)

    return {
        "name": name,
        "format": format,
        "timeframe_hours": timeframe_hours,
        "saved_to": str(save_path),
        "event_count": len(events),
        "ttp_count": len(ttps),
        "ioc_count": len(iocs),
        "sigma_rules_generated": len(sigma_rules),
        "sophistication": correlation.get("sophistication_label", "Unknown"),
        "content": content,
    }


# ── Tool 10: correlate_ttps ──────────────────────────────────────────────────

@mcp.tool()
def correlate_ttps(name: str) -> dict:
    """Map all observed attack behaviors to MITRE ATT&CK techniques and tactics.
    Includes kill chain stage analysis, ATT&CK Navigator layer JSON, and
    attack sophistication scoring.
    Args:
        name: Honeypot name to analyze (uses all available logs, no timeframe limit).
    """
    ctx: AppContext = mcp.get_context().request_context.lifespan_context
    entry = ctx.state.get(name)
    if not entry:
        return {"error": f"Honeypot '{name}' not found."}

    # Use full log history (168 hours default)
    from config import LOG_RETENTION_HOURS
    events = _get_events(entry, LOG_RETENTION_HOURS)
    ttps = _ttp_mapper.map_ttps(events)
    correlation = _correlator.correlate(ttps)
    navigator_layer = _ttp_mapper.build_navigator_layer(ttps, name)

    return {
        "name": name,
        "type": entry["type"],
        "total_events_analyzed": len(events),
        "ttps_detected": ttps,
        "correlation": correlation,
        "navigator_layer": navigator_layer,
        "navigator_url": "https://mitre-attack.github.io/attack-navigator/",
        "note": "Paste navigator_layer JSON into ATT&CK Navigator to visualize the kill chain.",
    }


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import os as _os

    # Railway (and most PaaS) inject PORT; default transport to HTTP when it's set
    _railway_port = _os.getenv("PORT")
    _default_transport = "streamable-http" if _railway_port else "stdio"
    _default_host = "0.0.0.0" if _railway_port else "127.0.0.1"
    _default_port = int(_railway_port) if _railway_port else 8000

    parser = argparse.ArgumentParser(description="HPThreat MCP Server")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default=_default_transport)
    parser.add_argument("--host", default=_default_host)
    parser.add_argument("--port", type=int, default=_default_port)
    args = parser.parse_args()

    if args.transport == "streamable-http":
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")
