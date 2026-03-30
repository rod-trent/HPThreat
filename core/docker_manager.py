"""Docker SDK wrapper with simulation-mode fallback."""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import DEFAULT_PORTS, HONEYPOT_IMAGES, LOG_DIR, SIMULATION_MODE
from core.simulation import BackgroundEventWriter, write_simulation_logs
from core.state import StateManager

try:
    import docker
    from docker.errors import DockerException, NotFound
    _DOCKER_AVAILABLE = True
except ImportError:
    _DOCKER_AVAILABLE = False


class DockerManager:
    def __init__(self, state: Optional[StateManager] = None):
        self.state = state
        self.simulation_mode = SIMULATION_MODE
        self._writers: dict[str, BackgroundEventWriter] = {}
        self._client = None

        if not SIMULATION_MODE and _DOCKER_AVAILABLE:
            try:
                self._client = docker.from_env()
                self._client.ping()
            except Exception:
                self.simulation_mode = True
                self._client = None

    @property
    def is_simulation(self) -> bool:
        return self.simulation_mode

    def deploy(self, honeypot_type: str, name: str, port: int, options: dict) -> dict:
        if honeypot_type not in HONEYPOT_IMAGES:
            return {"error": f"Unknown honeypot type '{honeypot_type}'. Choose: cowrie, dionaea, http"}

        log_dir = LOG_DIR / honeypot_type / name
        log_dir.mkdir(parents=True, exist_ok=True)

        if self.simulation_mode:
            return self._deploy_simulated(honeypot_type, name, port, options, log_dir)
        return self._deploy_docker(honeypot_type, name, port, options, log_dir)

    def _deploy_docker(self, honeypot_type: str, name: str, port: int, options: dict, log_dir: Path) -> dict:
        image = HONEYPOT_IMAGES[honeypot_type]
        port_bindings = self._build_port_bindings(honeypot_type, port)
        volumes = self._build_volumes(honeypot_type, name, log_dir)
        env = self._build_env(honeypot_type, name, options)

        try:
            container = self._client.containers.run(
                image,
                name=name,
                detach=True,
                ports=port_bindings,
                volumes=volumes,
                environment=env,
                restart_policy={"Name": "unless-stopped"},
            )
            return {
                "name": name,
                "type": honeypot_type,
                "container_id": container.id[:12],
                "status": "running",
                "port": port,
                "log_path": str(log_dir),
                "simulation": False,
                "deployed_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            return {"error": f"Docker deploy failed: {e}"}

    def _deploy_simulated(self, honeypot_type: str, name: str, port: int, options: dict, log_dir: Path) -> dict:
        fake_id = uuid.uuid4().hex[:12]
        # Write initial logs immediately
        write_simulation_logs(honeypot_type, name)
        # Start background writer
        writer = BackgroundEventWriter(honeypot_type, name, interval_seconds=30)
        writer.start()
        self._writers[name] = writer
        return {
            "name": name,
            "type": honeypot_type,
            "container_id": fake_id,
            "status": "running",
            "port": port,
            "log_path": str(log_dir),
            "simulation": True,
            "deployed_at": datetime.now(timezone.utc).isoformat(),
        }

    def stop(self, name: str, container_id: str) -> dict:
        # Stop background writer if present
        if name in self._writers:
            self._writers[name].stop()
            del self._writers[name]

        if self.simulation_mode:
            return {"name": name, "status": "stopped", "simulation": True}

        try:
            container = self._client.containers.get(container_id)
            container.stop(timeout=10)
            container.remove()
            return {"name": name, "status": "stopped", "simulation": False}
        except Exception as e:
            return {"error": f"Failed to stop container '{name}': {e}"}

    def get_container_status(self, name: str, container_id: str) -> str:
        if self.simulation_mode:
            return "running"
        try:
            container = self._client.containers.get(container_id)
            return container.status
        except Exception:
            return "unknown"

    def get_logs(self, honeypot_type: str, name: str, lines: int = 100) -> list[str]:
        from config import COWRIE_LOG_SUBPATH, DIONAEA_LOG_SUBPATH, HTTP_LOG_SUBPATH
        log_subpaths = {
            "cowrie": COWRIE_LOG_SUBPATH,
            "dionaea": DIONAEA_LOG_SUBPATH,
            "http": HTTP_LOG_SUBPATH,
        }
        log_file = LOG_DIR / honeypot_type / name / log_subpaths.get(honeypot_type, "honeypot.json")
        if log_file.exists():
            all_lines = log_file.read_text(encoding="utf-8").splitlines()
            return all_lines[-lines:] if lines > 0 else all_lines

        # Fallback to docker logs
        if not self.simulation_mode and self._client:
            try:
                container = self._client.containers.get(name)
                raw = container.logs(tail=lines).decode("utf-8", errors="replace")
                return raw.splitlines()
            except Exception:
                pass
        return []

    def list_running(self) -> list[dict]:
        if self.simulation_mode or not self._client:
            return []
        try:
            return [
                {"name": c.name, "id": c.id[:12], "status": c.status}
                for c in self._client.containers.list()
            ]
        except Exception:
            return []

    # ── helpers ─────────────────────────────────────────────────────────────

    def _build_port_bindings(self, honeypot_type: str, port: int) -> dict:
        if honeypot_type == "cowrie":
            return {"2222/tcp": port, "2223/tcp": port + 1}
        elif honeypot_type == "dionaea":
            base = port
            return {
                "21/tcp": base, "80/tcp": base + 80, "443/tcp": base + 443,
                "445/tcp": base + 445, "1433/tcp": base + 1433, "3306/tcp": base + 3306,
            }
        else:  # http
            return {"8080/tcp": port}

    def _build_volumes(self, honeypot_type: str, name: str, log_dir: Path) -> dict:
        container_paths = {
            "cowrie": "/cowrie/var/log/cowrie",
            "dionaea": "/opt/dionaea/var/log/dionaea",
            "http": "/app/logs",
        }
        return {str(log_dir): {"bind": container_paths.get(honeypot_type, "/logs"), "mode": "rw"}}

    def _build_env(self, honeypot_type: str, name: str, options: dict) -> list[str]:
        env = [f"HONEYPOT_NAME={name}"]
        if honeypot_type == "cowrie":
            hostname = options.get("hostname", "svr04")
            env.append(f"COWRIE_HOSTNAME={hostname}")
        return env
