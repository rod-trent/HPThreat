import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from config import STATE_FILE


class StateManager:
    def __init__(self, path: Path = STATE_FILE):
        self._path = path
        self._lock = threading.Lock()
        self._state: dict = {}

    def load(self):
        if self._path.exists():
            try:
                self._state = json.loads(self._path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._state = {}
        else:
            self._state = {}

    def save(self):
        with self._lock:
            self._path.write_text(
                json.dumps(self._state, indent=2, default=str), encoding="utf-8"
            )

    def register(self, entry: dict):
        with self._lock:
            self._state[entry["name"]] = entry
        self.save()

    def update_status(self, name: str, status: str):
        with self._lock:
            if name in self._state:
                self._state[name]["status"] = status
                self._state[name]["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.save()

    def get(self, name: str) -> Optional[dict]:
        return self._state.get(name)

    def remove(self, name: str):
        with self._lock:
            self._state.pop(name, None)
        self.save()

    def list_all(self) -> list[dict]:
        return list(self._state.values())
