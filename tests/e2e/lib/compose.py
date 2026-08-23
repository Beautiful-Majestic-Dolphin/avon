import subprocess
import time
from typing import List, Optional


class Compose:
    def __init__(self, project: str = ""):
        self.base = ["docker", "compose", "-f", "docker-compose.yml", "-f", "tests/e2e/docker-compose.e2e.yml"]

    def _run(self, *args: str, timeout: int = 60) -> str:
        cmd = self.base + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr} {result.stdout}")
        return result.stdout

    def up(self):
        self._run("up", "-d", "--build", timeout=600)

    def down(self):
        try:
            self._run("down", "-v", timeout=60)
        except Exception:
            pass

    def exec(self, service: str, *cmd: str, timeout: int = 60) -> str:
        return self._run("exec", "-T", service, *cmd, timeout=timeout)

    def exec_capture(self, service: str, *cmd: str, timeout: int = 60) -> tuple[int, str]:
        """Run a command and return (exit code, output) instead of raising.

        Some checks are about a command *failing* — a cloned identity that must
        not open, a port that must not connect — and an exception loses the
        output that says why.
        """
        full = self.base + ["exec", "-T", service, *cmd]
        result = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return result.returncode, (result.stdout or "") + (result.stderr or "")

    def stop(self, service: str):
        self._run("stop", service)

    def start(self, service: str):
        self._run("start", service)

    def restart(self, service: str):
        self._run("restart", service)

    def logs(self, service: str) -> str:
        return self._run("logs", "--no-color", service)

    def metric(self, service: str, name: str, labels: Optional[dict] = None) -> float:
        from .metrics import metric as m
        return m(self, service, name, labels)
