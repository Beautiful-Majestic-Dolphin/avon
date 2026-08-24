import subprocess
import time
from pathlib import Path
from typing import List, Optional

# self.base below names the compose files with paths relative to the repo
# root (matching the runner's own COMPOSE invocation). Scenarios are run by
# pytest with cwd=tests/e2e (both `cd tests/e2e && uv run pytest ...` and the
# runner's own `_run_pytest(cwd=HERE)`), so every subprocess this class
# launches must pin cwd=REPO explicitly -- relying on the caller's cwd would
# resolve "docker-compose.yml" against tests/e2e instead of the repo root.
REPO = Path(__file__).resolve().parents[3]


class HarnessError(RuntimeError):
    """The harness itself failed — docker, a missing service, a missing binary.

    Distinct from an observed negative. A scenario asserting that something is
    blocked must never be satisfied by this.
    """


class Compose:
    def __init__(self, project: str = ""):
        self.base = ["docker", "compose", "-f", "docker-compose.yml", "-f", "tests/e2e/docker-compose.e2e.yml"]

    def _run(self, *args: str, timeout: int = 60) -> str:
        cmd = self.base + list(args)
        result = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, timeout=timeout)
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
        """Run a command and return (exit code, output).

        Raises HarnessError if docker could not run the command at all.
        """
        full = self.base + ["exec", "-T", service, *cmd]
        result = subprocess.run(full, cwd=REPO, capture_output=True, text=True,
                                timeout=timeout)
        combined = (result.stdout or "") + (result.stderr or "")
        harness_failures = (
            "No such service",
            "is not running",
            "Cannot connect to the Docker daemon",
            "executable file not found",
        )
        if any(marker in combined for marker in harness_failures):
            raise HarnessError(
                f"harness could not run {' '.join(cmd)} in {service}: {combined.strip()}"
            )
        return result.returncode, combined

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

    def run_in_new_container(self, image, *cmd, network, volumes=None,
                             env=None, timeout=120):
        """Run a one-shot container on the stack's network.

        Layer 2 needs an agent binary but no TUN and no NET_ADMIN, so it uses a
        throwaway container rather than a long-lived compose service. Returns
        (exit code, combined output); a docker failure raises.
        """
        args = ["docker", "run", "--rm", "--network", network]
        for source, dest in (volumes or {}).items():
            args += ["-v", f"{source}:{dest}:ro"]
        for key, value in (env or {}).items():
            args += ["-e", f"{key}={value}"]
        args += ["--entrypoint", cmd[0], image, *cmd[1:]]
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=timeout)
        combined = (result.stdout or "") + (result.stderr or "")
        if "Cannot connect to the Docker daemon" in combined:
            raise RuntimeError("docker is not available: " + combined)
        return result.returncode, combined

    def mint_token(self, max_uses=1, expires_in="1 hour", tenant=None):
        """Create an enrollment token directly in Postgres and return it.

        The bootstrap token is max_uses=100 and shared, so tests that need a
        specific reuse or expiry policy must mint their own or they destroy each
        other's preconditions. The admin API would be the nicer interface but it
        belongs to layer 4; layer 2 has Postgres right here.

        The token is stored as sha256 of its own string, matching
        `store::hash_token` on the Rust side.
        """
        import hashlib
        import secrets

        token = secrets.token_hex(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        tenant_sql = (
            f"'{tenant}'::uuid" if tenant else "(SELECT id FROM tenants LIMIT 1)"
        )
        sql = (
            "INSERT INTO enrollment_tokens "
            "(tenant_id, token_hash, device_name, max_uses, expires_at) VALUES ("
            f"{tenant_sql}, decode('{digest}', 'hex'), NULL, {int(max_uses)}, "
            f"now() + interval '{expires_in}')"
        )
        code, out = self.exec_capture(
            "postgres", "psql", "-U", "avon", "-d", "avon", "-v", "ON_ERROR_STOP=1",
            "-c", sql,
        )
        if code != 0:
            raise HarnessError(f"could not mint an enrollment token: {out}")
        return token
