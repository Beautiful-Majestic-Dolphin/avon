import pathlib
import json
import os
import subprocess
import time
from typing import Any, Callable

import httpx


class _BearerAuth(httpx.Auth):
    """Attach the admin bearer token, logging in on demand and once more if the
    token has expired. The access token lives 15 minutes and a full walk builds
    for longer than that before it reaches the policy layer, so a single login
    at fixture setup would 401 halfway through. This logs in lazily and retries
    a 401 exactly once, transparently to every call."""

    def __init__(self, admin: "Admin") -> None:
        self.admin = admin

    def auth_flow(self, request):
        if not self.admin._token:
            self.admin.login()
        request.headers["Authorization"] = f"Bearer {self.admin._token}"
        response = yield request
        if response.status_code == 401:
            self.admin.login()
            request.headers["Authorization"] = f"Bearer {self.admin._token}"
            yield request


class Admin:
    def __init__(self, compose, base_url: str = "http://localhost:8080") -> None:
        self.compose = compose
        # `client` carries auth automatically; `_login_client` must not, or
        # logging in would recurse through the auth flow.
        self._login_client = httpx.Client(base_url=base_url, timeout=10.0)
        self.client = httpx.Client(base_url=base_url, timeout=10.0, auth=_BearerAuth(self))
        self._token: str | None = None

    def login(self) -> None:
        email = os.environ.get("ADMIN_EMAIL", "owner@example.com")
        password = os.environ.get("ADMIN_PASSWORD", "")
        # Fall back to the repo-root .env, which is where docker compose reads
        # ADMIN_PASSWORD from and where the bootstrap owner's password comes
        # from. pytest runs with cwd=tests/e2e, so a bare ".env" resolves to a
        # file that does not exist and login would send an empty password and
        # 401. Resolve it against the repo root (this file is tests/e2e/lib/).
        if not password:
            env_path = pathlib.Path(__file__).resolve().parents[3] / ".env"
            try:
                for line in env_path.read_text().splitlines():
                    if line.startswith("ADMIN_PASSWORD="):
                        password = line.split("=", 1)[1].strip()
                        break
            except Exception:
                pass
        r = self._login_client.post(
            "/api/v1/users/login", json={"email": email, "password": password}
        )
        r.raise_for_status()
        body = r.json()
        assert "access_token" in body, f"bootstrap owner should not require MFA in e2e: {body}"
        self._token = body["access_token"]

    def _headers(self):
        # Auth is applied by the client's auth flow; kept for call sites that
        # still pass headers=self._headers(), where it is now a harmless no-op.
        return {}

    def create_pod(self, name: str) -> str:
        r = self.client.post("/api/v1/pods/", json={"name": name}, headers=self._headers())
        r.raise_for_status()
        return r.json()["id"]

    def add_device_to_pod(self, device_id: str, pod_id: str) -> None:
        r = self.client.post(f"/api/v1/pods/{pod_id}/devices", json={"device_id": device_id}, headers=self._headers())
        r.raise_for_status()

    def create_policy(self, spec: dict, name: str | None = None) -> dict:
        import uuid
        payload = {"name": name or f"policy-{uuid.uuid4().hex[:6]}", "spec": spec}
        r = self.client.post("/api/v1/policies/", json=payload, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def disable_policy(self, policy_id: str) -> None:
        r = self.client.post(f"/api/v1/policies/{policy_id}/disable", headers=self._headers())
        r.raise_for_status()

    def list_policies(self) -> list[dict]:
        r = self.client.get("/api/v1/policies/", headers=self._headers())
        r.raise_for_status()
        body = r.json()
        return body.get("items", body) if isinstance(body, dict) else body

    def delete_policy(self, policy_id: str) -> None:
        self.client.delete(f"/api/v1/policies/{policy_id}", headers=self._headers())

    def list_pods(self) -> list[dict]:
        r = self.client.get("/api/v1/pods/", headers=self._headers())
        r.raise_for_status()
        body = r.json()
        return body.get("items", body) if isinstance(body, dict) else body

    def delete_pod(self, pod_id: str) -> None:
        self.client.delete(f"/api/v1/pods/{pod_id}", headers=self._headers())

    def reset_policies_and_pods(self) -> None:
        """Return the tenant to unconfigured: remove every policy and pod.

        The e2e stack is shared across scenarios and layers, and policies
        persist in the database. Without this, a `source: any` deny authored by
        one scenario silently denies every later scenario's traffic, and a
        tenant that any scenario configured never returns to the permissive
        unconfigured state the data-plane layer relies on. Best-effort: a
        failure to delete one item must not fail the scenario that is only
        trying to clean up.
        """
        for policy in self.list_policies():
            pid = policy.get("id") if isinstance(policy, dict) else policy
            if pid:
                try:
                    self.delete_policy(pid)
                except Exception:
                    pass
        for pod in self.list_pods():
            pid = pod.get("id") if isinstance(pod, dict) else pod
            if pid:
                try:
                    self.delete_pod(pid)
                except Exception:
                    pass

    def explain(self, device_id: str, destination: str, protocol: str, port: int) -> dict:
        r = self.client.post("/api/v1/policies/explain", json={"device_id": device_id, "destination": destination, "protocol": protocol, "port": port}, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def create_enroll_token(self, **kwargs) -> str:
        r = self.client.post("/api/v1/devices/enroll-tokens", json=kwargs, headers=self._headers())
        r.raise_for_status()
        return r.json()["token"]

    def pending_devices(self) -> list[dict]:
        r = self.client.get("/api/v1/devices?status=pending", headers=self._headers())
        r.raise_for_status()
        return r.json().get("items", [])

    def approve_device(self, device_id: str) -> None:
        r = self.client.post(f"/api/v1/devices/{device_id}/approve", headers=self._headers())
        r.raise_for_status()

    def revoke_device(self, device_id: str, reason: str = "e2e") -> None:
        try:
            r = self.client.post(f"/api/v1/devices/{device_id}/revoke", json={"reason": reason}, headers=self._headers())
            r.raise_for_status()
            return
        except Exception:
            pass
        # fallback to compose exec as before
        try:
            self.compose.exec("postgres", "psql", "-U", "avon", "-d", "avon", "-c", f"UPDATE devices SET status='revoked' WHERE id='{device_id}'")
        except Exception:
            pass

    def device(self, device_id: str) -> dict:
        r = self.client.get(f"/api/v1/devices/{device_id}", headers=self._headers())
        r.raise_for_status()
        return r.json()

    def wait_until(self, predicate, timeout: float = 10.0, interval: float = 0.2):
        """Poll `predicate` until it returns something truthy, and return it.

        A timeout raises AssertionError carrying the last value seen: a caller
        that writes `admin.wait_until(lambda: a.tcp_open(...))` and nothing
        else is asserting that it happened, and before this raised the
        scenario passed whether it happened or not. HarnessError propagates
        for the same reason it does everywhere else -- a harness that cannot
        run the probe has observed nothing. Other exceptions (the admin API
        mid-restart, a device row not there yet) are the things being waited
        out, and are swallowed until the deadline.
        """
        from lib.compose import HarnessError

        deadline = time.time() + timeout
        last: Any = None
        last_error: Exception | None = None
        while time.time() < deadline:
            try:
                last = predicate()
                if last:
                    return last
            except HarnessError:
                raise
            except Exception as e:  # noqa: BLE001 - polling through transient failures
                last_error = e
            time.sleep(interval)
        raise AssertionError(
            f"condition not met within {timeout}s; last value {last!r}"
            + (f"; last error {last_error!r}" if last_error else "")
        )
