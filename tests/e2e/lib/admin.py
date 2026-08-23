import pathlib
import json
import os
import subprocess
import time
from typing import Any, Callable

import httpx


class Admin:
    def __init__(self, compose, base_url: str = "http://localhost:8080") -> None:
        self.compose = compose
        self.client = httpx.Client(base_url=base_url, timeout=10.0)
        self._token: str | None = None

    def login(self) -> None:
        email = os.environ.get("ADMIN_EMAIL", "owner@example.com")
        password = os.environ.get("ADMIN_PASSWORD") or os.environ.get("ADMIN_PASSWORD", "test")
        # fallback to .env
        try:
            if not password:
                env = pathlib.Path(".env").read_text()
                for line in env.splitlines():
                    if line.startswith("ADMIN_PASSWORD="):
                        password = line.split("=",1)[1]
        except Exception:
            password = "test"
        r = self.client.post("/api/v1/users/login", json={"email": email, "password": password})
        r.raise_for_status()
        body = r.json()
        assert "access_token" in body, f"bootstrap owner should not require MFA in e2e: {body}"
        self._token = body["access_token"]

    def _headers(self):
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

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
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                last = predicate()
                if last:
                    return last
            except Exception:
                pass
            time.sleep(interval)
        return last
