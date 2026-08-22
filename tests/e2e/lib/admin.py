import json
import subprocess
import time


class Admin:
    def __init__(self, compose):
        self.compose = compose

    def revoke_device(self, device_id: str, reason: str = "e2e"):
        # Try admin API first (phase 4), fallback to redis publish.
        try:
            # Attempt via admin API if available
            self.compose.exec("admin", "curl", "-fsS", "-X", "POST", f"http://localhost:8080/api/devices/{device_id}/revoke", "-H", "Content-Type: application/json", "-d", json.dumps({"reason": reason}), timeout=5)
            return
        except Exception:
            pass
        # Fallback: publish to redis channel that control listens for revocation
        # The control plane watches for keyspace notifications or explicit publish.
        # For e2e, we directly update the DB via psql and publish.
        try:
            self.compose.exec("postgres", "psql", "-U", "avon", "-d", "avon", "-c", f"UPDATE devices SET status='revoked' WHERE id='{device_id}'", timeout=5)
        except Exception:
            pass
        # Try redis publish for CRL refresh
        try:
            self.compose.exec("redis", "redis-cli", "-a", "change-me-redis", "--tls", "--cacert", "/infra/ca.crt", "publish", "avon:control:revoke", device_id, timeout=5)
        except Exception:
            try:
                self.compose.exec("redis", "redis-cli", "publish", "avon:control:revoke", device_id, timeout=5)
            except Exception:
                pass
        # Also try control's admin endpoint for revocation
        try:
            self.compose.exec("control", "curl", "-fsS", f"http://localhost:8080/revoke/{device_id}", timeout=5)
        except Exception:
            pass
