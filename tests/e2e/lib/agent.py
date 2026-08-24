import json
import time
import subprocess


class Agent:
    def __init__(self, compose, service: str):
        self.compose = compose
        self.service = service

    def status(self) -> dict:
        out = self.compose.exec(self.service, "avon-agent", "status", "--json")
        return json.loads(out)

    def wait_connected(self, timeout: int = 120) -> dict:
        deadline = time.time() + timeout
        last = {}
        while time.time() < deadline:
            try:
                st = self.status()
                last = st
                if st.get("state") == "connected":
                    return st
            except Exception:
                pass
            time.sleep(1)
        raise AssertionError(f"{self.service} never reached connected: {last}")

    def curl(self, url: str, timeout: int = 5) -> str:
        return self.compose.exec(self.service, "curl", "-fsS", "--max-time", str(timeout), url, timeout=timeout + 5)

    def ping(self, ip: str, count: int = 3) -> bool:
        code, _ = self.compose.exec_capture(
            self.service, "ping", "-c", str(count), "-W", "2", ip, timeout=15
        )
        return code == 0

    def overlay_ip(self) -> str:
        st = self.status()
        # overlay_v4 is like 100.64.0.2/32 or 100.64.0.2
        v4 = st.get("overlay_v4") or ""
        return v4.split("/")[0]

    def device_id(self) -> str:
        return self.status().get("device_id") or ""

    def key_provider(self) -> str:
        """Which keystore holds this device's identity: software, tpm2, ..."""
        return self.status().get("key_provider", "unknown")

    def attestation_state(self) -> str:
        """The control plane's verdict, as the agent last heard it."""
        return self.status().get("attestation_state", "none")

    def protected_route_leaks(self, host: str) -> bool:
        """True if a packet to `host` would leave by a non-tunnel interface.

        `ip route get` reports the interface the kernel would choose; the
        firewall's job is to make sure that is either the tunnel or nothing.
        """
        rc, out = self.compose.exec_capture(self.service, "ip", "route", "get", host)
        if rc != 0:
            return False  # unroutable is exactly what fail-closed looks like
        return "dev avon" not in out


    def tcp_open(self, ip: str, port: int, timeout: int = 2) -> bool:
        """True if the port accepted a connection, False if it refused.

        A harness failure raises rather than returning False — otherwise a
        broken container satisfies every 'this must be blocked' assertion.
        """
        code, _ = self.compose.exec_capture(
            self.service, "timeout", str(timeout),
            "bash", "-c", f"cat < /dev/null > /dev/tcp/{ip}/{port}",
            timeout=timeout + 5,
        )
        return code == 0
