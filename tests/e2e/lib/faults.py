"""Fault injection helpers for e2e tests (compose + tc)."""

import subprocess
import time


class Faults:
    def __init__(self, compose):
        self.compose = compose

    def stop(self, service: str):
        self.compose.exec("docker", "compose", "-f", "docker-compose.yml", "-f", "tests/e2e/docker-compose.e2e.yml", "stop", service)

    def start(self, service: str):
        self.compose.exec("docker", "compose", "-f", "docker-compose.yml", "-f", "tests/e2e/docker-compose.e2e.yml", "start", service)

    def restart(self, service: str):
        self.compose.exec("docker", "compose", "-f", "docker-compose.yml", "-f", "tests/e2e/docker-compose.e2e.yml", "restart", service)

    def add_latency(self, service: str, iface: str = "eth0", delay_ms: int = 100):
        self.compose.exec(service, "tc", "qdisc", "add", "dev", iface, "root", "netem", "delay", f"{delay_ms}ms")

    def remove_latency(self, service: str, iface: str = "eth0"):
        self.compose.exec(service, "tc", "qdisc", "del", "dev", iface, "root", "netem", "delay", "100ms")

    def add_loss(self, service: str, iface: str = "eth0", loss_percent: int = 10):
        self.compose.exec(service, "tc", "qdisc", "add", "dev", iface, "root", "netem", "loss", f"{loss_percent}%")

    def remove_loss(self, service: str, iface: str = "eth0"):
        self.compose.exec(service, "tc", "qdisc", "del", "dev", iface, "root", "netem", "loss", "10%")

    def clear_qdisc(self, service: str, iface: str = "eth0"):
        # Remove any qdisc on iface
        try:
            self.compose.exec(service, "tc", "qdisc", "del", "dev", iface, "root")
        except Exception:
            pass
