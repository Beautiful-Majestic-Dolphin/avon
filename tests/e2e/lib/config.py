"""E2E Test Configuration

Loads configuration from environment variables for test execution.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class E2EConfig:
    """Configuration for E2E tests loaded from environment."""

    # Admin API
    admin_api_url: str

    # Policy Engine
    policy_engine_url: str

    # gRPC Services
    auth_url: str
    gateway_url: str

    # Agents
    agent_1_url: str
    agent_2_url: str
    agent_3_url: Optional[str]

    # Database
    postgres_url: str
    redis_url: str

    # Timeouts (seconds)
    default_timeout: float = 30.0
    enrollment_timeout: float = 60.0
    tunnel_timeout: float = 45.0

    @classmethod
    def from_env(cls) -> "E2EConfig":
        """Load configuration from environment variables."""
        return cls(
            admin_api_url=os.environ.get("ADMIN_API_URL", "http://localhost:8082"),
            policy_engine_url=os.environ.get("POLICY_ENGINE_URL", "http://localhost:8081"),
            auth_url=os.environ.get("AUTH_URL", "localhost:50051"),
            gateway_url=os.environ.get("GATEWAY_URL", "localhost:4600"),
            agent_1_url=os.environ.get("AGENT_1_URL", "http://localhost:8090"),
            agent_2_url=os.environ.get("AGENT_2_URL", "http://localhost:8091"),
            agent_3_url=os.environ.get("AGENT_3_URL"),
            postgres_url=os.environ.get(
                "POSTGRES_URL",
                "postgres://avon:test_password@localhost:5432/avon_e2e"
            ),
            redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379"),
            default_timeout=float(os.environ.get("DEFAULT_TIMEOUT", "30")),
            enrollment_timeout=float(os.environ.get("ENROLLMENT_TIMEOUT", "60")),
            tunnel_timeout=float(os.environ.get("TUNNEL_TIMEOUT", "45")),
        )


# Global config instance
config = E2EConfig.from_env()
