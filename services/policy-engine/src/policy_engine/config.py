"""Configuration for the AVON Policy Engine."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Policy Engine configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="POLICY_ENGINE_",
        case_sensitive=False,
    )

    database_url: str = "postgresql://localhost:5432/avon"
    redis_url: str = "redis://localhost:6379"
    grpc_port: int = 8081
    log_level: str = "INFO"
    cache_ttl_seconds: int = 60
    pod_cache_ttl_seconds: int = 300
    policy_cache_ttl_seconds: int = 60
    max_hierarchy_depth: int = 10
    default_action: str = "DENY"
    enable_audit_logging: bool = True


settings = Settings()
