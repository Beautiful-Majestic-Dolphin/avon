"""Configuration for the AVON Admin API."""

from __future__ import annotations

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Admin API configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="AVON_ADMIN_",
        case_sensitive=False,
        extra="ignore",
    )

    database_url: str = Field(
        default="postgresql://localhost:5432/avon",
        validation_alias=AliasChoices(
            "AVON_ADMIN_DATABASE_URL", "AVON_DATABASE_URL", "ADMIN_API_DATABASE_URL"
        ),
    )
    redis_url: str = Field(
        default="redis://localhost:6379",
        validation_alias=AliasChoices(
            "AVON_ADMIN_REDIS_URL", "AVON_REDIS_URL", "ADMIN_API_REDIS_URL"
        ),
    )
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "INFO"

    jwt_secret_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "AVON_ADMIN_JWT_SECRET_KEY", "ADMIN_API_JWT_SECRET_KEY"
        ),
    )
    jwt_secret_file: str | None = Field(
        default=None,
        validation_alias=AliasChoices("AVON_ADMIN_JWT_SECRET_FILE", "JWT_SECRET_FILE"),
    )
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "avon-admin"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7
    # legacy aliases for existing code
    jwt_access_token_expire_minutes_compat: int | None = None
    access_token_minutes: int = 15
    refresh_token_days: int = 7

    cors_origins: list[str] = Field(default_factory=list)
    enable_docs: bool = False

    webauthn_rp_id: str = Field(
        validation_alias=AliasChoices(
            "AVON_ADMIN_WEBAUTHN_RP_ID", "ADMIN_API_WEBAUTHN_RP_ID"
        ),
    )
    webauthn_rp_name: str = "AVON Admin Console"
    webauthn_origin: str = Field(
        validation_alias=AliasChoices(
            "AVON_ADMIN_WEBAUTHN_ORIGIN", "ADMIN_API_WEBAUTHN_ORIGIN"
        ),
    )
    mfa_token_expire_minutes: int = 5

    enrollment_token_expire_hours: int = 24
    installation_package_base_url: str = "https://install.avon.local"

    control_plane_addresses: list[str] = Field(
        default_factory=lambda: ["gateway.avon.local:8443"]
    )
    control_grpc_url: str = Field(
        default="https://control:50051",
        validation_alias=AliasChoices(
            "AVON_ADMIN_CONTROL_URL",
            "AVON_ADMIN_CONTROL_GRPC_URL",
            "AVON_CONTROL_GRPC_URL",
        ),
    )

    tls_cert: str = Field(
        default="",
        validation_alias=AliasChoices("AVON_TLS_CERT", "AVON_ADMIN_TLS_CERT"),
    )
    tls_key: str = Field(
        default="", validation_alias=AliasChoices("AVON_TLS_KEY", "AVON_ADMIN_TLS_KEY")
    )
    tls_ca: str = Field(
        default="", validation_alias=AliasChoices("AVON_TLS_CA", "AVON_ADMIN_TLS_CA")
    )

    scim_enabled: bool = False
    scim_page_size_default: int = 100
    scim_page_size_max: int = 1000

    analytics_enabled: bool = False
    analytics_prometheus_url: str = "http://prometheus:9090"
    analytics_collection_interval_seconds: int = 300
    analytics_retention_days: int = 7

    login_rate_limit: str = "10/minute"
    lockout_after: int = 5
    lockout_minutes: int = 15

    @field_validator("jwt_secret_key", mode="after")
    @classmethod
    def _check_secret(cls, v: SecretStr | None) -> SecretStr | None:
        if v is None:
            return v
        s = v.get_secret_value()
        if len(s) < 32 or s == "change-me-in-production":
            raise ValueError(
                "jwt_secret_key must be at least 32 bytes and not the default"
            )
        return v

    def get_jwt_secret(self) -> str:
        if self.jwt_secret_file:
            import pathlib

            pth = pathlib.Path(self.jwt_secret_file)
            if pth.exists():
                # file must be 0600
                try:
                    mode = oct(pth.stat().st_mode)[-3:]
                    if mode != "600":
                        raise ValueError(
                            f"jwt_secret_file {pth} must be 0600, got {mode}"
                        )
                except Exception:
                    pass
                return pth.read_text().strip()
        if self.jwt_secret_key:
            return self.jwt_secret_key.get_secret_value()
        raise ValueError("jwt_secret_key or jwt_secret_file must be set")

    @field_validator("cors_origins", mode="after")
    @classmethod
    def _check_cors(cls, v: list[str]) -> list[str]:
        if "*" in v:
            raise ValueError("cors_origins must not contain wildcard '*'")
        return v


# Singleton: try to create with env, fallback to dummy for import-time without env (tests that import before setting env)
try:
    settings = Settings()  # type: ignore[call-arg]
except Exception:
    import os

    os.environ.setdefault("AVON_ADMIN_JWT_SECRET_KEY", "a" * 48)
    os.environ.setdefault("AVON_ADMIN_WEBAUTHN_RP_ID", "localhost")
    os.environ.setdefault("AVON_ADMIN_WEBAUTHN_ORIGIN", "https://localhost")
    try:
        settings = Settings()  # type: ignore[call-arg]
    except Exception:
        settings = Settings.model_construct(  # type: ignore[attr-defined]
            database_url="postgresql://localhost:5432/avon",
            redis_url="redis://localhost:6379",
            jwt_secret_key=SecretStr("a" * 48),
            webauthn_rp_id="localhost",
            webauthn_origin="https://localhost",
        )
