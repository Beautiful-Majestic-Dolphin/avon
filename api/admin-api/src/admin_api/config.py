"""Configuration for the AVON Admin API."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Admin API configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="ADMIN_API_",
        case_sensitive=False,
    )

    database_url: str = "postgresql://localhost:5432/avon"
    redis_url: str = "redis://localhost:6379"
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "INFO"
    
    jwt_secret_key: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7
    
    cors_origins: list[str] = ["*"]

    # WebAuthn / FIDO2 settings
    webauthn_rp_id: str = "admin.avon.local"
    webauthn_rp_name: str = "AVON Admin Console"
    webauthn_origin: str = "https://admin.avon.local"
    mfa_token_expire_minutes: int = 5
    
    enrollment_token_expire_hours: int = 24
    installation_package_base_url: str = "https://install.avon.local"
    
    control_plane_addresses: list[str] = ["gateway.avon.local:8443"]

    # SCIM provisioning settings
    scim_enabled: bool = False
    scim_page_size_default: int = 100
    scim_page_size_max: int = 1000


settings = Settings()
