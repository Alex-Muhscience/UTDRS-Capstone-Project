from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # MongoDB
    MONGODB_URI: str
    # The engine keeps its own database: its events, alerts and rules have a different
    # shape from the gateway's, so the two must not share collections.
    DB_NAME: str = "utdrs_engine"

    # API Gateway
    API_GATEWAY_URL: Optional[str] = None

    # JWT
    JWT_SECRET: Optional[str] = None
    JWT_ALGORITHM: str = "HS256"

    # App
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    MODEL_PATH: str = "ml_models"
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Shared secret the API gateway sends in the X-Internal-Token header. Detection
    # endpoints reject requests without it. The engine is an internal service and should
    # not be reachable from the internet either way.
    INTERNAL_API_TOKEN: Optional[str] = None
    # Without a token the detection endpoints refuse every request, unless this is set:
    # for local development only, never where anything but you can reach the engine.
    ALLOW_UNAUTHENTICATED: bool = False

    # YARA Rules
    YARA_RULES_PATH: str = "rules/yara"

    # Threat Intelligence
    TI_CACHE_PATH: str = "cache/threat_intel"
    TI_CACHE_EXPIRY: int = 86400  # 24 hours in seconds

    # External API Keys (optional)
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None

    # Advanced Detection Settings
    ENABLE_YARA: bool = True
    ENABLE_THREAT_INTEL: bool = True
    ENABLE_CORRELATION: bool = True
    CORRELATION_WINDOW: int = 60  # minutes
    ANOMALY_BASELINE_DAYS: int = 7


settings = Settings()
