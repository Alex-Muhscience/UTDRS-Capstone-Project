from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # MongoDB
    MONGODB_URI: str
    DB_NAME: str = "utdrs"

    # JWT
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # App
    DEBUG: bool = False
    API_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "UTDRS API Gateway"
    VERSION: str = "1.0.0"
    ALLOWED_HOSTS: List[str] = ["*"]

    # Browser origins allowed to call the API with credentials. Set as a JSON list,
    # e.g. CORS_ORIGINS='["https://dashboard.example.com"]'. Never "*" with credentials.
    CORS_ORIGINS: List[str] = ["http://localhost:3001", "http://localhost:5173"]

    # Accounts
    # When false, only administrators can create accounts (POST /users/).
    ALLOW_REGISTRATION: bool = True
    # The first administrator: on startup, this account is created as an admin if it
    # does not exist, or made an active admin if it does. Its password is only used
    # when creating it, so a password changed later is kept.
    ADMIN_USERNAME: Optional[str] = None
    ADMIN_EMAIL: Optional[str] = None
    ADMIN_PASSWORD: Optional[str] = None

    # Integration services
    # When CORE_ENGINE_URL is set, every ingested event is sent to the core engine for
    # detection, and any threat it finds becomes an alert here.
    CORE_ENGINE_URL: Optional[str] = None
    CORE_ENGINE_TIMEOUT_SECONDS: float = 10.0
    # Shared secret sent to the core engine as X-Internal-Token (must match its setting).
    INTERNAL_API_TOKEN: Optional[str] = None


settings = Settings()
