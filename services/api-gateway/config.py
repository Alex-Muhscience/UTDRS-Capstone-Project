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

    # Integration services
    CORE_ENGINE_URL: Optional[str] = None
    RESPONSE_SERVICE_URL: Optional[str] = None


settings = Settings()
