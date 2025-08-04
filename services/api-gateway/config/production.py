"""Production configuration settings"""
import os
from typing import Optional, List, Union
from pydantic import BaseSettings, Field, validator


class ProductionSettings(BaseSettings):
    # MongoDB
    MONGODB_URI: str
    DB_NAME: str = "utdrs"
    
    # JWT
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # App
    DEBUG: bool = False
    API_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "UTDRS API Gateway"
    VERSION: str = "1.0.0"
    
    # Security
    ALLOWED_HOSTS: List[str] = ["*"]
    CORS_ORIGINS: List[str] = []
    SECRET_KEY: str
    BCRYPT_ROUNDS: int = 12
    
    # Rate limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    # Monitoring
    METRICS_ENABLED: bool = True
    HEALTH_CHECK_TIMEOUT: int = 30
    
    # Integration services
    CORE_ENGINE_URL: Optional[str] = None
    RESPONSE_SERVICE_URL: Optional[str] = None
    
    # Database connection pool
    DB_MIN_CONNECTIONS: int = 10
    DB_MAX_CONNECTIONS: int = 100
    DB_CONNECTION_TIMEOUT: int = 30
    
    # Request limits
    MAX_REQUEST_SIZE: int = 10 * 1024 * 1024  # 10MB
    MAX_UPLOAD_SIZE: int = 50 * 1024 * 1024   # 50MB
    
    @validator("CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    @validator("JWT_SECRET")
    def validate_jwt_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters long")
        return v
    
    @validator("SECRET_KEY")
    def validate_secret_key(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = ProductionSettings()
