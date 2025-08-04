import os
from typing import Optional
from pydantic import BaseSettings, Field

class Settings(BaseSettings):
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
    
    # Integration services
    CORE_ENGINE_URL: Optional[str] = None
    RESPONSE_SERVICE_URL: Optional[str] = None
    
    class Config:
        env_file = ".env"

settings = Settings()
