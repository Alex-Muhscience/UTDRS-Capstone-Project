# config.py
import os
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional

class Settings(BaseSettings):
    # MongoDB
    MONGODB_URI: str
    DB_NAME: str = "utdrs"
    
    # API Gateway
    API_GATEWAY_URL: str
    
    # JWT
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    
    # App
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    MODEL_PATH: str = "ml_models"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
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
    
    class Config:
        env_file = ".env"

settings = Settings()