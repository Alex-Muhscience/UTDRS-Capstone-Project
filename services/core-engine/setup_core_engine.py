#!/usr/bin/env python3
"""
Core Engine Setup Script for UTDRS

This script creates a Docker-ready Core Engine project structure
with MongoDB integration, suitable for deployment on Render.
"""

import os
import sys
import shutil
from pathlib import Path

# ANSI colors for terminal output
class Colors:
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    NC = '\033[0m'  # No Color

def print_colored(message, color):
    """Print a message with color."""
    print(f"{color}{message}{Colors.NC}")

def create_directory(path):
    """Create a directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)
    return path

def write_file(path, content):
    """Write content to a file."""
    with open(path, 'w') as f:
        f.write(content)
    return path

def generate_project_structure():
    """Generate the Core Engine project structure."""
    print_colored("=== Core Engine Project Setup Script ===", Colors.GREEN)
    
    # Define project directory
    project_dir = "core-engine"
    
    # Check if directory exists
    if os.path.exists(project_dir):
        print_colored(f"Warning: {project_dir} directory already exists.", Colors.YELLOW)
        user_input = input("Do you want to overwrite it? (y/n): ")
        if user_input.lower() != "y":
            print("Aborting setup.")
            sys.exit(0)
        shutil.rmtree(project_dir)
    
    print_colored("Creating project structure...", Colors.YELLOW)
    create_directory(project_dir)
    
    # Change to project directory
    os.chdir(project_dir)
    
    # Create directory structure
    create_directory("api")
    create_directory("api/routes")
    create_directory("api/controllers")

    create_directory("core")
    create_directory("core/detection")
    create_directory("core/models")
    create_directory("core/models/ml")
    create_directory("core/models/schema")
    create_directory("core/rules")
    create_directory("core/rules/predefined")
    create_directory("core/mitre")
    create_directory("core/risk")
    create_directory("core/services")
    create_directory("core/database")
    create_directory("core/database/repositories")

    create_directory("utils")
    create_directory("ml_models")
    create_directory("ml_models/phishing_detector")
    create_directory("ml_models/ransomware_detector")
    create_directory("ml_models/anomaly_detector")

    create_directory("tests")
    create_directory("tests/unit")
    create_directory("tests/integration")
    create_directory("tests/fixtures")

    # Create empty __init__.py files to make directories packages
    for dir_path in [
        "api",
        "api/routes",
        "api/controllers",
        "core",
        "core/detection",
        "core/models",
        "core/models/ml",
        "core/models/schema",
        "core/rules",
        "core/rules/predefined",
        "core/mitre",
        "core/risk",
        "core/services",
        "core/database",
        "core/database/repositories",
        "utils",
        "tests",
        "tests/unit",
        "tests/integration",
    ]:
        write_file(os.path.join(dir_path, "__init__.py"), "# Package\n")

    # Create requirements.txt
    print_colored("Creating requirements.txt...", Colors.YELLOW)
    requirements_content = """fastapi==0.103.1
uvicorn==0.23.2
motor==3.3.1
pymongo==4.5.0
python-dotenv==1.0.0
pydantic==2.3.0
pytest==7.4.2
httpx==0.24.1
gunicorn==21.2.0
scikit-learn==1.3.0
numpy==1.25.2
pandas==2.1.0
python-jose==3.3.0
passlib==1.7.4
"""
    write_file("requirements.txt", requirements_content)

    # Create .env file
    print_colored("Creating .env file...", Colors.YELLOW)
    env_content = """# MongoDB Connection
MONGODB_URI=mongodb+srv://<username>:<password>@cluster0.pmbmm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0
DB_NAME=utdrs

# API Gateway
API_GATEWAY_URL=http://api-gateway:8000

# JWT Settings
JWT_SECRET=your_super_secret_key_change_in_production
JWT_ALGORITHM=HS256

# App Settings
DEBUG=True
LOG_LEVEL=INFO
MODEL_PATH=ml_models
HOST=0.0.0.0
PORT=8000
"""
    write_file(".env", env_content)

    # Create .env.example file
    print_colored("Creating .env.example file...", Colors.YELLOW)
    env_example_content = """# MongoDB Connection
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname?retryWrites=true&w=majority
DB_NAME=utdrs

# API Gateway
API_GATEWAY_URL=http://api-gateway:8000

# JWT Settings
JWT_SECRET=your_secret_key
JWT_ALGORITHM=HS256

# App Settings
DEBUG=True
LOG_LEVEL=INFO
MODEL_PATH=ml_models
HOST=0.0.0.0
PORT=8000
"""
    write_file(".env.example", env_example_content)

    # Create config.py
    print_colored("Creating config.py...", Colors.YELLOW)
    config_content = """import os
from pydantic import BaseSettings, Field
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
    
    class Config:
        env_file = ".env"

settings = Settings()
"""
    write_file("config.py", config_content)

    # Create app.py
    print_colored("Creating app.py...", Colors.YELLOW)
    app_content = """from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from api.routes import detections, rules, health
from core.database.connection import connect_to_mongo, close_mongo_connection
from config import settings
import logging

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="UTDRS Core Engine",
    description="Core Detection Engine for the Unified Threat Detection and Response System",
    version="1.0.0",
)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database events
app.add_event_handler("startup", connect_to_mongo)
app.add_event_handler("shutdown", close_mongo_connection)

# Include API routes
app.include_router(health.router, tags=["health"])
app.include_router(detections.router, prefix="/detections", tags=["detections"])
app.include_router(rules.router, prefix="/rules", tags=["rules"])

@app.get("/")
async def root():
    return {"message": "Welcome to the UTDRS Core Engine API"}
"""
    write_file("app.py", app_content)

    # Create wsgi.py
    print_colored("Creating wsgi.py...", Colors.YELLOW)
    wsgi_content = """import uvicorn
from app import app
from config import settings

if __name__ == "__main__":
    uvicorn.run(
        "app:app", 
        host=settings.HOST, 
        port=settings.PORT, 
        reload=settings.DEBUG
    )
"""
    write_file("wsgi.py", wsgi_content)

    # Create Dockerfile
    print_colored("Creating Dockerfile...", Colors.YELLOW)
    dockerfile_content = """FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Run gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app", "-k", "uvicorn.workers.UvicornWorker"]
"""
    write_file("Dockerfile", dockerfile_content)

    # Create .dockerignore
    print_colored("Creating .dockerignore...", Colors.YELLOW)
    dockerignore_content = """venv/
.env
__pycache__/
*.py[cod]
*$py.class
.pytest_cache/
.coverage
htmlcov/
.DS_Store
.git/
.idea/
.vscode/
*.swp
"""
    write_file(".dockerignore", dockerignore_content)

    # Create docker-compose.yml for local development
    print_colored("Creating docker-compose.yml...", Colors.YELLOW)
    docker_compose_content = """version: '3.8'

services:
  core-engine:
    build: .
    ports:
      - "8001:8000"
    volumes:
      - .:/app
    environment:
      - MONGODB_URI=${MONGODB_URI}
      - API_GATEWAY_URL=${API_GATEWAY_URL}
      - JWT_SECRET=${JWT_SECRET}
      - DEBUG=True
      - LOG_LEVEL=INFO
    command: uvicorn app:app --host 0.0.0.0 --port 8000 --reload
    restart: unless-stopped
"""
    write_file("docker-compose.yml", docker_compose_content)

    # Create render.yaml for Render deployment
    print_colored("Creating render.yaml...", Colors.YELLOW)
    render_yaml_content = """services:
  - type: web
    name: utdrs-core-engine
    env: docker
    dockerfilePath: ./Dockerfile
    dockerContext: .
    envVars:
      - key: MONGODB_URI
        sync: false  # Set this manually in the Render dashboard
      - key: DB_NAME
        value: utdrs
      - key: API_GATEWAY_URL
        sync: false  # Set this to the deployed API Gateway URL
      - key: JWT_SECRET
        generateValue: true
      - key: DEBUG
        value: false
      - key: LOG_LEVEL
        value: INFO
"""
    write_file("render.yaml", render_yaml_content)

    # Create database connection file
    print_colored("Creating database connection...", Colors.YELLOW)
    connection_content = """from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure
from config import settings
from utils.logger import get_logger

logger = get_logger(__name__)

class Database:
    client: AsyncIOMotorClient = None
    db_name: str = settings.DB_NAME

db = Database()

async def connect_to_mongo():
    try:
        db.client = AsyncIOMotorClient(settings.MONGODB_URI)
        # Validate connection
        await db.client.admin.command('ping')
        logger.info("Connected to MongoDB")
    except ConnectionFailure:
        logger.error("Failed to connect to MongoDB")
        raise

async def close_mongo_connection():
    if db.client:
        db.client.close()
        logger.info("Closed MongoDB connection")

def get_database():
    return db.client[db.db_name]
"""
    write_file("core/database/connection.py", connection_content)

    # Create health check route
    print_colored("Creating health check route...", Colors.YELLOW)
    health_route_content = """from fastapi import APIRouter, Depends
from core.database.connection import get_database

router = APIRouter()

@router.get("/health")
async def health_check():
    '''Health check endpoint to verify API and database are working.'''
    return {
        "status": "ok",
        "service": "core-engine"
    }

@router.get("/health/db")
async def database_health_check():
    '''Check database connection health.'''
    db = get_database()
    try:
        # Execute simple command to check DB connection
        await db.command("ping")
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        return {"status": "error", "database": "disconnected", "detail": str(e)}
"""
    write_file("api/routes/health.py", health_route_content)

    # Create detections route
    print_colored("Creating detections route...", Colors.YELLOW)
    detections_route_content = """from fastapi import APIRouter, Depends, HTTPException, status, Body
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from core.detection.engine import DetectionEngine
from core.services.event_processor import process_event
from core.models.schema.alert import AlertCreate, Alert

router = APIRouter()

# Initialize detection engine
detection_engine = DetectionEngine()

class EventData(BaseModel):
    source: str
    event_type: str
    timestamp: str
    data: Dict[str, Any]

@router.post("/process", response_model=Optional[Alert])
async def process_event_data(event: EventData):
    '''Process an event and generate an alert if a threat is detected.'''
    alert = await process_event(event.dict())
    return alert

@router.get("/alerts", response_model=List[Alert])
async def get_alerts(
    severity: Optional[str] = None, 
    source: Optional[str] = None, 
    limit: int = 100, 
    skip: int = 0
):
    '''Get alerts based on filters.'''
    filters = {}
    if severity:
        filters["severity"] = severity
    if source:
        filters["source"] = source
        
    alerts = await detection_engine.get_alerts(filters, limit, skip)
    return alerts

@router.get("/alerts/{alert_id}", response_model=Alert)
async def get_alert(alert_id: str):
    '''Get a specific alert by ID.'''
    alert = await detection_engine.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    return alert
"""
    write_file("api/routes/detections.py", detections_route_content)

    # Create rules route
    print_colored("Creating rules route...", Colors.YELLOW)
    rules_route_content = """from fastapi import APIRouter, Depends, HTTPException, status, Body
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from core.rules.rule_loader import RuleManager

router = APIRouter()

# Initialize rule manager
rule_manager = RuleManager()

class DetectionRule(BaseModel):
    name: str
    description: str
    rule_type: str
    detection: Dict[str, Any]
    enabled: bool = True
    severity: str
    tags: List[str] = []

@router.get("/", response_model=List[DetectionRule])
async def get_rules(
    rule_type: Optional[str] = None, 
    enabled: Optional[bool] = None,
    limit: int = 100, 
    skip: int = 0
):
    '''Get detection rules based on filters.'''
    filters = {}
    if rule_type:
        filters["rule_type"] = rule_type
    if enabled is not None:
        filters["enabled"] = enabled
        
    rules = await rule_manager.get_rules(filters, limit, skip)
    return rules

@router.get("/{rule_id}", response_model=DetectionRule)
async def get_rule(rule_id: str):
    '''Get a specific rule by ID.'''
    rule = await rule_manager.get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    return rule

@router.post("/", response_model=DetectionRule)
async def create_rule(rule: DetectionRule):
    '''Create a new detection rule.'''
    created_rule = await rule_manager.create_rule(rule.dict())
    return created_rule

@router.put("/{rule_id}", response_model=DetectionRule)
async def update_rule(rule_id: str, rule: DetectionRule):
    '''Update an existing detection rule.'''
    updated_rule = await rule_manager.update_rule(rule_id, rule.dict())
    if not updated_rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
    return updated_rule

@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: str):
    '''Delete a detection rule.'''
    deleted = await rule_manager.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )
"""
    write_file("api/routes/rules.py", rules_route_content)

    # Create detection engine
    print_colored("Creating detection engine...", Colors.YELLOW)
    detection_engine_content = """from typing import Dict, List, Any, Optional
from core.database.repositories.alert_repository import AlertRepository
from core.rules.rule_loader import RuleManager
from core.detection.signature_detector import SignatureDetector
from core.detection.anomaly_detector import AnomalyDetector
from core.detection.ml_detector import MLDetector
from core.models.schema.alert import Alert, AlertCreate
from utils.logger import get_logger

logger = get_logger(__name__)

class DetectionEngine:
    def __init__(self):
        self.alert_repository = AlertRepository()
        self.rule_manager = RuleManager()
        self.signature_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        self.ml_detector = MLDetector()
        
    async def detect_threats(self, event):
        logger.info(f"Analyzing event from source: {event.get('source', 'unknown')}")
        
        # Try signature-based detection first (fastest)
        signature_result = await self.signature_detector.detect(event)
        if signature_result:
            logger.info(f"Signature detection found threat: {signature_result['name']}")
            return await self._create_alert(event, signature_result)
            
        # Try ML-based detection
        ml_result = await self.ml_detector.detect(event)
        if ml_result:
            logger.info(f"ML detection found threat: {ml_result['name']}")
            return await self._create_alert(event, ml_result)
            
        # Try anomaly detection
        anomaly_result = await self.anomaly_detector.detect(event)
        if anomaly_result:
            logger.info(f"Anomaly detection found threat: {anomaly_result['name']}")
            return await self._create_alert(event, anomaly_result)
            
        logger.info("No threats detected in event")
        return None
        
    async def _create_alert(self, event, detection_result):
        alert_data = AlertCreate(
            title=detection_result['name'],
            description=detection_result['description'],
            severity=detection_result['severity'],
            source=event.get('source', 'unknown'),
            event_ids=[event.get('id', 'unknown')],
            detection_type=detection_result['detection_type'],
            details={
                'event': event,
                'detection': detection_result
            }
        )
        
        return await self.alert_repository.create_alert(alert_data)
        
    async def get_alerts(self, filters, limit=100, skip=0):
        return await self.alert_repository.find_many(filters, limit, skip)
        
    async def get_alert_by_id(self, alert_id):
        return await self.alert_repository.find_by_id(alert_id)
"""
    write_file("core/detection/engine.py", detection_engine_content)

    # Create signature detector
    print_colored("Creating signature detector...", Colors.YELLOW)
    signature_detector_content = """from typing import Dict, Any, Optional
from core.rules.rule_loader import RuleManager
from utils.logger import get_logger

logger = get_logger(__name__)

class SignatureDetector:
    def __init__(self):
        self.rule_manager = RuleManager()
        
    async def detect(self, event):
        # Get all enabled signature rules
        rules = await self.rule_manager.get_rules({
            "rule_type": "signature", 
            "enabled": True
        })
        
        for rule in rules:
            if await self._match_rule(event, rule):
                logger.info(f"Event matched signature rule: {rule['name']}")
                return {
                    "name": rule['name'],
                    "description": rule['description'],
                    "severity": rule['severity'],
                    "detection_type": "signature",
                    "rule_id": str(rule.get('_id', '')),
                    "tags": rule.get('tags', [])
                }
                
        return None
        
    async def _match_rule(self, event, rule):
        try:
            detection_conditions = rule.get('detection', {}).get('conditions', {})
            
            # Check for simple field matches
            for field, expected_value in detection_conditions.items():
                # Handle nested fields using dot notation (e.g., "details.ip")
                if "." in field:
                    parts = field.split(".")
                    value = event
                    for part in parts:
                        if isinstance(value, dict) and part in value:
                            value = value[part]
                        else:
                            return False
                else:
                    # Direct field access
                    if field not in event:
                        return False
                    value = event[field]
                    
                # Check if value matches expected value
                if value != expected_value:
                    return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Error matching rule {rule.get('name')}: {str(e)}")
            return False
"""
    write_file("core/detection/signature_detector.py", signature_detector_content)

    # Create anomaly detector
    print_colored("Creating anomaly detector...", Colors.YELLOW)
    anomaly_detector_content = """from typing import Dict, Any, Optional
from utils.logger import get_logger

logger = get_logger(__name__)

class AnomalyDetector:
    def __init__(self):
        pass
        
    async def detect(self, event):
        # Placeholder logic for anomaly detection
        # For now, we'll just return None as if no anomalies were detected
        return None
"""
    write_file("core/detection/anomaly_detector.py", anomaly_detector_content)

    # Create ML detector
    print_colored("Creating ML detector...", Colors.YELLOW)
    ml_detector_content = """from typing import Dict, Any, Optional
from core.models.ml.model_registry import ModelRegistry
from utils.logger import get_logger
import os
from config import settings

logger = get_logger(__name__)

class MLDetector:
    def __init__(self):
        self.model_registry = ModelRegistry(settings.MODEL_PATH)
        
    async def detect(self, event):
        # Determine which ML model to use based on event type
        event_type = event.get('event_type', '')
        
        if 'email' in event_type or 'url' in event_type:
            # Use phishing detector for email or URL events
            model_result = await self._run_phishing_detection(event)
            if model_result and model_result['confidence'] > 0.7:  # 70% confidence threshold
                return {
                    "name": "Potential Phishing Attempt",
                    "description": f"ML model detected phishing indicators with {model_result['confidence']*100:.1f}% confidence",
                    "severity": "high" if model_result['confidence'] > 0.9 else "medium",
                    "detection_type": "ml",
                    "model": "phishing_detector",
                    "confidence": model_result['confidence'],
                    "tags": ["phishing", "ml-detection"]
                }
                
        elif 'file' in event_type or 'process' in event_type:
            # Use ransomware detector for file or process events
            model_result = await self._run_ransomware_detection(event)
            if model_result and model_result['confidence'] > 0.7:  # 70% confidence threshold
                return {
                    "name": "Potential Ransomware Activity",
                    "description": f"ML model detected ransomware indicators with {model_result['confidence']*100:.1f}% confidence",
                    "severity": "critical" if model_result['confidence'] > 0.9 else "high",
                    "detection_type": "ml",
                    "model": "ransomware_detector",
                    "confidence": model_result['confidence'],
                    "tags": ["ransomware", "ml-detection"]
                }
                
        # No threat detected
        return None
        
    async def _run_phishing_detection(self, event):
        # In a real system, this would extract features from the event
        # and use a trained ML model to classify the event
        
        # For now, return None (no detection)
        return None
        
    async def _run_ransomware_detection(self, event):
        # In a real system, this would extract features from the event
        # and use a trained ML model to classify the event
        
        # For now, return None (no detection)
        return None
"""
    write_file("core/detection/ml_detector.py", ml_detector_content)

    # Create rule loader
    print_colored("Creating rule loader...", Colors.YELLOW)
    rule_loader_content = """from typing import Dict, List, Any, Optional
from core.database.repositories.rule_repository import RuleRepository
from utils.logger import get_logger

logger = get_logger(__name__)

class RuleManager:
    def __init__(self):
        self.rule_repository = RuleRepository()
        
    async def get_rules(self, filters, limit=100, skip=0):
        return await self.rule_repository.find_many(filters, limit, skip)
        
    async def get_rule_by_id(self, rule_id):
        return await self.rule_repository.find_by_id(rule_id)
        
    async def create_rule(self, rule_data):
        # Validate rule before saving
        self._validate_rule(rule_data)
        
        # Add created timestamp
        from datetime import datetime
        rule_data['created_at'] = utcnow()
        rule_data['updated_at'] = utcnow()
        
        # Save to database
        rule_id = await self.rule_repository.insert_one(rule_data)
        return await self.get_rule_by_id(rule_id)
        
    async def update_rule(self, rule_id, rule_data):
        # Validate rule before updating
        self._validate_rule(rule_data)
        
        # Update timestamp
        from datetime import datetime
        rule_data['updated_at'] = utcnow()
        
        # Update in database
        success = await self.rule_repository.update_one(rule_id, rule_data)
        if success:
            return await self.get_rule_by_id(rule_id)
        return None
        
    async def delete_rule(self, rule_id):
        return await self.rule_repository.delete_one(rule_id)
        
    def _validate_rule(self, rule_data):
        required_fields = ['name', 'description', 'rule_type', 'detection']
        for field in required_fields:
            if field not in rule_data:
                raise ValueError(f"Missing required field: {field}")
                
        valid_rule_types = ['signature', 'anomaly', 'correlation', 'ml']
        if rule_data['rule_type'] not in valid_rule_types:
            raise ValueError(f"Invalid rule type: {rule_data['rule_type']}. Must be one of {valid_rule_types}")
            
        # Validate detection based on rule type
        if rule_data['rule_type'] == 'signature':
            if 'conditions' not in rule_data.get('detection', {}):
                raise ValueError("Signature rules must have detection.conditions defined")
"""
    write_file("core/rules/rule_loader.py", rule_loader_content)

    # Create event processor service
    print_colored("Creating event processor service...", Colors.YELLOW)
    event_processor_content = """from typing import Dict, Any, Optional
from core.detection.engine import DetectionEngine
from core.models.schema.alert import Alert
from utils.logger import get_logger

logger = get_logger(__name__)

# Initialize detection engine
detection_engine = DetectionEngine()

async def process_event(event_data):
    try:
        logger.info(f"Processing event from source: {event_data.get('source', 'unknown')}")
        
        # Perform detection using the detection engine
        alert = await detection_engine.detect_threats(event_data)
        
        if alert:
            logger.info(f"Generated alert: {alert.title}")
            # In a real system, you might send the alert to the API Gateway or a notification service
            
        return alert
        
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        return None
"""
    write_file("core/services/event_processor.py", event_processor_content)

    # Create model registry
    print_colored("Creating model registry...", Colors.YELLOW)
    model_registry_content = """import os
from typing import Dict, Any, Optional, List
from utils.logger import get_logger

logger = get_logger(__name__)

class ModelRegistry:
    def __init__(self, models_directory):
        self.models_directory = models_directory
        self.models = {}
        self.load_models()
        
    def load_models(self):
        logger.info(f"Loading ML models from {self.models_directory}")
        
        # Check if models directory exists
        if not os.path.exists(self.models_directory):
            logger.warning(f"Models directory {self.models_directory} does not exist")
            return
            
        # In a real system, this would scan the directory and load each model
        # For now, we'll just log the model directories we find
        for model_dir in [d for d in os.listdir(self.models_directory) 
                          if os.path.isdir(os.path.join(self.models_directory, d))]:
            logger.info(f"Found model directory: {model_dir}")
            
    def get_model(self, model_name):
        if model_name in self.models:
            return self.models[model_name]
        logger.warning(f"Model {model_name} not found in registry")
        return None
        
    def list_models(self):
        return list(self.models.keys())
"""
    write_file("core/models/ml/model_registry.py", model_registry_content)

    # Create alert model
    print_colored("Creating alert model...", Colors.YELLOW)
    alert_model_content = """from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime

class AlertBase(BaseModel):
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    source: str
    event_ids: List[str] = []
    detection_type: str  # signature, anomaly, ml
    details: Dict[str, Any] = {}
    status: str = "open"  # open, in_progress, resolved, closed, false_positive

class AlertCreate(AlertBase):
    pass

class Alert(AlertBase):
    id: str = Field(..., alias="_id")
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    
    class Config:
        allow_population_by_field_name = True
"""
    write_file("core/models/schema/alert.py", alert_model_content)

    # Create base repository
    print_colored("Creating base repository...", Colors.YELLOW)
    base_repository_content = """from typing import List, Dict, Any, Optional, TypeVar, Generic
from bson import ObjectId
from pydantic import BaseModel
from core.database.connection import get_database

T = TypeVar('T', bound=BaseModel)

class BaseRepository:
    def __init__(self, collection_name: str):
        self.db = get_database()
        self.collection = self.db[collection_name]
    
    async def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        result = await self.collection.find_one(query)
        if result:
            result["_id"] = str(result["_id"])
        return result
    
    async def find_by_id(self, id: str) -> Optional[Dict[str, Any]]:
        if not ObjectId.is_valid(id):
            return None
        return await self.find_one({"_id": ObjectId(id)})
    
    async def find_many(self, query: Dict[str, Any], limit: int = 100, skip: int = 0) -> List[Dict[str, Any]]:
        cursor = self.collection.find(query).skip(skip).limit(limit)
        results = await cursor.to_list(length=limit)
        for result in results:
            result["_id"] = str(result["_id"])
        return results
    
    async def count(self, query: Dict[str, Any]) -> int:
        return await self.collection.count_documents(query)
    
    async def insert_one(self, document: Dict[str, Any]) -> str:
        result = await self.collection.insert_one(document)
        return str(result.inserted_id)
    
    async def insert_many(self, documents: List[Dict[str, Any]]) -> List[str]:
        result = await self.collection.insert_many(documents)
        return [str(id) for id in result.inserted_ids]
    
    async def update_one(self, id: str, update_data: Dict[str, Any]) -> bool:
        if not ObjectId.is_valid(id):
            return False
        result = await self.collection.update_one(
            {"_id": ObjectId(id)}, {"$set": update_data}
        )
        return result.modified_count > 0
    
    async def delete_one(self, id: str) -> bool:
        if not ObjectId.is_valid(id):
            return False
        result = await self.collection.delete_one({"_id": ObjectId(id)})
        return result.deleted_count > 0
"""
    write_file("core/database/repositories/base_repository.py", base_repository_content)

    # Create alert repository
    print_colored("Creating alert repository...", Colors.YELLOW)
    alert_repository_content = """from typing import List, Dict, Any, Optional
from datetime import datetime
from core.database.repositories.base_repository import BaseRepository
from core.models.schema.alert import AlertCreate, Alert

class AlertRepository(BaseRepository):
    def __init__(self):
        super().__init__("alerts")
    
    async def create_alert(self, alert_data):
        alert_dict = alert_data.model_dump()
        
        # Add timestamps
        now = utcnow()
        alert_dict["created_at"] = now
        alert_dict["updated_at"] = now
        
        # Insert into database
        alert_id = await self.insert_one(alert_dict)
        
        # Get the created alert
        alert_doc = await self.find_by_id(alert_id)
        return Alert(**alert_doc)
    
    async def update_alert_status(self, alert_id, status, assigned_to=None):
        update_data = {
            "status": status,
            "updated_at": utcnow()
        }
        
        if assigned_to:
            update_data["assigned_to"] = assigned_to
            
        success = await self.update_one(alert_id, update_data)
        if success:
            alert_doc = await self.find_by_id(alert_id)
            return Alert(**alert_doc)
        return None
"""
    write_file("core/database/repositories/alert_repository.py", alert_repository_content)

    # Create rule repository
    print_colored("Creating rule repository...", Colors.YELLOW)
    rule_repository_content = """from core.database.repositories.base_repository import BaseRepository

class RuleRepository(BaseRepository):
    def __init__(self):
        super().__init__("detection_rules")
"""
    write_file("core/database/repositories/rule_repository.py", rule_repository_content)

    # Create logger utility
    print_colored("Creating logger utility...", Colors.YELLOW)
    logger_content = """import logging
import sys
from config import settings
from utils.time import utcnow

def get_logger(name: str) -> logging.Logger:
    '''Create a logger with the given name.'''
    logger = logging.getLogger(name)
    
    # Set log level based on DEBUG setting
    if settings.DEBUG:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(getattr(logging, settings.LOG_LEVEL))
    
    # Create console handler if not already added
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        
        # Set formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        
        # Add handler to logger
        logger.addHandler(console_handler)
    
    return logger
"""
    write_file("utils/logger.py", logger_content)

    # Create README.md
    print_colored("Creating README.md...", Colors.YELLOW)
    readme_content = """# Core Engine for Unified Threat Detection and Response System (UTDRS)

This is the Core Engine component of the UTDRS, providing threat detection capabilities using signature-based, anomaly-based, and machine learning approaches.

## Features

- Multi-layered threat detection
- Rule-based detection engine
- Machine learning model integration
- MITRE ATT&CK framework mapping
- MongoDB integration for data storage
- Dockerized for easy deployment on Render
- REST API for integration with other components

## Getting Started

### Prerequisites

- Docker and Docker Compose (for local development)
- MongoDB database (can use MongoDB Atlas)

### Local Development

1. **Clone the repository**

```bash
git clone <repository-url>
cd core-engine
```

2. **Configure environment variables**

Copy the example environment file and update it with your settings:

```bash
cp .env.example .env
# Edit .env with your MongoDB connection details and other settings
```

3. **Run using Docker Compose**

```bash
docker-compose up
```

The API will start running at `http://localhost:8001`, and you can access the API documentation at `http://localhost:8001/docs`.

## Deployment on Render

### Using the Render Dashboard

1. Create a new Web Service on Render
2. Select "Build and deploy from a Git repository"
3. Connect your GitHub/GitLab repository
4. Select "Docker" as the runtime
5. Configure environment variables:
   - `MONGODB_URI`: Your MongoDB connection string
   - `DB_NAME`: Database name (default is "utdrs")
   - `API_GATEWAY_URL`: URL of the deployed API Gateway
   - `JWT_SECRET`: A secret key for JWT token generation
   - `DEBUG`: Set to "false" for production

## API Endpoints

- **/health** - Health check endpoints
- **/detections/process** - Process an event and generate alerts
- **/detections/alerts** - Get and manage alerts
- **/rules** - Manage detection rules

## Project Structure

- **api/** - API routes and controllers
- **core/** - Core detection engine logic
  - **detection/** - Detection modules (signature, anomaly, ML)
  - **models/** - Data models and ML models
  - **rules/** - Rule management
  - **services/** - Business logic services
  - **database/** - Database connection and repositories
- **utils/** - Utility functions
- **ml_models/** - Pre-trained ML models
- **tests/** - Test files

## Integration with Other Components

The Core Engine integrates with:

- **API Gateway** - For centralized communication
- **MongoDB** - For data storage
- **Response Service** - For automated threat response
"""
    write_file("README.md", readme_content)

    # Print final instructions
    print_colored("\n=== Core Engine Project Setup Complete ===", Colors.GREEN)
    print_colored("Project structure created successfully.", Colors.YELLOW)
    print("\nTo deploy the Core Engine on Render:")
    print("  1. Push the core-engine folder to a Git repository")
    print("  2. Log in to Render and create a new Web Service")
    print("  3. Select 'Build and deploy from a Git repository'")
    print("  4. Choose Docker as the environment type")
    print("  5. Set up the necessary environment variables:")
    print("     - MONGODB_URI: Your MongoDB connection string")
    print("     - API_GATEWAY_URL: URL of the deployed API Gateway")
    print("     - JWT_SECRET: A secure secret key")
    print("\nTo run locally with Docker:")
    print("  1. cd core-engine")
    print("  2. docker-compose up")
    print("\nAPI documentation will be available at: http://localhost:8001/docs")
    print("\nMake sure to update the MongoDB connection string in the .env file.")
    print_colored("Happy coding!", Colors.YELLOW)

# Execute the script directly when run
if __name__ == "__main__":
    generate_project_structure()