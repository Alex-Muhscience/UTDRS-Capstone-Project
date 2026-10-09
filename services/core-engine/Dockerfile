FROM python:3.9-slim

WORKDIR /app

# Install system dependencies needed for Python packages with C extensions
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    build-essential \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Explicitly install pydantic-settings
RUN pip install --no-cache-dir pydantic-settings==2.0.3

COPY . .

# Create a fixed config.py that works with Pydantic v2
RUN echo 'import os\nfrom pydantic_settings import BaseSettings\nfrom pydantic import Field\nfrom typing import Optional\n\nclass Settings(BaseSettings):\n    # MongoDB\n    MONGODB_URI: str\n    DB_NAME: str = "utdrs"\n    \n    # API Gateway\n    API_GATEWAY_URL: str\n    \n    # JWT\n    JWT_SECRET: str\n    JWT_ALGORITHM: str = "HS256"\n    \n    # App\n    DEBUG: bool = False\n    LOG_LEVEL: str = "INFO"\n    MODEL_PATH: str = "ml_models"\n    HOST: str = "0.0.0.0"\n    PORT: int = 8000\n    \n    class Config:\n        env_file = ".env"\n\nsettings = Settings()' > /app/config.py

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Run gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app", "-k", "uvicorn.workers.UvicornWorker"]