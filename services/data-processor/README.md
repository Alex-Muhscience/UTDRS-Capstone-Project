# MongoDB Data Processor

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![MongoDB](https://img.shields.io/badge/MongoDB-4.4%2B-green)
![License](https://img.shields.io/badge/license-MIT-orange)

A robust data processing pipeline that continuously transforms MongoDB documents with batch processing, error handling, and monitoring.

## Features

- **Batch Processing**: Configurable document batch size
- **Dead Letter Queue**: Failed documents stored with error context
- **Health Monitoring**: REST endpoint with metrics
- **Resilient**: Automatic retries and error tracking
- **Configurable**: Environment variable driven

## Quick Start

```bash
# Clone and install
git clone https://github.com/your-repo/mongodb-data-processor.git
cd mongodb-data-processor
pip install -r requirements.txt

# Configure (adjust as needed)
export MONGODB_URI="mongodb://localhost:27017/"
export BATCH_SIZE=20

# Run
python data_processor.py

# Check health (in another terminal)
curl http://localhost:5000/health
Configuration
Variable Description Default
MONGODB_URI MongoDB connection string mongodb://localhost:27017/
BATCH_SIZE Documents per batch 10
PROCESSING_INTERVAL Seconds between cycles 5
MAX_RETRIES Connection retries 3
API Endpoints
GET /health

json
Copy
{
  "status": "running",
  "uptime": 125.67,
  "metrics": {
    "processed": 42,
    "failed": 3,
    "last_processed": "2023-10-15T14:32:18.123456",
    "avg_processing_time": 0.45
  }
}
Architecture
mermaid
Copy
graph LR
    A[Source] --> B[Processor]
    B --> C[Processed]
    B --> D[Dead Letters]
    E[Health] --> B
Deployment
Docker Example:

dockerfile
Copy
FROM python:3.9-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "data_processor.py"]
Build and run:

bash
Copy
docker build -t data-processor .
docker run -e MONGODB_URI="mongodb://host.docker.internal:27017/" data-processor
License
MIT - See LICENSE for details.
