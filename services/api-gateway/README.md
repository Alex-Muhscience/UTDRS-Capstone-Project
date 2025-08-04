# UTDRS API Gateway - Production Ready

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-green.svg)](https://fastapi.tiangolo.com/)
[![Security](https://img.shields.io/badge/security-enhanced-brightgreen.svg)](#security-features)
[![SaaS](https://img.shields.io/badge/type-SaaS-orange.svg)](#about)

A production-ready API Gateway for the Unified Threat Detection and Response System (UTDRS). This gateway provides secure, scalable, and monitored access to threat detection and response capabilities with enterprise-grade features including rate limiting, structured logging, comprehensive error handling, and security middleware.

## 🚀 Production-Ready Features

### Security Features
- **Enhanced Security Middleware**: Request validation, sanitization, and security headers
- **Rate Limiting**: Configurable API rate limiting to prevent abuse
- **Input Sanitization**: XSS protection and input validation
- **CORS Configuration**: Configurable cross-origin resource sharing
- **JWT Security**: Secure token-based authentication with configurable expiration
- **Password Security**: bcrypt hashing with configurable rounds

### Monitoring & Observability
- **Structured Logging**: JSON-formatted logs with request tracing
- **Request ID Tracking**: Unique request identifiers for debugging
- **Prometheus Metrics**: Built-in metrics collection
- **Health Checks**: Comprehensive system and database health monitoring
- **Error Tracking**: Centralized error handling and logging

### Performance & Scalability
- **Connection Pooling**: Optimized database connections
- **Async Processing**: Full async/await implementation
- **Request Size Limits**: Configurable payload size restrictions
- **Gunicorn Integration**: Production WSGI server configuration

### Development & Testing
- **Comprehensive Test Suite**: Unit and integration tests
- **Docker Support**: Full containerization with docker-compose
- **CI/CD Ready**: GitHub Actions workflow templates
- **Environment Configuration**: Separate dev/staging/production configs

## Features

- **Authentication and Authorization**
  - JWT-based authentication
  - Role-based access control
  - User registration and profile management
  - Password hashing with bcrypt

- **Alert Management**
  - Create, retrieve, update alerts
  - Filter by status, severity, assignee
  - Tag management and searching
  - Event correlation

- **Event Processing**
  - Event collection and storage
  - Filtering by type, time range, source
  - Severity classification
  - Tagging and metadata

- **Asset Management**
  - Asset inventory and tracking
  - Vulnerability management
  - Status monitoring
  - Criticality classification

- **Detection Rules**
  - Rule creation and management
  - Multiple detection sources support
  - Performance metrics tracking
  - Status control (enabled, disabled, testing)

- **Simulation**
  - Threat simulation creation and execution
  - Scenario-based testing
  - Result tracking and analysis
  - Asset targeting and scope definition

- **Integration**
  - MongoDB integration for data storage
  - Extensible design for connecting with detection and response components
  - Comprehensive API documentation via Swagger

## Getting Started

### Prerequisites

- Python 3.9+
- Docker and Docker Compose (for local development)
- MongoDB database (can use MongoDB Atlas)

### Local Development

1. **Clone the repository**

```bash
git clone <repository-url>
cd api-gateway
```

2. **Set up a virtual environment**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**

```bash
pip install -r requirements.txt
```

4. **Configure environment variables**

Copy the example environment file and update it with your settings:

```bash
cp .env.example .env
# Edit .env with your MongoDB connection details and other settings
```

5. **Run the development server**

```bash
uvicorn app:app --reload
```

The API will start running at `http://localhost:8000`, and you can access the API documentation at `http://localhost:8000/api/v1/docs`.

### Run with Docker

```bash
docker-compose up
```

## Deployment on Render

### Option 1: Using the Render Dashboard

1. Create a new Web Service on Render
2. Select "Build and deploy from a Git repository"
3. Connect your GitHub/GitLab repository
4. Select "Docker" as the runtime
5. Configure environment variables:
   - `MONGODB_URI`: Your MongoDB connection string
   - `DB_NAME`: Database name (default: utdrs)
   - `JWT_SECRET`: A secret key for JWT token generation
   - `DEBUG`: Set to "false" for production

### Option 2: Using render.yaml

1. Push your code to a Git repository
2. In the Render dashboard, select "Blueprint" and connect to your repository
3. Render will automatically detect the `render.yaml` file and set up the service

## API Routes

### Authentication

- **POST /api/v1/auth/login** - User login
- **POST /api/v1/auth/register** - User registration
- **GET /api/v1/auth/me** - Get current user info
- **PUT /api/v1/auth/me** - Update user info
- **POST /api/v1/auth/me/change-password** - Change password

### Alerts

- **GET /api/v1/alerts** - Get all alerts with optional filtering
- **POST /api/v1/alerts** - Create a new alert
- **GET /api/v1/alerts/{alert_id}** - Get a specific alert
- **PUT /api/v1/alerts/{alert_id}** - Update an alert
- **PATCH /api/v1/alerts/{alert_id}/status** - Update alert status
- **PATCH /api/v1/alerts/{alert_id}/assign** - Assign alert to user
- **PATCH /api/v1/alerts/{alert_id}/events/{event_id}** - Add event to alert
- **POST /api/v1/alerts/{alert_id}/tags/{tag}** - Add tag to alert
- **DELETE /api/v1/alerts/{alert_id}/tags/{tag}** - Remove tag from alert
- **GET /api/v1/alerts/search** - Search alerts

### Events

- **GET /api/v1/events** - Get events with optional filtering
- **POST /api/v1/events** - Create a new event
- **GET /api/v1/events/{event_id}** - Get a specific event
- **PUT /api/v1/events/{event_id}** - Update an event
- **GET /api/v1/events/recent** - Get most recent events
- **GET /api/v1/events/timerange** - Get events in time range
- **PATCH /api/v1/events/{event_id}/severity** - Set event severity
- **POST /api/v1/events/{event_id}/tags/{tag}** - Add tag to event
- **DELETE /api/v1/events/{event_id}/tags/{tag}** - Remove tag from event
- **GET /api/v1/events/search** - Search events

### Assets

- **GET /api/v1/assets** - Get assets with optional filtering
- **POST /api/v1/assets** - Create a new asset
- **GET /api/v1/assets/{asset_id}** - Get a specific asset
- **PUT /api/v1/assets/{asset_id}** - Update an asset
- **GET /api/v1/assets/name/{name}** - Get asset by name
- **GET /api/v1/assets/ip/{ip_address}** - Get asset by IP
- **GET /api/v1/assets/mac/{mac_address}** - Get asset by MAC
- **PATCH /api/v1/assets/{asset_id}/vulnerabilities/add** - Add vulnerability to asset
- **PATCH /api/v1/assets/{asset_id}/vulnerabilities/remove** - Remove vulnerability from asset
- **POST /api/v1/assets/{asset_id}/tags/{tag}** - Add tag to asset
- **DELETE /api/v1/assets/{asset_id}/tags/{tag}** - Remove tag from asset
- **PATCH /api/v1/assets/{asset_id}/lastseen** - Update asset last seen
- **GET /api/v1/assets/search** - Search assets

### Detection

- **GET /api/v1/detection** - Get detection system status
- **GET /api/v1/detection/rules** - Get detection rules with filtering
- **POST /api/v1/detection/rules** - Create a new detection rule
- **GET /api/v1/detection/rules/{rule_id}** - Get a specific rule
- **PUT /api/v1/detection/rules/{rule_id}** - Update a rule
- **PATCH /api/v1/detection/rules/{rule_id}/status** - Update rule status
- **GET /api/v1/detection/rules/name/{name}** - Get rule by name
- **POST /api/v1/detection/rules/{rule_id}/tags/{tag}** - Add tag to rule
- **DELETE /api/v1/detection/rules/{rule_id}/tags/{tag}** - Remove tag from rule
- **PATCH /api/v1/detection/rules/{rule_id}/metrics** - Update rule metrics
- **GET /api/v1/detection/rules/search** - Search rules

### Simulation

- **GET /api/v1/simulation** - Get simulations with filtering
- **POST /api/v1/simulation** - Create a new simulation
- **GET /api/v1/simulation/{simulation_id}** - Get a specific simulation
- **PUT /api/v1/simulation/{simulation_id}** - Update a simulation
- **POST /api/v1/simulation/start** - Start a simulation
- **POST /api/v1/simulation/stop** - Stop a simulation
- **GET /api/v1/simulation/scheduled** - Get scheduled simulations
- **GET /api/v1/simulation/running** - Get running simulations
- **PATCH /api/v1/simulation/{simulation_id}/results** - Update simulation results
- **POST /api/v1/simulation/{simulation_id}/events** - Generate simulation event
- **POST /api/v1/simulation/{simulation_id}/alerts/{alert_id}** - Associate alert with simulation
- **GET /api/v1/simulation/search** - Search simulations

### Health

- **GET /api/v1/health** - System health check
- **GET /api/v1/health/db** - Database health check

## Project Structure

- **api/** - API routes, controllers, and middleware
  - **routes/** - API endpoint definitions
  - **controllers/** - Business logic handlers
  - **middleware/** - Request/response middleware
- **core/** - Business logic, models, and data access
  - **models/** - Pydantic models for data validation
  - **database/** - Database connection and repositories
  - **services/** - Service layer for business logic
- **utils/** - Utility functions and helpers
  - **security.py** - Authentication and authorization helpers
  - **logger.py** - Logging configuration
- **tests/** - Test files
  - **unit/** - Unit tests
  - **integration/** - Integration tests
- **Dockerfile** - Docker configuration
- **docker-compose.yml** - Docker Compose configuration
- **render.yaml** - Render deployment configuration

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Copyright and Proprietary Notice

© 2024 UTDRS. All rights reserved.

This software is proprietary and confidential. Unauthorized copying, distribution, or use of this software, via any medium, is strictly prohibited without the express written permission of the copyright owner.

This project is part of a Software as a Service (SaaS) platform and contains trade secrets and proprietary information.
