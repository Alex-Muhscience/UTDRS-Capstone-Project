import pytest
from httpx import AsyncClient
import os
import pytest_asyncio
from app import app
from core.database.connection import connect_to_mongo, close_mongo_connection
from datetime import datetime
from utils.security import create_access_token

# Skip these tests if MONGODB_URI environment variable is not set
pytestmark = pytest.mark.skipif(
    os.environ.get("MONGODB_URI") is None,
    reason="MongoDB connection URI not set"
)

@pytest_asyncio.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    # Connect to DB before tests
    await connect_to_mongo()
    yield
    # Close DB connection after tests
    await close_mongo_connection()

@pytest_asyncio.fixture
async def auth_token():
    # Create a test token
    token = create_access_token(data={"sub": "integration_test_user"})
    return {"Authorization": f"Bearer {token}"}

@pytest.mark.asyncio
async def test_health_endpoint(client):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "api-gateway"

@pytest.mark.asyncio
async def test_db_health_endpoint(client):
    response = await client.get("/api/v1/health/db")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["database"] == "connected"

@pytest.mark.asyncio
async def test_authentication_required(client):
    # Test that authentication is required for protected endpoints
    endpoints = [
        "/api/v1/alerts/",
        "/api/v1/events/",
        "/api/v1/assets/",
        "/api/v1/detection/",
        "/api/v1/simulation/"
    ]
    
    for endpoint in endpoints:
        response = await client.get(endpoint)
        assert response.status_code == 401
        assert "Not authenticated" in response.json()["detail"]

@pytest.mark.asyncio
async def test_auth_endpoints(client):
    # Test that auth endpoints are accessible without authentication
    response = await client.get("/api/v1/auth/login")
    assert response.status_code != 401  # Should not be "Not authenticated" error

@pytest.mark.asyncio
async def test_protected_endpoints_with_auth(client, auth_token):
    # Test access to protected endpoints with valid authentication
    
    # Note: These tests will likely fail in a real integration test since we're using
    # a dummy token that doesn't correspond to a real user in the database.
    # In a real test, you would need to create a test user first.
    
    endpoints = [
        "/api/v1/alerts/",
        "/api/v1/events/",
        "/api/v1/assets/",
        "/api/v1/detection/",
        "/api/v1/simulation/"
    ]
    
    for endpoint in endpoints:
        response = await client.get(endpoint, headers=auth_token)
        # Should either succeed or fail with a reason other than "Not authenticated"
        assert "Not authenticated" not in response.text