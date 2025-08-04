from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from app import app
from datetime import datetime
from bson import ObjectId
import json
from utils.security import create_access_token

client = TestClient(app)

# Mock alert data
mock_alert_data = {
    "_id": ObjectId("60d5ec2dcb43a5e37d0c7513"),
    "title": "Suspicious Activity",
    "description": "Multiple failed login attempts detected",
    "severity": "high",
    "source": "SIEM",
    "type": "intrusion",
    "status": "open",
    "tags": ["login", "brute-force"],
    "asset_ids": [],
    "event_ids": [],
    "created_at": datetime.utcnow(),
    "updated_at": datetime.utcnow(),
    "created_by": str(ObjectId("60d5ec2dcb43a5e37d0c7514")),
    "assigned_to": None,
    "notes": None,
    "metadata": {}
}

# Mock user data for authentication
mock_user_data = {
    "_id": ObjectId("60d5ec2dcb43a5e37d0c7514"),
    "username": "testuser",
    "email": "test@example.com",
    "firstName": "Test",
    "lastName": "User",
    "role": "analyst",
    "active": True,
    "id": str(ObjectId("60d5ec2dcb43a5e37d0c7514"))
}

# Helper function to get authorization headers
def get_auth_headers():
    token = create_access_token(data={"sub": str(mock_user_data["_id"])})
    return {"Authorization": f"Bearer {token}"}

@patch('core.services.alert_service.AlertService.get_alerts')
@patch('utils.security.get_current_user')
def test_get_alerts(mock_get_current_user, mock_get_alerts):
    # Setup mocks
    mock_get_current_user.return_value = AsyncMock(return_value=mock_user_data)()
    mock_get_alerts.return_value = AsyncMock(return_value=[mock_alert_data])()
    
    # Test get alerts
    response = client.get(
        "/api/v1/alerts/",
        headers=get_auth_headers()
    )
    
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["title"] == "Suspicious Activity"

@patch('core.services.alert_service.AlertService.create_alert')
@patch('core.services.alert_service.AlertService.get_alert_by_id')
@patch('utils.security.get_current_user')
def test_create_alert(mock_get_current_user, mock_get_alert_by_id, mock_create_alert):
    # Setup mocks
    mock_get_current_user.return_value = AsyncMock(return_value=mock_user_data)()
    mock_create_alert.return_value = AsyncMock(return_value=str(mock_alert_data["_id"]))()
    mock_get_alert_by_id.return_value = AsyncMock(return_value=mock_alert_data)()
    
    # Test create alert
    response = client.post(
        "/api/v1/alerts/",
        headers=get_auth_headers(),
        json={
            "title": "Suspicious Activity",
            "description": "Multiple failed login attempts detected",
            "severity": "high",
            "source": "SIEM",
            "type": "intrusion",
            "status": "open",
            "tags": ["login", "brute-force"],
            "asset_ids": [],
            "event_ids": []
        }
    )
    
    assert response.status_code == 201
    assert response.json()["title"] == "Suspicious Activity"
    assert response.json()["severity"] == "high"

@patch('core.services.alert_service.AlertService.get_alert_by_id')
@patch('utils.security.get_current_user')
def test_get_alert_by_id(mock_get_current_user, mock_get_alert_by_id):
    # Setup mocks
    mock_get_current_user.return_value = AsyncMock(return_value=mock_user_data)()
    mock_get_alert_by_id.return_value = AsyncMock(return_value=mock_alert_data)()
    
    # Test get alert by ID
    response = client.get(
        f"/api/v1/alerts/{str(mock_alert_data['_id'])}",
        headers=get_auth_headers()
    )
    
    assert response.status_code == 200
    assert response.json()["title"] == "Suspicious Activity"
    assert response.json()["_id"] == str(mock_alert_data["_id"])

@patch('core.services.alert_service.AlertService.get_alert_by_id')
@patch('utils.security.get_current_user')
def test_get_alert_not_found(mock_get_current_user, mock_get_alert_by_id):
    # Setup mocks
    mock_get_current_user.return_value = AsyncMock(return_value=mock_user_data)()
    mock_get_alert_by_id.return_value = AsyncMock(return_value=None)()
    
    # Test get non-existent alert
    response = client.get(
        "/api/v1/alerts/60d5ec2dcb43a5e37d0c7599",
        headers=get_auth_headers()
    )
    
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]

@patch('core.services.alert_service.AlertService.update_alert')
@patch('core.services.alert_service.AlertService.get_alert_by_id')
@patch('utils.security.get_current_user')
def test_update_alert(mock_get_current_user, mock_get_alert_by_id, mock_update_alert):
    # Setup mocks
    mock_get_current_user.return_value = AsyncMock(return_value=mock_user_data)()
    
    updated_alert = mock_alert_data.copy()
    updated_alert["status"] = "in_progress"
    updated_alert["notes"] = "Investigating this alert"
    
    mock_update_alert.return_value = AsyncMock(return_value=updated_alert)()
    mock_get_alert_by_id.return_value = AsyncMock(return_value=updated_alert)()
    
    # Test update alert
    response = client.put(
        f"/api/v1/alerts/{str(mock_alert_data['_id'])}",
        headers=get_auth_headers(),
        json={
            "status": "in_progress",
            "notes": "Investigating this alert"
        }
    )
    
    assert response.status_code == 200
    assert response.json()["status"] == "in_progress"
    assert response.json()["notes"] == "Investigating this alert"