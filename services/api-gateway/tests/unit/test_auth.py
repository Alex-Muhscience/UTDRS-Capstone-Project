from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from app import app
from datetime import datetime
from bson import ObjectId

client = TestClient(app)

mock_user_data = {
    "_id": ObjectId("60d5ec2dcb43a5e37d0c7513"),
    "username": "testuser",
    "email": "test@example.com",
    "firstName": "Test",
    "lastName": "User",
    "role": "analyst",
    "active": True,
    "passwordHash": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
    "createdAt": datetime.utcnow(),
    "updatedAt": datetime.utcnow(),
    "preferences": {}
}

@patch('core.database.repositories.user_repository.UserRepository.find_by_username')
@patch('core.database.repositories.user_repository.UserRepository.update_last_login')
def test_login_success(mock_update_last_login, mock_find_by_username):
    # Setup mocks
    mock_find_by_username.return_value = AsyncMock(return_value=mock_user_data)()
    mock_update_last_login.return_value = AsyncMock(return_value=True)()
    
    # Test login
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "password"}
    )
    
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"
    assert response.json()["user"]["username"] == "testuser"

@patch('core.database.repositories.user_repository.UserRepository.find_by_username')
def test_login_wrong_password(mock_find_by_username):
    # Setup mocks
    mock_find_by_username.return_value = AsyncMock(return_value=mock_user_data)()
    
    # Test login with wrong password
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "wrongpassword"}
    )
    
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]

@patch('core.database.repositories.user_repository.UserRepository.find_by_username')
def test_login_user_not_found(mock_find_by_username):
    # Setup mocks
    mock_find_by_username.return_value = AsyncMock(return_value=None)()
    
    # Test login with non-existent user
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "nonexistent", "password": "password"}
    )
    
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]

@patch('core.database.repositories.user_repository.UserRepository.find_by_username')
@patch('core.database.repositories.user_repository.UserRepository.find_by_email')
@patch('core.database.repositories.user_repository.UserRepository.create_user')
@patch('core.database.repositories.user_repository.UserRepository.find_by_id')
def test_register_success(mock_find_by_id, mock_create_user, mock_find_by_email, mock_find_by_username):
    # Setup mocks
    mock_find_by_username.return_value = AsyncMock(return_value=None)()
    mock_find_by_email.return_value = AsyncMock(return_value=None)()
    mock_create_user.return_value = AsyncMock(return_value=str(mock_user_data["_id"]))()
    mock_find_by_id.return_value = AsyncMock(return_value=mock_user_data)()
    
    # Test registration
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "newuser",
            "email": "new@example.com",
            "password": "password123",
            "firstName": "New",
            "lastName": "User"
        }
    )
    
    assert response.status_code == 200
    assert response.json()["username"] == "testuser"  # From the mock
    assert response.json()["email"] == "test@example.com"  # From the mock

@patch('core.database.repositories.user_repository.UserRepository.find_by_username')
def test_register_username_exists(mock_find_by_username):
    # Setup mocks
    mock_find_by_username.return_value = AsyncMock(return_value=mock_user_data)()
    
    # Test registration with existing username
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "testuser",
            "email": "new@example.com",
            "password": "password123",
            "firstName": "New",
            "lastName": "User"
        }
    )
    
    assert response.status_code == 400
    assert "Username already registered" in response.json()["detail"]