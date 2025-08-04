from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field, validator
from bson import ObjectId

class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")

class UserBase(BaseModel):
    username: str
    email: EmailStr
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    role: str = "analyst"  # admin, analyst, responder, readonly
    active: bool = True

class UserCreate(UserBase):
    password: str

class UserInDB(UserBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    passwordHash: str
    lastLogin: Optional[datetime] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)
    updatedAt: datetime = Field(default_factory=datetime.utcnow)
    preferences: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }
        schema_extra = {
            "example": {
                "_id": "60d5ec2dcb43a5e37d0c7513",
                "username": "analyst1",
                "email": "analyst1@example.com",
                "firstName": "John",
                "lastName": "Doe",
                "role": "analyst",
                "active": True,
                "passwordHash": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
                "lastLogin": "2023-04-01T10:00:00.000Z",
                "createdAt": "2023-01-01T00:00:00.000Z",
                "updatedAt": "2023-04-01T10:00:00.000Z",
                "preferences": {"theme": "dark", "alertsPerPage": 20}
            }
        }

class User(UserBase):
    id: str = Field(..., alias="_id")
    lastLogin: Optional[datetime] = None
    createdAt: datetime
    updatedAt: datetime
    preferences: Dict[str, Any] = {}

    class Config:
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "_id": "60d5ec2dcb43a5e37d0c7513",
                "username": "analyst1",
                "email": "analyst1@example.com",
                "firstName": "John",
                "lastName": "Doe",
                "role": "analyst",
                "active": True,
                "lastLogin": "2023-04-01T10:00:00.000Z",
                "createdAt": "2023-01-01T00:00:00.000Z",
                "updatedAt": "2023-04-01T10:00:00.000Z",
                "preferences": {"theme": "dark", "alertsPerPage": 20}
            }
        }

class UserUpdate(BaseModel):
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    active: Optional[bool] = None
    preferences: Optional[Dict[str, Any]] = None
