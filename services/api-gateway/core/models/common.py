"""Field types shared by the API models."""
from typing import Annotated, Any

from bson import ObjectId
from pydantic import BeforeValidator, PlainSerializer, WithJsonSchema


def _to_object_id(value: Any) -> ObjectId:
    if isinstance(value, ObjectId):
        return value
    if isinstance(value, str) and ObjectId.is_valid(value):
        return ObjectId(value)
    raise ValueError("Invalid ObjectId")


def _to_id_string(value: Any) -> Any:
    return str(value) if isinstance(value, ObjectId) else value


# A MongoDB ObjectId inside the application, serialised as a string.
PyObjectId = Annotated[
    ObjectId,
    BeforeValidator(_to_object_id),
    PlainSerializer(str, return_type=str),
    WithJsonSchema({"type": "string"}),
]

# A document id in API responses: accepts the ObjectId read from MongoDB, exposes a string.
IdString = Annotated[str, BeforeValidator(_to_id_string)]
