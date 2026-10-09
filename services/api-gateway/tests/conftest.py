"""
Test configuration shared by every test module.

Settings are read when `config` is first imported, so the environment is prepared
here, before any test imports the app. Tests that need a real MongoDB (integration
and end-to-end) only run when MONGODB_URI is provided; each run then uses its own
throwaway database, dropped at the end.
"""
import os
import uuid

import pytest

RUN_DB_TESTS = bool(os.environ.get("MONGODB_URI"))

os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")
os.environ.setdefault("JWT_SECRET", "test-secret-key-not-for-production")
os.environ.setdefault("DB_NAME", f"utdrs_test_{uuid.uuid4().hex[:8]}")
os.environ["UTDRS_RUN_DB_TESTS"] = "1" if RUN_DB_TESTS else ""

requires_mongodb = pytest.mark.skipif(not RUN_DB_TESTS, reason="MONGODB_URI not set")


@pytest.fixture(scope="session", autouse=True)
def drop_test_database():
    yield
    if RUN_DB_TESTS:
        from pymongo import MongoClient

        with MongoClient(os.environ["MONGODB_URI"]) as client:
            client.drop_database(os.environ["DB_NAME"])
