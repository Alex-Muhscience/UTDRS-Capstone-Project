"""
Test configuration shared by every test module.

Settings are read when `config` is first imported, so the environment is prepared
here. Tests that need MongoDB use the `mongo` fixture and only run when MONGODB_URI
is provided; each run uses its own throwaway database.
"""
import os
import uuid

import pytest
import pytest_asyncio

RUN_DB_TESTS = bool(os.environ.get("MONGODB_URI"))

os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", f"utdrs_core_test_{uuid.uuid4().hex[:8]}")
# Never call real threat-intelligence services from tests.
os.environ["ENABLE_THREAT_INTEL"] = "false"
for key in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"):
    os.environ.pop(key, None)

requires_mongodb = pytest.mark.skipif(not RUN_DB_TESTS, reason="MONGODB_URI not set")


@pytest_asyncio.fixture
async def mongo():
    """A connected database, emptied after the test."""
    if not RUN_DB_TESTS:
        pytest.skip("MONGODB_URI not set")
    from core.database.connection import close_mongo_connection, connect_to_mongo, get_database

    await connect_to_mongo()
    database = get_database()
    yield database
    await database.client.drop_database(database.name)
    await close_mongo_connection()
