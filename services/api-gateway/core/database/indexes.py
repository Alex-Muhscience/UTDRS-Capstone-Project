"""Indexes the gateway relies on, created at start-up (creating an existing one is a no-op)."""
from pymongo.errors import OperationFailure

from core.database.connection import get_database
from core.services import api_keys, audit, case_service, login_throttle, notifications, playbooks, response_actions
from core.tenancy import TENANT_SCOPED
from utils.logger import get_logger

logger = get_logger(__name__)


async def ensure_indexes() -> None:
    await login_throttle.ensure_indexes()
    await api_keys.ensure_indexes()
    await audit.ensure_indexes()
    await case_service.ensure_indexes()
    await response_actions.ensure_indexes()
    await playbooks.ensure_indexes()
    await notifications.ensure_indexes()

    database = get_database()
    await database["tenants"].create_index("slug", unique=True)
    for name in sorted(TENANT_SCOPED):
        await database[name].create_index("tenant_id")

    # One asset per name within an organisation: device scans find and update the asset
    # by its name, and two first scans arriving together must not create it twice.
    assets = database["assets"]
    if "name_unique" in await assets.index_information():
        try:
            await assets.drop_index("name_unique")  # before tenancy, names were unique overall
        except OperationFailure as e:
            if e.code != 27:  # IndexNotFound: already dropped
                raise
    try:
        await assets.create_index([("tenant_id", 1), ("name", 1)], unique=True, name="tenant_name_unique")
    except OperationFailure as e:
        if e.code != 11000:  # duplicate key: existing data already has repeated names
            raise
        logger.warning(
            "Assets with the same name exist, so names cannot be made unique. Rename or "
            "merge them, then restart the gateway; until then, a device scan may create "
            f"a duplicate asset. ({e.details.get('errmsg', e)})"
        )
