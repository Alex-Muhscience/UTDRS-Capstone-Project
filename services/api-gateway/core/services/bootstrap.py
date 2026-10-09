"""Start-up tasks that make a fresh deployment usable."""
from pydantic import ValidationError

from config import settings
from core.database.repositories.user_repository import UserRepository
from core.models.user import ADMIN, UserCreate, UserUpdate
from utils.logger import get_logger

logger = get_logger(__name__)


async def ensure_admin() -> None:
    """
    Make ADMIN_USERNAME an active administrator: create the account (with
    ADMIN_PASSWORD) if it does not exist, otherwise promote and reactivate it.
    An existing account's password is never changed here.
    """
    username = settings.ADMIN_USERNAME
    if not username:
        return

    users = UserRepository()
    existing = await users.find_by_username(username)
    if existing:
        if existing.get("role") != ADMIN or not existing.get("active", True):
            await users.update_user(str(existing["_id"]), UserUpdate(role=ADMIN, active=True))
            logger.info(f"Made {username} an active administrator")
        return

    if not settings.ADMIN_PASSWORD:
        logger.warning(f"ADMIN_USERNAME is set but ADMIN_PASSWORD is not; {username} was not created")
        return

    try:
        admin = UserCreate(
            username=username,
            email=settings.ADMIN_EMAIL or f"{username}@localhost.localdomain",
            password=settings.ADMIN_PASSWORD,
            role=ADMIN,
            active=True,
        )
    except ValidationError as exc:
        problems = "; ".join(error["msg"].removeprefix("Value error, ") for error in exc.errors())
        raise RuntimeError(f"Cannot create the administrator from ADMIN_* settings: {problems}") from None
    await users.create_user(admin)
    logger.info(f"Created the administrator {username}")
