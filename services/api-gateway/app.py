import asyncio
from contextlib import asynccontextmanager, suppress

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from api.middleware.error_handler import ErrorHandlerMiddleware
from api.middleware.security import (
    RequestValidationMiddleware,
    SecurityMiddleware,
    rate_limit_handler,
)
from api.routes import alerts, api_keys, assets, audit, auth, detection, events, health, scans, simulation, tenants as tenant_routes, users
from config import settings
from core.database.connection import close_mongo_connection, connect_to_mongo
from core.database.indexes import ensure_indexes
from core.services import tenants
from core.services.bootstrap import ensure_admin
from core.services.startup_lock import startup_lock
from core.services.audit import audited
from core.services.rule_sync import sync_periodically
from utils.security import require_scope


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    # Every process runs these; they take turns (startup_lock), so they cannot race.
    async with startup_lock():
        # Data from before tenancy belongs to the default organisation; then the
        # indexes, several of which are unique within an organisation.
        await tenants.adopt_untenanted(await tenants.ensure_default())
        await ensure_indexes()
        await ensure_admin()
    rule_sync = asyncio.create_task(sync_periodically())
    yield
    rule_sync.cancel()
    with suppress(asyncio.CancelledError):
        await rule_sync
    await close_mongo_connection()


app = FastAPI(
    lifespan=lifespan,
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    docs_url=f"{settings.API_PREFIX}/docs",
)

# Enhance security middleware
app.add_middleware(
    SecurityMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS,
    docs_paths=(app.docs_url, app.redoc_url),
)
app.add_middleware(RequestValidationMiddleware)
app.add_middleware(ErrorHandlerMiddleware)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes. Routers people and API keys both use check the key's scopes for
# their area (require_scope); the rest are for people, or for UTDRS's own services.
# Changes made through them are also written to the audit log.
def scoped(area):
    return [Depends(require_scope(area)), Depends(audited(area))]


app.include_router(health.router, prefix=settings.API_PREFIX, tags=["health"])
app.include_router(auth.router, prefix=f"{settings.API_PREFIX}/auth", tags=["authentication"])
app.include_router(users.router, prefix=f"{settings.API_PREFIX}/users", tags=["users"], dependencies=scoped("users"))
app.include_router(alerts.router, prefix=f"{settings.API_PREFIX}/alerts", tags=["alerts"], dependencies=scoped("alerts"))
# Events are ingested in volume and are their own record, so they are not audited.
app.include_router(
    events.router, prefix=f"{settings.API_PREFIX}/events", tags=["events"], dependencies=[Depends(require_scope("events"))]
)
app.include_router(assets.router, prefix=f"{settings.API_PREFIX}/assets", tags=["assets"], dependencies=scoped("assets"))
app.include_router(scans.router, prefix=f"{settings.API_PREFIX}/scans", tags=["scans"])
app.include_router(detection.router, prefix=f"{settings.API_PREFIX}/detection", tags=["detection"], dependencies=scoped("rules"))
app.include_router(
    simulation.router, prefix=f"{settings.API_PREFIX}/simulation", tags=["simulation"], dependencies=scoped("simulations")
)
app.include_router(api_keys.router, prefix=f"{settings.API_PREFIX}/api-keys", tags=["api keys"])
app.include_router(audit.router, prefix=f"{settings.API_PREFIX}/audit-log", tags=["audit log"])
app.include_router(tenant_routes.router, prefix=f"{settings.API_PREFIX}/tenants", tags=["organisations"])


@app.get("/")
async def root():
    return {
        "message": "Welcome to the UTDRS API Gateway. Visit /api/v1/docs for documentation."
    }
