from contextlib import asynccontextmanager

from fastapi import FastAPI
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
from api.routes import alerts, assets, auth, detection, events, health, scans, simulation, users
from config import settings
from core.database.connection import close_mongo_connection, connect_to_mongo
from core.database.indexes import ensure_indexes
from core.services.bootstrap import ensure_admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    await ensure_indexes()
    await ensure_admin()
    yield
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

# Include API routes
app.include_router(health.router, prefix=settings.API_PREFIX, tags=["health"])
app.include_router(
    auth.router, prefix=f"{settings.API_PREFIX}/auth", tags=["authentication"]
)
app.include_router(users.router, prefix=f"{settings.API_PREFIX}/users", tags=["users"])
app.include_router(
    alerts.router, prefix=f"{settings.API_PREFIX}/alerts", tags=["alerts"]
)
app.include_router(
    events.router, prefix=f"{settings.API_PREFIX}/events", tags=["events"]
)
app.include_router(
    assets.router, prefix=f"{settings.API_PREFIX}/assets", tags=["assets"]
)
app.include_router(scans.router, prefix=f"{settings.API_PREFIX}/scans", tags=["scans"])
app.include_router(
    detection.router, prefix=f"{settings.API_PREFIX}/detection", tags=["detection"]
)
app.include_router(
    simulation.router, prefix=f"{settings.API_PREFIX}/simulation", tags=["simulation"]
)


@app.get("/")
async def root():
    return {
        "message": "Welcome to the UTDRS API Gateway. Visit /api/v1/docs for documentation."
    }
