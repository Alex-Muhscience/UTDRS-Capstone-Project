from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from api.routes import auth, alerts, events, assets, detection, simulation, health
from core.database.connection import connect_to_mongo, close_mongo_connection
from config.production import settings  # Use production config for production
from api.middleware.security import SecurityMiddleware, RequestValidationMiddleware, rate_limit_handler
from api.middleware.error_handler import ErrorHandlerMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    docs_url=f"{settings.API_PREFIX}/docs",
)

# Enhance security middleware
app.add_middleware(SecurityMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
app.add_middleware(RequestValidationMiddleware)
app.add_middleware(ErrorHandlerMiddleware)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database events
app.add_event_handler("startup", connect_to_mongo)
app.add_event_handler("shutdown", close_mongo_connection)

# Include API routes
app.include_router(health.router, prefix=settings.API_PREFIX, tags=["health"])
app.include_router(auth.router, prefix=f"{settings.API_PREFIX}/auth", tags=["authentication"])
app.include_router(alerts.router, prefix=f"{settings.API_PREFIX}/alerts", tags=["alerts"])
app.include_router(events.router, prefix=f"{settings.API_PREFIX}/events", tags=["events"])
app.include_router(assets.router, prefix=f"{settings.API_PREFIX}/assets", tags=["assets"])
app.include_router(detection.router, prefix=f"{settings.API_PREFIX}/detection", tags=["detection"])
app.include_router(simulation.router, prefix=f"{settings.API_PREFIX}/simulation", tags=["simulation"])

@app.get("/")
async def root():
    return {"message": "Welcome to the UTDRS API Gateway. Visit /api/v1/docs for documentation."}
