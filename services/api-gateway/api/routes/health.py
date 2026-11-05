import hmac

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from config import settings
from core.database.connection import get_database
from utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter()


@router.api_route("/health", methods=["GET", "HEAD"])
async def health_check():
    """Health check endpoint to verify API and database are working."""
    return {"status": "ok", "service": "api-gateway"}


@router.api_route("/health/db", methods=["GET", "HEAD"])
async def database_health_check():
    """Check database connection health."""
    db = get_database()
    try:
        # Execute simple command to check DB connection
        await db.command("ping")
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        logger.error(f"Database health check failed: {e}")  # the reason is for the logs, not the public
        return JSONResponse(status_code=503, content={"status": "error", "database": "disconnected"})


@router.api_route("/health/ready", methods=["GET", "HEAD"])
async def readiness_check():
    """
    For load balancers and uptime monitors: 200 when the gateway can serve (its database
    answers), 503 when it cannot. `problems` lists what is failing on the platform (the
    core engine, the analysis backlog, email, background loops), which does not stop it serving.
    """
    from core.services import platform_health

    try:
        await get_database().command("ping")
    except Exception as e:
        logger.error(f"Readiness check: the database does not answer: {e}")
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": "disconnected"})
    problems = await platform_health.summary()
    return {"status": "degraded" if problems else "ok", "database": "connected", "problems": problems}


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    """Prometheus metrics (text format), for a scraper holding METRICS_TOKEN as a bearer token."""
    from core.services import metrics as metrics_service

    expected = settings.METRICS_TOKEN
    if not expected:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    given = request.headers.get("authorization", "")
    if not hmac.compare_digest(given.encode(), f"Bearer {expected}".encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Metrics need METRICS_TOKEN", headers={"WWW-Authenticate": "Bearer"})
    return Response(content=await metrics_service.render(), media_type="text/plain; version=0.0.4; charset=utf-8")
