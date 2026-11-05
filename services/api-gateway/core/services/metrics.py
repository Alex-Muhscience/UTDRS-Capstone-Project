"""
Metrics for Prometheus (GET /api/v1/metrics, with METRICS_TOKEN).

Two kinds:
- Requests: counted by each process in memory (by method, route and status class, with
  their durations in buckets), then added to totals in the database every
  METRICS_FLUSH_SECONDS. Every process therefore reports the same totals, whichever one a
  scrape reaches; totals only grow, as Prometheus counters should.
- The platform's state, read from the database at each scrape: the analysis queue, the
  email outbox, webhook deliveries, connectors, background loops, sessions and open alerts.

Metrics cover every organisation together and are for whoever runs the deployment; they
never carry an organisation's data.
"""
import asyncio
import time
from collections import defaultdict
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Tuple

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings
from core.database.connection import get_database
from core.services import core_engine_client, heartbeat
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

COLLECTION = "metrics_http"
BUCKETS = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

# (method, route, status class) -> [count, duration sum, bucket counts...]
_pending: Dict[Tuple[str, str, str], List[float]] = defaultdict(lambda: [0, 0.0] + [0] * len(BUCKETS))


def record(method: str, route: str, status: int, seconds: float) -> None:
    entry = _pending[(method, route, f"{status // 100}xx")]
    entry[0] += 1
    entry[1] += seconds
    for i, bound in enumerate(BUCKETS):
        if seconds <= bound:
            entry[2 + i] += 1


def route_template(scope: Dict[str, Any]) -> str:
    """
    The route a request matched, with its parameters' names in place of their values
    (/api/v1/alerts/{alert_id}); "unmatched" for a path no route has, so unknown paths do
    not each become a metric.
    """
    if scope.get("route") is None:
        return "unmatched"
    values = {str(v): k for k, v in (scope.get("path_params") or {}).items()}
    return "/".join("{" + values[part] + "}" if part in values else part for part in scope.get("path", "").split("/"))


class RequestMetricsMiddleware(BaseHTTPMiddleware):
    """Counts each request under its route's template (/alerts/{alert_id}), never its actual path."""

    async def dispatch(self, request: Request, call_next):
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            template = route_template(request.scope)
            if not template.endswith("/metrics"):
                record(request.method, template, status, time.perf_counter() - started)


async def flush() -> None:
    """Add what this process counted to the totals."""
    if not _pending:
        return
    taken = dict(_pending)
    _pending.clear()
    collection = get_database()[COLLECTION]
    for (method, route, status), values in taken.items():
        increments: Dict[str, Any] = {"count": values[0], "seconds": values[1]}
        increments.update({f"le_{i}": values[2 + i] for i in range(len(BUCKETS))})
        await collection.update_one({"_id": f"{method} {route} {status}"},
                                    {"$inc": increments, "$set": {"method": method, "route": route, "status": status}}, upsert=True)


async def flush_periodically() -> None:
    while True:
        await asyncio.sleep(settings.METRICS_FLUSH_SECONDS)
        error = None
        try:
            await flush()
        except Exception as e:  # never let the loop die; what was counted is lost, not the process
            logger.error(f"Flushing request metrics failed: {e}")
            error = e
        await heartbeat.beat("metrics_flush", settings.METRICS_FLUSH_SECONDS, error)


# ---------------------------------------------------------------------------- Exposition

def _label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


class _Out:
    def __init__(self) -> None:
        self.lines: List[str] = []

    def metric(self, name: str, kind: str, help_text: str, samples: Iterable[Tuple[Dict[str, Any], float]]) -> None:
        self.lines.append(f"# HELP {name} {help_text}")
        self.lines.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            self.sample(name, labels, value)

    def sample(self, name: str, labels: Dict[str, Any], value: float) -> None:
        text = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
        self.lines.append(f"{name}{{{text}}} {float(value):g}" if text else f"{name} {float(value):g}")


async def _count(collection: str, query: Dict[str, Any]) -> int:
    return await get_database()[collection].count_documents(query)


async def render() -> str:
    """The metrics, in Prometheus's text format."""
    await flush()
    db = get_database()
    now = utcnow()
    day_ago = now - timedelta(days=1)
    out = _Out()

    started = time.perf_counter()
    await db.command("ping")
    out.metric("utdrs_database_ping_seconds", "gauge", "Time for the database to answer a ping.", [({}, time.perf_counter() - started)])

    client = core_engine_client.get_core_engine_client()
    reachable = await client.is_healthy() if client else False
    out.metric("utdrs_core_engine_configured", "gauge", "Whether a core engine is configured.", [({}, client is not None)])
    out.metric("utdrs_core_engine_reachable", "gauge", "Whether the core engine answers its health check.", [({}, reachable)])

    # Requests, from the totals every process adds to.
    http = await db[COLLECTION].find().to_list(5000)
    out.metric("utdrs_http_requests_total", "counter", "Requests answered, by route and status class.",
               [({"method": r["method"], "route": r["route"], "status": r["status"]}, r.get("count", 0)) for r in http])
    by_route: Dict[Tuple[str, str], List[float]] = defaultdict(lambda: [0, 0.0] + [0] * len(BUCKETS))
    for r in http:
        entry = by_route[(r["method"], r["route"])]
        entry[0] += r.get("count", 0)
        entry[1] += r.get("seconds", 0.0)
        for i in range(len(BUCKETS)):
            entry[2 + i] += r.get(f"le_{i}", 0)
    name = "utdrs_http_request_duration_seconds"
    out.lines += [f"# HELP {name} Time to answer requests, by route.", f"# TYPE {name} histogram"]
    for (method, route), entry in sorted(by_route.items()):
        for i, bound in enumerate(BUCKETS):
            out.sample(f"{name}_bucket", {"method": method, "route": route, "le": bound}, entry[2 + i])
        out.sample(f"{name}_bucket", {"method": method, "route": route, "le": "+Inf"}, entry[0])
        out.sample(f"{name}_sum", {"method": method, "route": route}, entry[1])
        out.sample(f"{name}_count", {"method": method, "route": route}, entry[0])

    # Analysis.
    waiting = {"metadata.analysis.status": {"$in": ["queued", "analysing"]}}
    oldest = await db["events"].find_one(waiting, {"metadata.analysis.queued_at": 1}, sort=[("metadata.analysis.queued_at", 1)])
    queued_at = (((oldest or {}).get("metadata") or {}).get("analysis") or {}).get("queued_at")
    out.metric("utdrs_analysis_waiting", "gauge", "Events waiting to be analysed by the core engine.", [({}, await _count("events", waiting))])
    out.metric("utdrs_analysis_oldest_waiting_seconds", "gauge", "How long the oldest waiting event has waited.",
               [({}, (now - _aware(queued_at, now)).total_seconds() if queued_at else 0)])
    out.metric("utdrs_analysis_failed_last_day", "gauge", "Events whose analysis failed for good in the last day.",
               [({}, await _count("events", {"metadata.analysis.status": "error", "metadata.analysis.analysed_at": {"$gte": day_ago}}))])

    from core.services import analysis_stream

    stream = await analysis_stream.status()
    if stream is not None:
        out.metric("utdrs_analysis_stream", "gauge", "The analysis stream (Redis): entries kept, and taken by a worker but not yet acknowledged.",
                   [({"kind": "length"}, stream["length"]), ({"kind": "pending"}, stream["pending"])])

    # Email and webhooks.
    out.metric("utdrs_email_outbox", "gauge", "Emails waiting to be sent, and failed for good in the last day.", [
        ({"status": "queued"}, await _count("notifications", {"status": {"$in": ["queued", "sending"]}})),
        ({"status": "failed"}, await _count("notifications", {"status": "failed", "created_at": {"$gte": day_ago}})),
    ])
    out.metric("utdrs_webhook_deliveries", "gauge", "Webhook deliveries waiting, and failed for good in the last day.", [
        ({"status": "queued"}, await _count("webhook_deliveries", {"status": {"$in": ["queued", "sending"]}})),
        ({"status": "failed"}, await _count("webhook_deliveries", {"status": "failed", "created_at": {"$gte": day_ago}})),
    ])

    # Connectors.
    connectors = await (await db["connections"].aggregate([{"$group": {"_id": {"kind": "$connector", "status": "$status"}, "n": {"$sum": 1}}}])).to_list(100)
    out.metric("utdrs_connectors", "gauge", "Connected services, by kind and status.",
               [({"kind": c["_id"].get("kind") or "unknown", "status": c["_id"].get("status") or "unknown"}, c["n"]) for c in connectors])

    # Background loops.
    loops = await heartbeat.all_loops()
    out.metric("utdrs_loop_last_run_age_seconds", "gauge", "Seconds since each background loop last ran.",
               [({"loop": loop["_id"]}, loop["age_seconds"]) for loop in loops])
    out.metric("utdrs_loop_ok", "gauge", "Whether each background loop's last round succeeded.", [({"loop": loop["_id"]}, loop.get("ok", False)) for loop in loops])
    out.metric("utdrs_loop_stale", "gauge", "Whether each background loop has stopped running.", [({"loop": loop["_id"]}, loop["stale"]) for loop in loops])

    # Use.
    out.metric("utdrs_organisations", "gauge", "Organisations.", [({}, await _count("tenants", {}))])
    out.metric("utdrs_sessions_active", "gauge", "Sessions that have not ended.", [({}, await _count("sessions", {"ended_at": None, "expires_at": {"$gt": now}}))])
    open_alerts = await (await db["alerts"].aggregate([
        {"$match": {"status": {"$nin": ["resolved", "closed", "false_positive"]}}},
        {"$group": {"_id": "$severity", "n": {"$sum": 1}}},
    ])).to_list(20)
    out.metric("utdrs_alerts_open", "gauge", "Alerts not yet resolved, by severity.", [({"severity": a["_id"] or "unknown"}, a["n"]) for a in open_alerts])
    return "\n".join(out.lines) + "\n"


def _aware(value, now):
    return value if value.tzinfo else value.replace(tzinfo=now.tzinfo)
