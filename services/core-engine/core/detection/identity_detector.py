"""
Identity correlations: attacks on accounts that show only across several sign-ins.

Each sign-in event is reduced to a few normalised fields (`identity`: who, from which
address, success or failure, the error code, where, and when), stored with the event so
later sign-ins can be compared with it through indexed queries for one user or one
address, never a scan of everything recent. On each new sign-in:

- **Impossible travel**: a successful sign-in too far from the user's previous one for
  the time between them (faster than a plane), more than MIN_TRAVEL_KM apart.
- **Password spraying**: failures for SPRAY_USERS different accounts from one address
  within SPRAY_WINDOW.
- **Brute force**: BRUTE_FAILURES failures for one account within BRUTE_WINDOW.
- **Brute force, then success**: a successful sign-in after SUCCESS_AFTER_FAILURES
  failures for the account within SUCCESS_WINDOW: the guessing may have worked.
- **MFA fatigue**: MFA_DENIALS multi-factor prompts denied or failed for one account
  within MFA_WINDOW, as when someone bombards a person with prompts until they accept.

Each fires once per account or address per COOLDOWN (a claim in `identity_state`), so
a burst of sign-ins raises one alert, not dozens.
"""
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from pymongo.errors import DuplicateKeyError

from core.database.connection import get_database
from core.tenancy import current_tenant
from utils.logger import get_logger
from utils.time import utcnow

logger = get_logger(__name__)

MIN_TRAVEL_KM = 500
MAX_SPEED_KMH = 900  # a commercial flight
TRAVEL_LOOK_BACK = timedelta(hours=24)
SPRAY_USERS, SPRAY_WINDOW = 10, timedelta(minutes=15)
BRUTE_FAILURES, BRUTE_WINDOW = 10, timedelta(minutes=10)
SUCCESS_AFTER_FAILURES, SUCCESS_WINDOW = 5, timedelta(minutes=30)
MFA_DENIALS, MFA_WINDOW = 5, timedelta(minutes=10)
COOLDOWN = timedelta(hours=1)

FAILED = {"failure", "failed", "denied"}
SUCCEEDED = {"success", "succeeded"}
# Entra ID: "authentication failed during strong authentication request" (MFA denied,
# timed out or failed), and "MFA denied; user declined the authentication".
MFA_DENIED_CODES = {500121, 500124}
STATE = "identity_state"


def _first(data: Dict[str, Any], *names: str) -> Any:
    for name in names:
        value = data.get(name)
        if value not in (None, ""):
            return value
    return None


def _time(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return utcnow()
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def identity_of(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The sign-in fields of an authentication event, normalised; None for other events."""
    if event.get("event_type") != "authentication":
        return None
    data = event.get("data") or {}
    user = _first(data, "user", "username", "user_id", "account")
    outcome = str(_first(data, "status", "result", "action") or "").lower()
    try:
        code = int(_first(data, "error_code") or 0)
    except (TypeError, ValueError):
        code = 0
    try:
        lat, lon = float(data["latitude"]), float(data["longitude"])
    except (KeyError, TypeError, ValueError):
        lat = lon = None
    return {
        "user": str(user).strip().lower() if user else None,
        "ip": _first(data, "source_ip", "src_ip"),
        "outcome": "failure" if outcome in FAILED or code else "success" if outcome in SUCCEEDED else None,
        "error_code": code,
        "lat": lat,
        "lon": lon,
        "place": ", ".join(str(p) for p in (data.get("city"), data.get("country")) if p) or None,
        "at": _time(event.get("timestamp")),
    }


def km_between(a_lat: float, a_lon: float, b_lat: float, b_lon: float) -> float:
    """Great-circle distance (haversine)."""
    radius = 6371.0
    d_lat, d_lon = math.radians(b_lat - a_lat), math.radians(b_lon - a_lon)
    h = math.sin(d_lat / 2) ** 2 + math.cos(math.radians(a_lat)) * math.cos(math.radians(b_lat)) * math.sin(d_lon / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(h))


class IdentityDetector:
    async def ensure_indexes(self) -> None:
        database = get_database()
        await database["events"].create_index([("tenant_id", 1), ("identity.user", 1), ("identity.at", -1)])
        await database["events"].create_index([("tenant_id", 1), ("identity.ip", 1), ("identity.at", -1)])
        await database[STATE].create_index("key", unique=True)
        await database[STATE].create_index("until", expireAfterSeconds=0)

    async def _claim(self, rule: str, subject: str, now: datetime) -> bool:
        """True the first time `rule` fires for `subject` within the cooldown, in this organisation."""
        state = get_database()[STATE]
        key = f"{current_tenant()}:{rule}:{subject}"
        await state.delete_one({"key": key, "until": {"$lte": now}})
        try:
            await state.insert_one({"key": key, "until": now + COOLDOWN})
        except DuplicateKeyError:
            return False
        return True

    async def _recent(self, field: str, value: str, since: datetime, event_id: str) -> List[Dict[str, Any]]:
        cursor = get_database()["events"].find(
            {f"identity.{field}": value, "identity.at": {"$gte": since}, "id": {"$ne": event_id}},
            {"identity": 1, "id": 1},
        ).sort("identity.at", -1)
        events = await cursor.to_list(500)
        for e in events:  # stored times may come back without their time zone
            e["identity"]["at"] = _time(e["identity"].get("at"))
        return events

    def _result(self, name: str, description: str, severity: str, techniques: List[str], tags: List[str], events: List[Dict[str, Any]], **details) -> Dict[str, Any]:
        return {
            "name": name,
            "description": description,
            "severity": severity,
            "detection_type": "correlation",
            "confidence": 0.85,
            "tags": ["identity", *tags, *techniques],
            "mitre_tactics": [],
            "mitre_techniques": techniques,
            "event_ids": [e["id"] for e in events if e.get("id")],
            "details": details,
        }

    async def detect(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        identity = event.get("identity")
        if not identity or not (identity["user"] or identity["ip"]):
            return None
        now, me = identity["at"], {"id": event.get("id"), "identity": identity}
        user, ip = identity["user"], identity["ip"]

        if identity["outcome"] == "failure":
            if identity["error_code"] in MFA_DENIED_CODES and user:
                denials = [e for e in await self._recent("user", user, now - MFA_WINDOW, event.get("id")) if e["identity"].get("error_code") in MFA_DENIED_CODES]
                if len(denials) + 1 >= MFA_DENIALS and await self._claim("mfa_fatigue", user, now):
                    return self._result(
                        "Possible MFA fatigue attack",
                        f"{len(denials) + 1} multi-factor prompts for {user} were denied or failed within {MFA_WINDOW.seconds // 60} minutes. "
                        "Someone with the password may be sending prompts until the person accepts one.",
                        "high", ["T1621"], ["mfa", "account-compromise"], [me, *denials], user=user,
                    )
            if ip:
                failures = [e for e in await self._recent("ip", ip, now - SPRAY_WINDOW, event.get("id")) if e["identity"].get("outcome") == "failure"]
                users = {e["identity"].get("user") for e in failures if e["identity"].get("user")} | ({user} if user else set())
                if len(users) >= SPRAY_USERS and await self._claim("password_spray", ip, now):
                    return self._result(
                        "Password spraying",
                        f"Sign-ins to {len(users)} different accounts failed from {ip} within {SPRAY_WINDOW.seconds // 60} minutes: "
                        "someone is trying common passwords across your accounts.",
                        "high", ["T1110.003"], ["brute-force"], [me, *failures], source_ip=ip, accounts=sorted(users)[:50],
                    )
            if user:
                failures = [e for e in await self._recent("user", user, now - BRUTE_WINDOW, event.get("id")) if e["identity"].get("outcome") == "failure"]
                if len(failures) + 1 >= BRUTE_FAILURES and await self._claim("brute_force", user, now):
                    return self._result(
                        "Password guessing against one account",
                        f"{len(failures) + 1} sign-ins to {user} failed within {BRUTE_WINDOW.seconds // 60} minutes.",
                        "medium", ["T1110.001"], ["brute-force"], [me, *failures], user=user,
                    )
            return None

        if identity["outcome"] != "success" or not user:
            return None
        history = await self._recent("user", user, now - TRAVEL_LOOK_BACK, event.get("id"))
        failures = [e for e in history if e["identity"].get("outcome") == "failure" and e["identity"]["at"] >= now - SUCCESS_WINDOW]
        if len(failures) >= SUCCESS_AFTER_FAILURES and await self._claim("success_after_failures", user, now):
            return self._result(
                "Sign-in succeeded after repeated failures",
                f"{user} signed in successfully after {len(failures)} failed attempts within {SUCCESS_WINDOW.seconds // 60} minutes: "
                "a guessed password may have worked.",
                "high", ["T1110", "T1078"], ["brute-force", "account-compromise"], [me, *failures], user=user,
            )
        if identity["lat"] is None:
            return None
        previous = next((e for e in history if e["identity"].get("outcome") == "success" and e["identity"].get("lat") is not None), None)
        if not previous:
            return None
        before = previous["identity"]
        km = km_between(before["lat"], before["lon"], identity["lat"], identity["lon"])
        hours = max((now - before["at"]).total_seconds() / 3600, 1 / 60)
        if km >= MIN_TRAVEL_KM and km / hours > MAX_SPEED_KMH and await self._claim("impossible_travel", user, now):
            return self._result(
                "Impossible travel",
                f"{user} signed in from {identity['place'] or 'one place'} {round(km)} km from their previous sign-in "
                f"({before.get('place') or 'elsewhere'}) {round(hours * 60)} minutes earlier: faster than anyone can travel. "
                "Someone else may be using the account.",
                "high", ["T1078"], ["account-compromise", "impossible-travel"], [me, previous],
                user=user, km=round(km), minutes=round(hours * 60), speed_kmh=round(km / hours),
            )
        return None
