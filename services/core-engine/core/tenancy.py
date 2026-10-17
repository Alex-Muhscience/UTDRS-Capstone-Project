"""
Tenancy in the engine: each organisation's events and alerts are kept apart.

The gateway sends every event with its organisation's tenant_id. While the engine
processes it, that tenant is current (tenant_context), and the database the detectors
use (core.database.connection.get_database) shows them only that organisation's
events and alerts: the history correlation and anomaly detection compare against, and
the alerts they count. So one organisation's activity can never trigger, or hide, a
detection in another's. Detection rules are not scoped this way: built-in rules apply
to everyone, and each organisation's own rules are selected by tenant_id explicitly
(SignatureDetector, RuleManager.replace_managed_rules).

Outside event processing (the internal rules and alerts APIs, start-up) no tenant is
set and the database is seen whole.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Dict, Iterator, Mapping, Optional

FIELD = "tenant_id"
# For events sent without a tenant, by callers from before tenancy.
DEFAULT_TENANT = "default"
TENANT_SCOPED = {"events", "alerts", "risk_assessments", "system_info"}

_current: ContextVar[Optional[str]] = ContextVar("tenant_id", default=None)


class TenantScopeError(RuntimeError):
    """A tenant-scoped collection was used across tenants."""


def current_tenant() -> Optional[str]:
    return _current.get()


@contextmanager
def tenant_context(tenant_id: str) -> Iterator[None]:
    token = _current.set(tenant_id or DEFAULT_TENANT)
    try:
        yield
    finally:
        _current.reset(token)


def _filter(query: Optional[Mapping[str, Any]], tenant_id: str) -> Dict[str, Any]:
    query = dict(query or {})
    if FIELD in query and query[FIELD] != tenant_id:
        raise TenantScopeError("A query named another tenant")
    query[FIELD] = tenant_id
    return query


def _stamp(document: Dict[str, Any], tenant_id: str) -> Dict[str, Any]:
    if document.get(FIELD, tenant_id) != tenant_id:
        raise TenantScopeError("A document for another tenant was inserted")
    document[FIELD] = tenant_id
    return document


def _check_update(update: Any) -> None:
    for stage in update if isinstance(update, list) else [update]:
        if isinstance(stage, Mapping):
            for fields in stage.values():
                if isinstance(fields, Mapping) and FIELD in fields:
                    raise TenantScopeError(f"An update tried to change {FIELD}")


class ScopedCollection:
    """A collection seen as one tenant: only its documents exist."""

    def __init__(self, collection, tenant_id: str):
        self._collection, self._tenant = collection, tenant_id

    @property
    def name(self):
        return self._collection.name

    def find(self, filter=None, *args, **kwargs):
        return self._collection.find(_filter(filter, self._tenant), *args, **kwargs)

    async def find_one(self, filter=None, *args, **kwargs):
        return await self._collection.find_one(_filter(filter, self._tenant), *args, **kwargs)

    async def count_documents(self, filter=None, *args, **kwargs):
        return await self._collection.count_documents(_filter(filter, self._tenant), *args, **kwargs)

    async def distinct(self, key, filter=None, *args, **kwargs):
        return await self._collection.distinct(key, _filter(filter, self._tenant), *args, **kwargs)

    async def aggregate(self, pipeline, *args, **kwargs):
        return await self._collection.aggregate([{"$match": {FIELD: self._tenant}}, *pipeline], *args, **kwargs)

    async def insert_one(self, document, *args, **kwargs):
        return await self._collection.insert_one(_stamp(document, self._tenant), *args, **kwargs)

    async def insert_many(self, documents, *args, **kwargs):
        return await self._collection.insert_many([_stamp(d, self._tenant) for d in documents], *args, **kwargs)

    async def update_one(self, filter, update, *args, **kwargs):
        _check_update(update)
        return await self._collection.update_one(_filter(filter, self._tenant), update, *args, **kwargs)

    async def update_many(self, filter, update, *args, **kwargs):
        _check_update(update)
        return await self._collection.update_many(_filter(filter, self._tenant), update, *args, **kwargs)

    async def delete_one(self, filter, *args, **kwargs):
        return await self._collection.delete_one(_filter(filter, self._tenant), *args, **kwargs)

    async def delete_many(self, filter, *args, **kwargs):
        return await self._collection.delete_many(_filter(filter, self._tenant), *args, **kwargs)

    def __getattr__(self, name):
        raise TenantScopeError(f"{name} is not available on a tenant-scoped collection")


class TenantDatabase:
    """A database whose tenant-scoped collections show only the current tenant, if one is set."""

    def __init__(self, database):
        self._database = database

    def _collection(self, name):
        collection = self._database[name]
        tenant_id = current_tenant()
        if tenant_id and name in TENANT_SCOPED:
            return ScopedCollection(collection, tenant_id)
        return collection

    def __getitem__(self, name):
        return self._collection(name)

    def __getattr__(self, name):
        if name in TENANT_SCOPED:
            return self._collection(name)
        return getattr(self._database, name)
