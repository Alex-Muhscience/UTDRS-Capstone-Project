"""
Tenancy: every organisation's data is kept apart, enforced here rather than in each query.

A tenant is one organisation. Authentication sets the caller's tenant for the rest of the
request (current_tenant). Collections holding an organisation's data are reached through
ScopedCollection, which adds the tenant to every filter, stamps it on every document
inserted, and refuses to move a document to another tenant. With no tenant set, a scoped
collection refuses to run at all, so forgetting to set one fails closed rather than
reading or writing every organisation's data.

Code that legitimately works across tenants (sign-in, before anyone is known; start-up
tasks) uses `unscoped(...)` explicitly, so every such place is easy to find.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Dict, Iterator, List, Mapping, Optional

FIELD = "tenant_id"

# Collections that hold an organisation's data. Everything else is platform-wide.
TENANT_SCOPED = {
    "users",
    "events",
    "alerts",
    "cases",
    "assets",
    "detection_rules",
    "simulations",
    "api_keys",
    "audit_log",
    "audit_log_head",
    "gateway_state",
}

# The tenant for entries that belong to no organisation, such as a sign-in attempt with
# a username nobody has. Nobody's requests run as it.
PLATFORM = "platform"

_current: ContextVar[Optional[str]] = ContextVar("tenant_id", default=None)


class TenantScopeError(RuntimeError):
    """A scoped collection was used with no tenant set, or across tenants."""


def current_tenant() -> str:
    tenant_id = _current.get()
    if not tenant_id:
        raise TenantScopeError("No tenant is set for this operation")
    return tenant_id


def current_tenant_or_none() -> Optional[str]:
    return _current.get()


def set_tenant(tenant_id: str) -> None:
    """Set the tenant for the rest of the current request or task."""
    if not tenant_id:
        raise TenantScopeError("A tenant id is required")
    _current.set(tenant_id)


@contextmanager
def tenant_context(tenant_id: str) -> Iterator[None]:
    """Run a block as one tenant, then restore whatever was set before."""
    if not tenant_id:
        raise TenantScopeError("A tenant id is required")
    token = _current.set(tenant_id)
    try:
        yield
    finally:
        _current.reset(token)


def _scoped_filter(query: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    tenant_id = current_tenant()
    query = dict(query or {})
    if FIELD in query and query[FIELD] != tenant_id:
        raise TenantScopeError("A query named another tenant")
    query[FIELD] = tenant_id
    return query


def _check_update(update: Any) -> None:
    """An update may not set or remove the tenant."""
    stages = update if isinstance(update, list) else [update]
    for stage in stages:
        if not isinstance(stage, Mapping):
            continue
        for operator, fields in stage.items():
            if isinstance(fields, Mapping) and any(k == FIELD or k.startswith(f"{FIELD}.") for k in fields):
                raise TenantScopeError(f"An update tried to change {FIELD}")
            if operator in ("$unset", "$project") and fields == FIELD:
                raise TenantScopeError(f"An update tried to change {FIELD}")


def _stamp(document: Dict[str, Any]) -> Dict[str, Any]:
    tenant_id = current_tenant()
    if document.get(FIELD, tenant_id) != tenant_id:
        raise TenantScopeError("A document for another tenant was inserted")
    document[FIELD] = tenant_id
    return document


class ScopedCollection:
    """A MongoDB collection seen as the current tenant: only its documents exist."""

    def __init__(self, collection):
        self._collection = collection

    @property
    def name(self) -> str:
        return self._collection.name

    def unscoped(self):
        """The underlying collection, across every tenant. Use sparingly and say why."""
        return self._collection

    # Reads
    def find(self, filter=None, *args, **kwargs):
        return self._collection.find(_scoped_filter(filter), *args, **kwargs)

    async def find_one(self, filter=None, *args, **kwargs):
        return await self._collection.find_one(_scoped_filter(filter), *args, **kwargs)

    async def count_documents(self, filter=None, *args, **kwargs):
        return await self._collection.count_documents(_scoped_filter(filter), *args, **kwargs)

    async def distinct(self, key, filter=None, *args, **kwargs):
        return await self._collection.distinct(key, _scoped_filter(filter), *args, **kwargs)

    async def aggregate(self, pipeline: List[Dict[str, Any]], *args, **kwargs):
        return await self._collection.aggregate([{"$match": _scoped_filter({})}, *pipeline], *args, **kwargs)

    # Writes
    async def insert_one(self, document, *args, **kwargs):
        return await self._collection.insert_one(_stamp(document), *args, **kwargs)

    async def insert_many(self, documents, *args, **kwargs):
        return await self._collection.insert_many([_stamp(d) for d in documents], *args, **kwargs)

    async def update_one(self, filter, update, *args, **kwargs):
        _check_update(update)
        return await self._collection.update_one(_scoped_filter(filter), update, *args, **kwargs)

    async def update_many(self, filter, update, *args, **kwargs):
        _check_update(update)
        return await self._collection.update_many(_scoped_filter(filter), update, *args, **kwargs)

    async def replace_one(self, filter, replacement, *args, **kwargs):
        return await self._collection.replace_one(_scoped_filter(filter), _stamp(dict(replacement)), *args, **kwargs)

    async def find_one_and_update(self, filter, update, *args, **kwargs):
        _check_update(update)
        return await self._collection.find_one_and_update(_scoped_filter(filter), update, *args, **kwargs)

    async def find_one_and_replace(self, filter, replacement, *args, **kwargs):
        return await self._collection.find_one_and_replace(_scoped_filter(filter), _stamp(dict(replacement)), *args, **kwargs)

    async def find_one_and_delete(self, filter, *args, **kwargs):
        return await self._collection.find_one_and_delete(_scoped_filter(filter), *args, **kwargs)

    async def delete_one(self, filter, *args, **kwargs):
        return await self._collection.delete_one(_scoped_filter(filter), *args, **kwargs)

    async def delete_many(self, filter, *args, **kwargs):
        return await self._collection.delete_many(_scoped_filter(filter), *args, **kwargs)

    # Anything else (bulk_write, watch, ...) would bypass the scope: refuse rather than guess.
    def __getattr__(self, name):
        raise TenantScopeError(f"{name} is not available on a tenant-scoped collection; use unscoped() deliberately")


def scoped(database, name: str):
    """The collection `name`, scoped to the current tenant when it holds tenant data."""
    collection = database[name]
    return ScopedCollection(collection) if name in TENANT_SCOPED else collection


def unscoped(database, name: str):
    """The collection `name` across every tenant. For sign-in and platform tasks only."""
    return database[name]
