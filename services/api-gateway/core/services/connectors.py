"""
Connectors: how UTDRS reaches the services an organisation uses, such as Microsoft 365.

Each connector registers a factory that returns an HTTP client for the current
organisation (authenticated, with the service's base URL), or None when that
organisation has not connected it. Response actions use these clients, so they never
handle credentials themselves. The Microsoft 365 connector registers "m365" once an
organisation connects it; until then its actions report that it is not connected.
"""
from typing import Awaitable, Callable, Dict, Optional

import httpx

ClientFactory = Callable[[], Awaitable[Optional[httpx.AsyncClient]]]

NAMES = {"m365": "Microsoft 365", "utdrs": "UTDRS"}

_factories: Dict[str, ClientFactory] = {}


def register(connector: str, factory: ClientFactory) -> None:
    _factories[connector] = factory


def unregister(connector: str) -> None:
    _factories.pop(connector, None)


async def client(connector: str) -> Optional[httpx.AsyncClient]:
    """A client for `connector` as the current organisation, or None when it is not connected."""
    factory = _factories.get(connector)
    return await factory() if factory else None


async def connected(connector: str) -> bool:
    if connector == "utdrs":
        return True
    found = await client(connector)
    if found is None:
        return False
    await found.aclose()
    return True
