"""The address a request really came from, behind the proxies we trust."""
import ipaddress
from functools import lru_cache
from typing import List, Tuple

from fastapi import Request

from config import settings

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@lru_cache(maxsize=1)
def _trusted(proxies: Tuple[str, ...]) -> List[Network]:
    return [ipaddress.ip_network(p, strict=False) for p in proxies]


def _is_trusted(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in _trusted(tuple(settings.TRUSTED_PROXIES)))


def client_address(request: Request) -> str:
    """
    The client's address. When the request came through a trusted proxy (the dashboard's
    nginx, a load balancer), X-Forwarded-For is read from the right, skipping trusted
    proxies, so a client cannot pick its own address by sending the header itself.
    """
    peer = request.client.host if request.client else ""
    if not _is_trusted(peer):
        return peer
    forwarded = [a.strip() for a in request.headers.get("x-forwarded-for", "").split(",") if a.strip()]
    for address in reversed(forwarded):
        if not _is_trusted(address):
            return address
    return forwarded[0] if forwarded else peer
