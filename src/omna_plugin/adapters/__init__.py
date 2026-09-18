from __future__ import annotations

from .base import SiteAdapter
from .generic import GenericAdapter

_GENERIC = GenericAdapter()
_REGISTRY: list[SiteAdapter] = []   # site adapters register themselves (a later task, not yours)


def register(adapter: SiteAdapter) -> None:
    _REGISTRY.append(adapter)


def for_host(host: str) -> SiteAdapter:
    h = (host or "").lower()
    for a in _REGISTRY:
        if any(h == s or h.endswith("." + s) for s in a.hosts):
            return a
    return _GENERIC
