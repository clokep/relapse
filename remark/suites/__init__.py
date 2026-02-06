from types import ModuleType

from . import lrucache, lrucache_evict

SUITES: list[tuple[ModuleType, int | None]] = [
    (lrucache, None),
    (lrucache_evict, None),
]
