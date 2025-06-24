from types import ModuleType
from typing import Optional

from . import lrucache, lrucache_evict

SUITES: list[tuple[ModuleType, Optional[int]]] = [
    (lrucache, None),
    (lrucache_evict, None),
]
