from __future__ import annotations

from time import monotonic

from .concurrency import AtomicValue


class TTLCache:
    def __init__(self, ttl_seconds: int = 5):
        self.ttl_seconds = ttl_seconds
        self._state = AtomicValue((0.0, None))

    def get(self):
        ts, value = self._state.get()
        if value is not None and monotonic() - ts < self.ttl_seconds:
            return value
        return None

    def set(self, value) -> None:
        self._state.swap((monotonic(), value))

    def invalidate(self) -> None:
        self._state.swap((0.0, None))
