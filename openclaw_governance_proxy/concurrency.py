from __future__ import annotations

from threading import RLock


class AtomicValue:
    def __init__(self, value=None):
        self._value = value
        self._lock = RLock()

    def get(self):
        with self._lock:
            return self._value

    def swap(self, value) -> None:
        with self._lock:
            self._value = value
