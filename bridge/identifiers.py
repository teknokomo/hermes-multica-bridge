"""Generate monotonic UUID version 7 identifiers using only the standard library."""

from __future__ import annotations

import secrets
import threading
import time
import uuid

_LOCK = threading.Lock()
_LAST_TIMESTAMP_MS = 0
_LAST_RANDOM = 0
_RANDOM_MASK = (1 << 74) - 1
_TIMESTAMP_MASK = (1 << 48) - 1


def uuid7() -> str:
    """Return a lexically sortable UUIDv7 string, including within one millisecond."""
    global _LAST_RANDOM, _LAST_TIMESTAMP_MS

    with _LOCK:
        timestamp_ms = time.time_ns() // 1_000_000
        if timestamp_ms > _LAST_TIMESTAMP_MS:
            random_bits = secrets.randbits(74)
        else:
            timestamp_ms = _LAST_TIMESTAMP_MS
            if _LAST_RANDOM == _RANDOM_MASK:
                raise RuntimeError("UUIDv7 monotonic sequence exhausted for the current timestamp")
            random_bits = _LAST_RANDOM + 1

        if timestamp_ms > _TIMESTAMP_MASK:
            raise RuntimeError("UUIDv7 timestamp exceeds the 48-bit range")
        _LAST_TIMESTAMP_MS = timestamp_ms
        _LAST_RANDOM = random_bits

    rand_a = random_bits >> 62
    rand_b = random_bits & ((1 << 62) - 1)
    value = (timestamp_ms << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return str(uuid.UUID(int=value))
