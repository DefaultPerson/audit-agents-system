"""
In-memory price cache with TTL support.
Uses simple dict-based caching for performance.
"""

import time
from dataclasses import dataclass
from threading import Lock


@dataclass
class CacheEntry:
    """Cache entry with value and expiration timestamp."""

    value: float
    expires_at: float


class PriceCache:
    """
    Thread-safe in-memory cache for prices with TTL.

    Uses simple dict storage for fast lookups.
    Expired entries are cleaned up lazily on access.
    """

    def __init__(self, ttl_seconds: int = 60):
        """
        Initialize cache.

        Args:
            ttl_seconds: Time-to-live in seconds (default: 60)
        """
        self._ttl = ttl_seconds
        self._cache: dict[str, CacheEntry] = {}
        self._lock = Lock()

    def get(self, key: str) -> float | None:
        """
        Get cached value if exists and not expired.

        Args:
            key: Cache key (coin_id)

        Returns:
            Cached price or None if not found/expired
        """
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None

            if time.time() > entry.expires_at:
                # Expired, remove it
                del self._cache[key]
                return None

            return entry.value

    def set(self, key: str, value: float) -> None:
        """
        Set cached value with TTL.

        Args:
            key: Cache key (coin_id)
            value: Price value
        """
        with self._lock:
            self._cache[key] = CacheEntry(
                value=value,
                expires_at=time.time() + self._ttl,
            )

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()

    def cleanup(self) -> int:
        """
        Remove all expired entries.

        Returns:
            Number of entries removed
        """
        now = time.time()
        removed = 0

        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items() if now > entry.expires_at
            ]
            for key in expired_keys:
                del self._cache[key]
                removed += 1

        return removed

    def __len__(self) -> int:
        """Return number of cached entries (including expired)."""
        return len(self._cache)
