"""Fixed-window rate limiting with swappable storage (in-memory or Redis).

The backend protocol is deliberately tiny so the same `RateLimiter` works against either store.
A clock is injectable so tests can move time without sleeping.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from fastapi import HTTPException, Request, status

log = logging.getLogger(__name__)

Clock = Callable[[], float]


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int  # seconds until the window resets (0 when allowed)

    def headers(self) -> dict[str, str]:
        h = {"X-RateLimit-Limit": str(self.limit), "X-RateLimit-Remaining": str(self.remaining)}
        if not self.allowed:
            h["Retry-After"] = str(max(self.retry_after, 1))
        return h


class RateLimitBackend(Protocol):
    def incr(self, key: str, window_seconds: int, now: float) -> tuple[int, int]:
        """Increment the counter for `key` in the window containing `now`.

        Returns (count_after_increment, seconds_until_window_reset).
        """


class InMemoryBackend:
    """Process-local store; fine for a single instance or tests."""

    def __init__(self) -> None:
        self._counters: dict[str, tuple[int, int]] = {}  # key -> (window_start, count)
        self._lock = threading.Lock()

    def incr(self, key: str, window_seconds: int, now: float) -> tuple[int, int]:
        window_start = int(now // window_seconds) * window_seconds
        with self._lock:
            start, count = self._counters.get(key, (window_start, 0))
            if start != window_start:
                start, count = window_start, 0
            count += 1
            self._counters[key] = (start, count)
        reset_in = int(start + window_seconds - now) or 1
        return count, max(reset_in, 1)

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()


class RedisBackend:
    """Shared store for multi-instance deployments.

    Keys embed the window start, so each window is its own counter. INCR and EXPIRE run inside a
    MULTI/EXEC transaction; refreshing the TTL on every hit is harmless because a key is never
    read again once its window has passed.
    """

    def __init__(self, client, key_prefix: str = "rl:") -> None:
        self._redis = client
        self._prefix = key_prefix

    def incr(self, key: str, window_seconds: int, now: float) -> tuple[int, int]:
        window_start = int(now // window_seconds) * window_seconds
        redis_key = f"{self._prefix}{key}:{window_start}"
        pipe = self._redis.pipeline(transaction=True)
        pipe.incr(redis_key)
        pipe.expire(redis_key, window_seconds + 1)
        count, _ = pipe.execute()
        reset_in = int(window_start + window_seconds - now)
        return int(count), max(reset_in, 1)


class RateLimiter:
    def __init__(self, backend: RateLimitBackend | None = None, clock: Clock | None = None):
        self.backend = backend or InMemoryBackend()
        self.clock = clock or time.time

    def hit(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        count, reset_in = self.backend.incr(key, window_seconds, self.clock())
        allowed = count <= limit
        return RateLimitResult(
            allowed=allowed,
            limit=limit,
            remaining=max(limit - count, 0),
            retry_after=0 if allowed else reset_in,
        )


def build_rate_limiter(redis_url: str | None) -> RateLimiter:
    if redis_url:
        import redis

        client = redis.Redis.from_url(redis_url, decode_responses=False)
        log.info("rate limiter using redis backend")
        return RateLimiter(RedisBackend(client))
    log.info("rate limiter using in-memory backend")
    return RateLimiter(InMemoryBackend())


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(scope: str, limit: int | None = None, window_seconds: int | None = None):
    """Route dependency: `Depends(rate_limit("login", 10, 60))`.

    When `limit`/`window_seconds` are omitted, the app-level auth defaults from settings apply.
    """

    def dependency(request: Request) -> RateLimitResult:
        settings = request.app.state.settings
        limiter: RateLimiter = request.app.state.rate_limiter
        eff_limit = limit or settings.rate_limit_auth_requests
        eff_window = window_seconds or settings.rate_limit_auth_window_seconds
        result = limiter.hit(f"{scope}:{client_ip(request)}", eff_limit, eff_window)
        if not result.allowed:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many requests",
                headers=result.headers(),
            )
        return result

    return dependency
