from __future__ import annotations

import fakeredis
import pytest
from fastapi.testclient import TestClient

from saas_auth.main import create_app
from saas_auth.ratelimit import InMemoryBackend, RateLimiter, RedisBackend

from .conftest import make_settings


class FakeClock:
    def __init__(self, start: float = 1_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.mark.parametrize(
    "backend_factory", [InMemoryBackend, lambda: RedisBackend(fakeredis.FakeRedis())]
)
def test_fixed_window_limits_then_resets(backend_factory):
    clock = FakeClock()
    limiter = RateLimiter(backend_factory(), clock=clock)

    results = [limiter.hit("login:1.2.3.4", limit=3, window_seconds=60) for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, True, False]
    assert [r.remaining for r in results] == [2, 1, 0, 0]
    assert results[-1].retry_after >= 1
    assert results[-1].headers()["Retry-After"] == str(results[-1].retry_after)

    clock.advance(60)
    assert limiter.hit("login:1.2.3.4", limit=3, window_seconds=60).allowed


def test_keys_are_independent():
    limiter = RateLimiter(InMemoryBackend(), clock=FakeClock())
    for _ in range(2):
        limiter.hit("a", 2, 60)
    assert not limiter.hit("a", 2, 60).allowed
    assert limiter.hit("b", 2, 60).allowed


def test_auth_endpoints_return_429_with_retry_after():
    settings = make_settings(rate_limit_auth_requests=2, rate_limit_auth_window_seconds=60)
    with TestClient(create_app(settings)) as client:
        body = {"email": "nobody@example.com", "password": "whatever-123"}
        assert client.post("/v1/auth/login", json=body).status_code == 401
        assert client.post("/v1/auth/login", json=body).status_code == 401
        r = client.post("/v1/auth/login", json=body)
        assert r.status_code == 429
        assert int(r.headers["Retry-After"]) >= 1
        assert r.headers["X-RateLimit-Remaining"] == "0"


def test_login_lockout_after_repeated_failures(api, client, settings):
    api.register("lock@example.com")
    body = {"email": "lock@example.com", "password": "wrong-password"}
    for _ in range(settings.login_max_attempts):
        assert client.post("/v1/auth/login", json=body).status_code == 401

    # Even the right password is refused while locked.
    r = client.post(
        "/v1/auth/login", json={"email": "lock@example.com", "password": "correct-horse-battery"}
    )
    assert r.status_code == 423
    assert int(r.headers["Retry-After"]) > 0


def test_successful_login_resets_failure_counter(api, client, settings):
    api.register("counter@example.com")
    bad = {"email": "counter@example.com", "password": "wrong-password"}
    for _ in range(settings.login_max_attempts - 1):
        client.post("/v1/auth/login", json=bad)
    api.login("counter@example.com")
    for _ in range(settings.login_max_attempts - 1):
        assert client.post("/v1/auth/login", json=bad).status_code == 401
    api.login("counter@example.com")  # still not locked
