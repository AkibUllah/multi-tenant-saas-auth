from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from saas_auth.config import Settings
from saas_auth.main import create_app


def make_settings(**overrides) -> Settings:
    base = dict(
        _env_file=None,
        database_url="sqlite://",
        jwt_secret="unit-test-secret-with-at-least-32-bytes-of-length",
        bcrypt_rounds=4,
        email_backend="memory",
        rate_limit_auth_requests=1000,
        rate_limit_auth_window_seconds=60,
        login_max_attempts=3,
        login_lockout_seconds=600,
        environment="test",
        log_level="WARNING",
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


@pytest.fixture
def outbox(app):
    return app.state.email.outbox


# ----------------------------------------------------------------------------- helpers


class Api:
    """Thin helper around TestClient for the repetitive auth dance in tests."""

    def __init__(self, client: TestClient):
        self.client = client

    def register(self, email: str, password: str = "correct-horse-battery", name: str = ""):
        r = self.client.post(
            "/v1/auth/register",
            json={"email": email, "password": password, "full_name": name or email.split("@")[0]},
        )
        assert r.status_code == 201, r.text
        return r.json()

    def login(self, email: str, password: str = "correct-horse-battery") -> dict:
        r = self.client.post("/v1/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        return r.json()

    def signup(self, email: str, password: str = "correct-horse-battery") -> dict:
        self.register(email, password)
        return self.login(email, password)

    @staticmethod
    def auth(tokens: dict) -> dict:
        return {"Authorization": f"Bearer {tokens['access_token']}"}

    def create_org(self, tokens: dict, name: str) -> dict:
        r = self.client.post("/v1/orgs", json={"name": name}, headers=self.auth(tokens))
        assert r.status_code == 201, r.text
        return r.json()

    def invite_and_accept(self, owner_tokens: dict, org_id: str, email: str, role: str) -> dict:
        """Owner invites `email` with `role`; the invitee registers and accepts. Returns tokens."""
        r = self.client.post(
            f"/v1/orgs/{org_id}/invitations",
            json={"email": email, "role": role},
            headers=self.auth(owner_tokens),
        )
        assert r.status_code == 201, r.text
        token = self.client.app.state.email.last_for(email).context["token"]
        tokens = self.signup(email)
        r = self.client.post(
            "/v1/invitations/accept", json={"token": token}, headers=self.auth(tokens)
        )
        assert r.status_code == 200, r.text
        return tokens


@pytest.fixture
def api(client: TestClient) -> Api:
    return Api(client)
