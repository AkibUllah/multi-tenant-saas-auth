from __future__ import annotations

from types import SimpleNamespace

import pytest
from starlette.requests import Request

from saas_auth.ratelimit import trusted_client_ip
from saas_auth.security import Principal
from tests.conftest import make_settings


def request_with(hops: int, forwarded: str | None) -> Request:
    headers = [] if forwarded is None else [(b"x-forwarded-for", forwarded.encode())]
    app = SimpleNamespace(state=SimpleNamespace(settings=make_settings(trusted_proxy_hops=hops)))
    return Request(
        {"type": "http", "headers": headers, "client": ("10.0.0.1", 4242), "app": app, "path": "/"}
    )


@pytest.mark.parametrize(
    ("hops", "forwarded", "expected"),
    [
        (0, None, "10.0.0.1"),
        (0, "203.0.113.9", "10.0.0.1"),  # no proxy configured: the header is client-controlled
        (1, None, "10.0.0.1"),
        (1, "203.0.113.9", "203.0.113.9"),
        (1, "6.6.6.6, 203.0.113.9", "203.0.113.9"),  # a spoofed left-hand entry is ignored
        (2, "6.6.6.6, 203.0.113.9, 198.51.100.7", "203.0.113.9"),
        (2, "203.0.113.9", "10.0.0.1"),  # fewer entries than proxies: did not come through them
        (1, "not-an-ip", "10.0.0.1"),
        (1, "2001:db8::1", "2001:db8::1"),
    ],
)
def test_forwarded_for_is_only_trusted_up_to_the_configured_hops(hops, forwarded, expected):
    assert trusted_client_ip(request_with(hops, forwarded)) == expected


def test_negative_hops_are_rejected():
    with pytest.raises(ValueError):
        make_settings(trusted_proxy_hops=-1)


def test_principal_id_identifies_either_kind_of_actor():
    user, key = SimpleNamespace(id="user-1"), SimpleNamespace(id="key-1")
    assert Principal(user=user).id == "user-1"
    assert Principal(api_key=key).id == "key-1"
    assert Principal().id is None
