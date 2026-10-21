from __future__ import annotations

import pytest

from saas_auth.config import Settings


@pytest.mark.parametrize(
    "given",
    [
        "postgres://saas:secret@db.render.internal:5432/saas_auth",
        "postgresql://saas:secret@db.render.internal:5432/saas_auth",
    ],
)
def test_managed_postgres_urls_are_rewritten_to_psycopg3(given: str) -> None:
    settings = Settings(_env_file=None, database_url=given)
    assert (
        settings.database_url
        == "postgresql+psycopg://saas:secret@db.render.internal:5432/saas_auth"
    )


@pytest.mark.parametrize(
    "given",
    ["sqlite://", "sqlite:///./saas_auth.db", "postgresql+psycopg://saas:saas@db:5432/saas_auth"],
)
def test_explicit_driver_urls_are_left_alone(given: str) -> None:
    assert Settings(_env_file=None, database_url=given).database_url == given
