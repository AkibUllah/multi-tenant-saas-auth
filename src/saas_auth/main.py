"""Application factory."""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.engine import Engine

from . import __version__
from .config import Settings, get_settings
from .database import Base, make_engine, make_session_factory
from .emailer import build_email_backend
from .ratelimit import build_rate_limiter
from .routers import api_keys, auth, health, invitations, members, orgs, projects

log = logging.getLogger("saas_auth")


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    engine = engine or make_engine(settings.database_url)
    Base.metadata.create_all(engine)

    app = FastAPI(
        title="Multi-tenant SaaS Auth",
        version=__version__,
        description="Users, organizations, roles, API keys and sessions for multi-tenant products.",
    )
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)
    app.state.rate_limiter = build_rate_limiter(settings.redis_url)
    app.state.email = build_email_backend(settings)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.frontend_base_url],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        started = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        log.info(
            "%s %s -> %s %.1fms rid=%s",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
            request_id,
        )
        return response

    for router in (
        health.router,
        auth.router,
        orgs.router,
        members.router,
        invitations.router,
        api_keys.router,
        projects.router,
    ):
        app.include_router(router)

    if settings.is_production and settings.jwt_secret == "change-me-in-production":
        raise RuntimeError("JWT_SECRET must be set in production")

    return app
