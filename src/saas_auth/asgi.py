"""ASGI entrypoint: `uvicorn saas_auth.asgi:app`."""

from .main import create_app

app = create_app()
