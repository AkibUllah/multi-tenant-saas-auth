"""Outbound email. Console backend for development, in-memory backend for tests.

Swap in an SMTP/SES/Postmark backend by implementing `EmailBackend.send`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from .config import Settings

log = logging.getLogger(__name__)


@dataclass
class EmailMessage:
    to: str
    subject: str
    body: str
    context: dict = field(default_factory=dict)


class EmailBackend(Protocol):
    def send(self, message: EmailMessage) -> None: ...


class ConsoleEmailBackend:
    def __init__(self, sender: str) -> None:
        self.sender = sender

    def send(self, message: EmailMessage) -> None:
        log.info(
            "EMAIL from=%s to=%s subject=%r\n%s",
            self.sender,
            message.to,
            message.subject,
            message.body,
        )


class MemoryEmailBackend:
    def __init__(self) -> None:
        self.outbox: list[EmailMessage] = []

    def send(self, message: EmailMessage) -> None:
        self.outbox.append(message)

    def last_for(self, to: str) -> EmailMessage | None:
        for message in reversed(self.outbox):
            if message.to.lower() == to.lower():
                return message
        return None


def build_email_backend(settings: Settings) -> EmailBackend:
    if settings.email_backend == "memory":
        return MemoryEmailBackend()
    return ConsoleEmailBackend(sender=settings.email_from)


class Mailer:
    """Composes the handful of transactional emails this service sends."""

    def __init__(self, backend: EmailBackend, settings: Settings) -> None:
        self.backend = backend
        self.base_url = settings.frontend_base_url.rstrip("/")

    def send_verification(self, to: str, token: str) -> None:
        link = f"{self.base_url}/verify-email?token={token}"
        self.backend.send(
            EmailMessage(
                to=to,
                subject="Verify your email address",
                body=f"Welcome! Confirm your email by opening:\n{link}\n",
                context={"token": token, "link": link, "kind": "verify"},
            )
        )

    def send_password_reset(self, to: str, token: str) -> None:
        link = f"{self.base_url}/reset-password?token={token}"
        self.backend.send(
            EmailMessage(
                to=to,
                subject="Reset your password",
                body=f"Use the link below to choose a new password:\n{link}\n"
                "If you did not request this, you can ignore this email.\n",
                context={"token": token, "link": link, "kind": "reset"},
            )
        )

    def send_invitation(self, to: str, org_name: str, role: str, token: str) -> None:
        link = f"{self.base_url}/invitations/accept?token={token}"
        self.backend.send(
            EmailMessage(
                to=to,
                subject=f"You have been invited to {org_name}",
                body=f"You were invited to join {org_name} as {role}.\nAccept here:\n{link}\n",
                context={"token": token, "link": link, "kind": "invitation", "org": org_name},
            )
        )
