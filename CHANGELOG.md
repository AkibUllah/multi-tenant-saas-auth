# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CodeQL code scanning workflow and Dependabot configuration (pip, Docker, GitHub Actions).
- API reference and terminal screenshots in the README.
- Roadmap tracked as GitHub issues under the `v0.2.0` milestone.
- Audit log of security events: role changes, member removal and leaving, invitations, API key creation and revocation, account lockouts, organization deletion and exports. Events commit with the change they describe, are scoped to an organization, and never contain credentials.
- `GET /v1/orgs/{org_id}/audit-events` (filters, cursor pagination) and `GET /v1/orgs/{org_id}/audit-events/export.csv`, gated by a new `audit:read` permission held by owners and admins and available as an API key scope.
- `audit_events` is append-only: database triggers refuse updates and deletes on SQLite and PostgreSQL.
- `TRUSTED_PROXY_HOPS` setting, so recorded client addresses cannot be chosen through `X-Forwarded-For`.
- CI job running the test suite against PostgreSQL, with `TEST_DATABASE_URL` for doing the same locally.

### Fixed

- Revoking an invitation twice no longer overwrites its original `revoked_at`.

## [0.1.0] - 2026-10-25

First public release.

### Added

- Users, organizations and memberships with four roles (owner, admin, member, viewer).
- Flat permission vocabulary shared by roles and API key scopes, enforced through one `require("perm")` dependency that also resolves the tenant.
- Short-lived JWT access tokens and rotating refresh tokens stored as SHA-256 hashes, with token-family revocation on reuse.
- bcrypt password hashing, login lockout after repeated failures and timing-equalised login for unknown accounts.
- Email verification and password reset with single-use tokens (console and in-memory email backends).
- Per-organization API keys (`sk_<prefix>_<secret>`) with hashed secrets, scopes capped at the creator's permissions, `last_used_at` and revocation.
- Email invitations with accept tokens, last-owner protection and owner-only ownership transfer.
- Fixed-window rate limiting on auth endpoints (Redis when `REDIS_URL` is set, in-process otherwise).
- Non-members get 404 for organization routes so ids cannot be enumerated.
- `/health`, request ids, Docker image, docker compose with PostgreSQL and Redis, CI on Python 3.10/3.11, Pages API reference, Codespaces and Render kits.

### Fixed

- API key prefixes are generated so they never contain the `_` separator.
- `postgres://` and `postgresql://` database URLs are rewritten to the psycopg 3 driver.

[Unreleased]: https://github.com/AkibUllah/multi-tenant-saas-auth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AkibUllah/multi-tenant-saas-auth/releases/tag/v0.1.0
