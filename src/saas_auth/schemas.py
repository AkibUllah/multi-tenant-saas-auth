"""Pydantic request/response models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .rbac import ALL_PERMISSIONS, Role


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ----------------------------------------------------------------------------- auth


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(default="", max_length=255)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshIn(BaseModel):
    refresh_token: str


class EmailIn(BaseModel):
    email: EmailStr


class TokenIn(BaseModel):
    token: str


class ResetPasswordIn(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class UserOut(ORMModel):
    id: str
    email: EmailStr
    full_name: str
    is_active: bool
    is_verified: bool
    created_at: datetime


class MessageOut(BaseModel):
    message: str


# ----------------------------------------------------------------------------- orgs


class OrgCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    slug: str | None = Field(default=None, min_length=2, max_length=120, pattern=r"^[a-z0-9-]+$")


class OrgUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)


class OrgOut(ORMModel):
    id: str
    name: str
    slug: str
    created_at: datetime


class OrgWithRoleOut(OrgOut):
    role: str


class MemberOut(BaseModel):
    user_id: str
    email: EmailStr
    full_name: str
    role: str
    joined_at: datetime


class RoleUpdate(BaseModel):
    role: Role


# ----------------------------------------------------------------------------- invitations


class InvitationCreate(BaseModel):
    email: EmailStr
    role: Role = Role.MEMBER


class InvitationOut(ORMModel):
    id: str
    org_id: str
    email: EmailStr
    role: str
    expires_at: datetime
    accepted_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime

    @property
    def status(self) -> str:
        if self.revoked_at:
            return "revoked"
        if self.accepted_at:
            return "accepted"
        return "pending"


class AcceptInvitationOut(BaseModel):
    org: OrgOut
    role: str


# ----------------------------------------------------------------------------- api keys


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(default_factory=list)

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, scopes: list[str]) -> list[str]:
        unknown = sorted(set(scopes) - ALL_PERMISSIONS)
        if unknown:
            raise ValueError(f"unknown scopes: {unknown}")
        return sorted(set(scopes))


class ApiKeyOut(ORMModel):
    id: str
    org_id: str
    name: str
    prefix: str
    scopes: list[str]
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class ApiKeyCreated(ApiKeyOut):
    key: str  # full secret, returned exactly once


# ----------------------------------------------------------------------------- projects


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=5000)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)


class ProjectOut(ORMModel):
    id: str
    org_id: str
    name: str
    description: str
    created_by: str | None
    created_at: datetime
    updated_at: datetime


# ----------------------------------------------------------------------------- misc


class HealthOut(BaseModel):
    status: str
    version: str
    database: str
    rate_limiter: str


class PermissionsOut(BaseModel):
    roles: dict[str, list[str]]
