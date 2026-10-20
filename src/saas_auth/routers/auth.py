from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..emailer import Mailer
from ..models import User
from ..ratelimit import rate_limit
from ..schemas import (
    ChangePasswordIn,
    EmailIn,
    LoginIn,
    MessageOut,
    RefreshIn,
    RegisterIn,
    ResetPasswordIn,
    TokenIn,
    TokenPair,
    UserOut,
)
from ..security import create_access_token, get_current_user, hash_password, verify_password
from ..tokens import (
    PURPOSE_RESET,
    PURPOSE_VERIFY,
    InvalidRefreshToken,
    RefreshTokenReused,
    consume_email_token,
    issue_email_token,
    issue_refresh_token,
    revoke_all_for_user,
    revoke_refresh_token,
    rotate_refresh_token,
)
from ..utils import ensure_aware, in_seconds, utcnow

log = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/auth", tags=["auth"])


def _mailer(request: Request) -> Mailer:
    return Mailer(request.app.state.email, request.app.state.settings)


def _token_pair(db: Session, user: User, request: Request) -> TokenPair:
    settings = request.app.state.settings
    raw_refresh, _ = issue_refresh_token(
        db, user, settings, user_agent=request.headers.get("user-agent")
    )
    db.commit()
    return TokenPair(
        access_token=create_access_token(user.id, settings),
        refresh_token=raw_refresh,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("auth"))],
)
def register(payload: RegisterIn, request: Request, db: Session = Depends(get_db)) -> User:
    settings = request.app.state.settings
    email = payload.email.lower()
    if db.scalar(select(User).where(User.email == email)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = User(
        email=email,
        hashed_password=hash_password(payload.password, settings.bcrypt_rounds),
        full_name=payload.full_name.strip(),
    )
    db.add(user)
    db.flush()
    token = issue_email_token(db, user, PURPOSE_VERIFY, settings)
    db.commit()
    _mailer(request).send_verification(user.email, token)
    log.info("user registered id=%s", user.id)
    return user


@router.post("/login", response_model=TokenPair, dependencies=[Depends(rate_limit("auth"))])
def login(payload: LoginIn, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    settings = request.app.state.settings
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    if user is None:
        # Burn roughly the same time as a real check so timing does not reveal account existence.
        verify_password(payload.password, hash_password("timing-equaliser", 4))
        raise invalid

    locked_until = ensure_aware(user.locked_until)
    if locked_until is not None and locked_until > utcnow():
        retry = int((locked_until - utcnow()).total_seconds()) + 1
        raise HTTPException(
            status.HTTP_423_LOCKED,
            "Account temporarily locked after repeated failed logins",
            headers={"Retry-After": str(retry)},
        )

    if not user.is_active or not verify_password(payload.password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.login_max_attempts:
            user.locked_until = in_seconds(settings.login_lockout_seconds)
            user.failed_login_attempts = 0
            log.warning("account locked user=%s", user.id)
        db.commit()
        raise invalid

    user.failed_login_attempts = 0
    user.locked_until = None
    return _token_pair(db, user, request)


@router.post("/refresh", response_model=TokenPair)
def refresh(payload: RefreshIn, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    settings = request.app.state.settings
    try:
        new_raw, _, user = rotate_refresh_token(
            db, payload.refresh_token, settings, request.headers.get("user-agent")
        )
    except RefreshTokenReused as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    except InvalidRefreshToken as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    db.commit()
    return TokenPair(
        access_token=create_access_token(user.id, settings),
        refresh_token=new_raw,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post("/logout", response_model=MessageOut)
def logout(payload: RefreshIn, db: Session = Depends(get_db)) -> MessageOut:
    revoke_refresh_token(db, payload.refresh_token)
    db.commit()
    return MessageOut(message="Logged out")


@router.post("/logout-all", response_model=MessageOut)
def logout_all(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> MessageOut:
    count = revoke_all_for_user(db, user.id)
    db.commit()
    return MessageOut(message=f"Revoked {count} session(s)")


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.post("/verify-email", response_model=MessageOut)
def verify_email(payload: TokenIn, db: Session = Depends(get_db)) -> MessageOut:
    user = consume_email_token(db, payload.token, PURPOSE_VERIFY)
    if user is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired verification token")
    user.is_verified = True
    db.commit()
    return MessageOut(message="Email verified")


@router.post(
    "/resend-verification",
    response_model=MessageOut,
    dependencies=[Depends(rate_limit("auth"))],
)
def resend_verification(
    request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> MessageOut:
    if user.is_verified:
        return MessageOut(message="Email already verified")
    token = issue_email_token(db, user, PURPOSE_VERIFY, request.app.state.settings)
    db.commit()
    _mailer(request).send_verification(user.email, token)
    return MessageOut(message="Verification email sent")


@router.post(
    "/forgot-password",
    response_model=MessageOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit("auth"))],
)
def forgot_password(
    payload: EmailIn, request: Request, db: Session = Depends(get_db)
) -> MessageOut:
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if user is not None and user.is_active:
        token = issue_email_token(db, user, PURPOSE_RESET, request.app.state.settings)
        db.commit()
        _mailer(request).send_password_reset(user.email, token)
    # Same response whether or not the account exists.
    return MessageOut(message="If the account exists, a reset email has been sent")


@router.post("/reset-password", response_model=MessageOut)
def reset_password(
    payload: ResetPasswordIn, request: Request, db: Session = Depends(get_db)
) -> MessageOut:
    user = consume_email_token(db, payload.token, PURPOSE_RESET)
    if user is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset token")
    settings = request.app.state.settings
    user.hashed_password = hash_password(payload.new_password, settings.bcrypt_rounds)
    user.failed_login_attempts = 0
    user.locked_until = None
    revoke_all_for_user(db, user.id)
    db.commit()
    return MessageOut(message="Password updated; all sessions were signed out")


@router.post("/change-password", response_model=MessageOut)
def change_password(
    payload: ChangePasswordIn,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageOut:
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    settings = request.app.state.settings
    user.hashed_password = hash_password(payload.new_password, settings.bcrypt_rounds)
    revoke_all_for_user(db, user.id)
    db.commit()
    return MessageOut(message="Password changed; all sessions were signed out")
