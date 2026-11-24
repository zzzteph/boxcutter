"""Settings: the admin password (HTTP basic auth) and Telegram / Slack notifications."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from ..config import settings
from ..db import get_session
from ..models import AppSettings
from ..notify import SEVERITIES, settings_of, test_channel
from ..security import check_credentials, set_admin_password

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/account")
def account(session: Session = Depends(get_session)):
    row = session.get(AppSettings, 1)
    return {"username": settings.admin_user,
            "password_changed_at": row.password_changed_at if row else None,
            "default_password": bool(row and row.password_changed_at is None
                                     and check_credentials(settings.admin_user, settings.admin_password))}


class PasswordIn(BaseModel):
    current_password: str
    new_password: str


@router.post("/password")
def change_password(body: PasswordIn, session: Session = Depends(get_session)):
    if not check_credentials(settings.admin_user, body.current_password):
        raise HTTPException(400, "current password is wrong")
    if len(body.new_password) < 8:
        raise HTTPException(400, "use at least 8 characters")
    set_admin_password(session, body.new_password)
    return {"ok": True}


def _notify_out(session: Session) -> dict:
    ns = settings_of(session)
    try:
        sevs = json.loads(ns.severities_json or "[]")
    except Exception:  # noqa: BLE001
        sevs = []
    return {"telegram": {"enabled": ns.telegram_enabled, "chat_id": ns.telegram_chat_id,
                         "has_token": bool(ns.telegram_token)},
            "slack": {"enabled": ns.slack_enabled, "has_webhook": bool(ns.slack_webhook)},
            "severities": sevs, "scan_done": ns.scan_done, "all_severities": SEVERITIES}


class NotifyIn(BaseModel):
    telegram_enabled: bool | None = None
    telegram_chat_id: str | None = None
    telegram_token: str | None = None        # write-only; stored only when a non-empty value is sent
    slack_enabled: bool | None = None
    slack_webhook: str | None = None         # write-only
    severities: list[str] | None = None
    scan_done: bool | None = None


@router.get("/notifications")
def get_notifications(session: Session = Depends(get_session)):
    return _notify_out(session)


@router.post("/notifications")
def set_notifications(body: NotifyIn, session: Session = Depends(get_session)):
    ns = settings_of(session)
    if body.telegram_enabled is not None:
        ns.telegram_enabled = body.telegram_enabled
    if body.telegram_chat_id is not None:
        ns.telegram_chat_id = body.telegram_chat_id.strip()[:64]
    if body.telegram_token:
        ns.telegram_token = body.telegram_token.strip()
    if body.slack_enabled is not None:
        ns.slack_enabled = body.slack_enabled
    if body.slack_webhook:
        hook = body.slack_webhook.strip()
        if not hook.startswith("https://"):
            raise HTTPException(400, "a Slack incoming-webhook URL starts with https://")
        ns.slack_webhook = hook
    if body.severities is not None:
        ns.severities_json = json.dumps([s for s in body.severities if s in SEVERITIES])
    if body.scan_done is not None:
        ns.scan_done = body.scan_done
    session.add(ns)
    session.commit()
    return _notify_out(session)


@router.post("/notifications/test/{channel}")
def test_notification(channel: str, session: Session = Depends(get_session)):
    ok, err = test_channel(settings_of(session), channel)
    return {"ok": ok, "error": err}
