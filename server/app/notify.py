"""Outbound notifications: Telegram and Slack (incoming webhook).

What is sent:
* new findings whose severity is selected in Settings - one Telegram message per finding, one batched Slack
  message per result (capped so a big result can't flood a channel);
* optionally a one-line summary when a scan finishes.

Everything is fire-and-forget in a daemon thread so a slow/dead endpoint never blocks the request that
triggered it. Stdlib only."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

from sqlmodel import Session

from .models import NotifySettings, Scan

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
_SEV_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "⚪"}
_CAP = 30                 # max findings per result batch (avoid flooding / rate limits)


def _post(url: str, payload: dict, timeout: int = 8) -> None:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=timeout).read()


def _quiet(fn, *a) -> None:
    try:
        fn(*a)
    except Exception:  # noqa: BLE001 - notifications are best-effort; never raise into the caller
        pass


def send_telegram(token: str, chat_id: str, text: str) -> None:
    _post(f"https://api.telegram.org/bot{token}/sendMessage",
          {"chat_id": chat_id, "text": text, "disable_web_page_preview": True})


def send_slack(webhook: str, text: str) -> None:
    _post(webhook, {"text": text})


def settings_of(session: Session) -> NotifySettings:
    ns = session.get(NotifySettings, 1)
    if ns is None:
        ns = NotifySettings(id=1)
        session.add(ns)
        session.commit()
    return ns


def _channels(ns: NotifySettings) -> dict:
    out = {}
    if ns.telegram_enabled and ns.telegram_token and ns.telegram_chat_id:
        out["telegram"] = (ns.telegram_token, ns.telegram_chat_id)
    if ns.slack_enabled and ns.slack_webhook:
        out["slack"] = ns.slack_webhook
    return out


def _severities(ns: NotifySettings) -> set:
    try:
        return set(json.loads(ns.severities_json or "[]"))
    except Exception:  # noqa: BLE001
        return set()


def _line(f: dict) -> str:
    emoji = _SEV_EMOJI.get(f.get("severity", ""), "•")
    loc = f.get("url") or f.get("target") or ""
    return f"{emoji} {f.get('severity', '')} — {(f.get('title') or 'finding')[:200]}" + (f"\n{loc}" if loc else "")


def notify_findings(session: Session, scan_name: str, findings: list[dict]) -> None:
    """New findings from one job result -> every enabled channel, filtered by the selected severities."""
    ns = settings_of(session)
    ch, sevs = _channels(ns), _severities(ns)
    picked = [f for f in findings if f.get("severity") in sevs]
    if not (ch and picked):
        return
    extra = len(picked) - _CAP
    picked = picked[:_CAP]

    def run():
        if "telegram" in ch:
            token, chat = ch["telegram"]
            for f in picked:
                _quiet(send_telegram, token, chat, f"[{scan_name}] " + _line(f))
                time.sleep(0.05)
            if extra > 0:
                _quiet(send_telegram, token, chat, f"…and {extra} more finding(s) in '{scan_name}'")
        if "slack" in ch:
            text = f"*boxcutter — {len(picked) + max(extra, 0)} new finding(s) in '{scan_name}'*\n" + \
                   "\n".join(_line(f).replace("\n", " · ") for f in picked)
            if extra > 0:
                text += f"\n…and {extra} more"
            _quiet(send_slack, ch["slack"], text)

    threading.Thread(target=run, daemon=True).start()


def notify_scan_done(session: Session, scan: Scan, stats: dict) -> None:
    ns = settings_of(session)
    ch = _channels(ns)
    if not (ch and ns.scan_done):
        return
    text = (f"✅ boxcutter: scan '{scan.name}' (run #{scan.run_no}) finished — "
            f"{stats.get('new', 0)} new, {stats.get('open', 0)} still open, {stats.get('removed', 0)} no longer found")
    gone = stats.get("removed_list") or []
    if gone:
        text += "\nNo longer found:\n" + "\n".join(f"• [{f['severity']}] {f['title']} — {f['target']}" for f in gone[:15])
        if len(gone) > 15:
            text += f"\n…and {len(gone) - 15} more"

    def run():
        if "telegram" in ch:
            _quiet(send_telegram, *ch["telegram"], text)
        if "slack" in ch:
            _quiet(send_slack, ch["slack"], text)

    threading.Thread(target=run, daemon=True).start()


def test_channel(ns: NotifySettings, channel: str) -> tuple[bool, str]:
    """Synchronous test send for the Settings page. Returns (ok, error)."""
    try:
        if channel == "telegram":
            if not (ns.telegram_token and ns.telegram_chat_id):
                return False, "set a bot token and chat id first"
            send_telegram(ns.telegram_token, ns.telegram_chat_id, "✅ boxcutter test notification")
        elif channel == "slack":
            if not ns.slack_webhook:
                return False, "set a Slack webhook URL first"
            send_slack(ns.slack_webhook, "✅ boxcutter test notification")
        else:
            return False, "unknown channel"
        return True, ""
    except urllib.error.HTTPError as e:
        return False, f"{channel} error {e.code}: {e.read().decode(errors='replace')[:200]}"
    except Exception as e:  # noqa: BLE001
        return False, str(e)[:300]
