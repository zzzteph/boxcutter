"""Best-effort outbound notifications. Fire-and-forget in a daemon thread so a slow/dead endpoint never blocks
the request that triggered it. Stdlib only.

- Webhook (env NOTIFY_WEBHOOK): a JSON POST on scan-done / new-critical.
- Telegram: per-finding messages, configured in the UI (Settings → Telegram) and stored in NotifySettings —
  see notify_findings(). The env TELEGRAM_* just seeds that config on first boot."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

from .config import settings

_SEV_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "⚪"}
_NOTIFY_CAP = 30                 # max Telegram messages per result batch (avoid flooding / rate limits)


def _post(url: str, payload: dict) -> None:
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=8).read()
    except Exception:  # noqa: BLE001 - notifications are best-effort; never raise into the caller
        pass


def send_telegram(token: str, chat_id: str, text: str) -> None:
    if token and chat_id:
        _post(f"https://api.telegram.org/bot{token}/sendMessage",
              {"chat_id": chat_id, "text": text, "disable_web_page_preview": True})


def telegram_test(token: str, chat_id: str) -> tuple[bool, str]:
    """Synchronous send used by the 'Send test' button — returns (ok, error) so the UI can report the result."""
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=json.dumps({"chat_id": chat_id, "text": "✅ boxcutter test notification"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=8).read()
        return True, ""
    except urllib.error.HTTPError as e:
        return False, f"telegram error {e.code}: {e.read().decode()[:200]}"
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def notify_findings(cfg: dict, findings: list[dict]) -> None:
    """Send one Telegram message per NEW finding whose severity is selected — severity + short info + url.
    cfg = {token, chat_id, severities:set[str]}. Best-effort, throttled, and capped so one big result can't
    flood the chat. Runs in the background so it never blocks the runner's result request."""
    token, chat_id, sevs = cfg.get("token"), cfg.get("chat_id"), (cfg.get("severities") or set())
    if not (token and chat_id and sevs):
        return
    picked = [f for f in findings if f.get("severity") in sevs]
    if not picked:
        return
    extra = len(picked) - _NOTIFY_CAP
    picked = picked[:_NOTIFY_CAP]

    def run():
        for f in picked:
            emoji = _SEV_EMOJI.get(f.get("severity", ""), "•")
            info = (f.get("title") or "finding")[:200]
            loc = f.get("url") or f.get("target") or ""
            text = f"{emoji} {f.get('severity', '')} — {info}" + (f"\n{loc}" if loc else "")
            send_telegram(token, chat_id, text)
            time.sleep(0.05)
        if extra > 0:
            send_telegram(token, chat_id, f"…and {extra} more finding(s) this batch")

    threading.Thread(target=run, daemon=True).start()


def notify(kind: str, data: dict, text: str) -> None:
    """Event summary to the webhook (JSON {event, ...data}) on 'scan_done' / 'new_critical'. Background."""
    if not settings.notify_webhook:
        return
    threading.Thread(target=lambda: _post(settings.notify_webhook, {"event": kind, **data}), daemon=True).start()
