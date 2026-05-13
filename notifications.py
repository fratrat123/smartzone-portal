"""Notifications on new pending device requests.

Fires off Slack webhook (if configured) and admin email (if configured) so admins
don't have to keep the queue page open. Failures are swallowed and logged — a
busted notification should never break the underlying portal flow.

Each admin email is sent individually so it can include a magic link tied to
that specific recipient (one-click approve / deny). See action_tokens.py.
"""
from __future__ import annotations

import json
import logging
import threading
import urllib.request

from action_tokens import make_token
from config import config

log = logging.getLogger(__name__)


def _send_slack(text: str) -> None:
    if not config.NOTIFY_SLACK_WEBHOOK_URL:
        return
    try:
        body = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(
            config.NOTIFY_SLACK_WEBHOOK_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            r.read()
    except Exception as e:
        log.warning("notifications: slack failed: %s", e)


def _smtp_send(to_email: str, subject: str, text_body: str, html_body: str) -> None:
    if not config.SMTP_HOST or not config.SMTP_FROM_EMAIL:
        return
    import smtplib
    from email.message import EmailMessage
    from email.utils import formataddr

    msg = EmailMessage()
    msg["From"] = formataddr((config.SMTP_FROM_NAME, config.SMTP_FROM_EMAIL))
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            if config.SMTP_USER and config.SMTP_PASS:
                s.login(config.SMTP_USER, config.SMTP_PASS)
            s.send_message(msg)
    except Exception as e:
        log.warning("notifications: email to %s failed: %s", to_email, e)


def _portal_url(path: str = "/admin/") -> str:
    return config.PORTAL_BASE_URL.rstrip("/") + path


def _link(mac: str, recipient_email: str, action: str) -> str:
    return _portal_url(f"/admin/link/{make_token(mac, recipient_email, action)}")


def notify_new_pending(*, mac: str, mac_display: str, requested_by_email: str | None,
                       friendly_name: str | None, hostname: str | None,
                       device_type: str | None, ssid: str | None) -> None:
    """Notify admins that a new device is awaiting approval. Non-blocking."""
    name = friendly_name or hostname or "(unnamed device)"
    user = requested_by_email or "(no portal sign-in yet)"
    queue_url = _portal_url("/admin/")

    slack_text = (
        f":bell: New Wi-Fi access request\n"
        f"*Device:* {name}\n"
        f"*MAC:* `{mac_display}`\n"
        f"*Requested by:* {user}\n"
        f"*Type:* {device_type or '—'}    *SSID:* {ssid or '—'}\n"
        f"<{queue_url}|Open admin queue>"
    )

    def _build_email(recipient: str) -> tuple[str, str, str]:
        approve = _link(mac, recipient, "approve")
        deny = _link(mac, recipient, "deny")
        subject = f"[Wi-Fi Portal] New request: {name}"
        text_body = (
            f"A new Wi-Fi access request is waiting for review.\n\n"
            f"Device:       {name}\n"
            f"MAC:          {mac_display}\n"
            f"Requested by: {user}\n"
            f"Hostname:     {hostname or '(unknown)'}\n"
            f"Device type:  {device_type or '—'}\n"
            f"SSID:         {ssid or '—'}\n\n"
            f"Approve (1 day): {approve}\n"
            f"Deny:            {deny}\n\n"
            f"Or open the queue: {queue_url}\n"
            f"\n"
            f"The links above are tied to {recipient} and require a confirmation\n"
            f"click on the next page. They expire in 7 days.\n"
        )
        html_body = f"""<!doctype html>
<html><body style="font-family:-apple-system,BlinkMacSystemFont,system-ui,Segoe UI,Roboto,sans-serif;color:#222;max-width:560px">
<h2 style="margin-bottom:8px">New Wi-Fi access request</h2>
<p style="color:#555;margin-top:0">A device is waiting for review.</p>
<table style="border-collapse:collapse;margin:12px 0">
  <tr><td style="color:#888;padding:2px 12px 2px 0">Device</td><td>{name}</td></tr>
  <tr><td style="color:#888;padding:2px 12px 2px 0">MAC</td><td><code>{mac_display}</code></td></tr>
  <tr><td style="color:#888;padding:2px 12px 2px 0">Requested by</td><td>{user}</td></tr>
  <tr><td style="color:#888;padding:2px 12px 2px 0">Hostname</td><td>{hostname or '(unknown)'}</td></tr>
  <tr><td style="color:#888;padding:2px 12px 2px 0">Type</td><td>{device_type or '—'}</td></tr>
  <tr><td style="color:#888;padding:2px 12px 2px 0">SSID</td><td>{ssid or '—'}</td></tr>
</table>
<p style="margin:18px 0">
  <a href="{approve}" style="background:#16a34a;color:#fff;text-decoration:none;padding:10px 18px;border-radius:6px;font-weight:600;display:inline-block;margin-right:8px">Approve (1 day)</a>
  <a href="{deny}" style="background:#dc2626;color:#fff;text-decoration:none;padding:10px 18px;border-radius:6px;font-weight:600;display:inline-block">Deny</a>
</p>
<p style="color:#888;font-size:0.85em">
  These links are tied to <strong>{recipient}</strong> and require a confirmation click on the next page.
  They expire in 7 days. Or <a href="{queue_url}">open the admin queue</a>.
</p>
</body></html>
"""
        return subject, text_body, html_body

    def _fire():
        _send_slack(slack_text)
        for recipient in config.NOTIFY_EMAILS:
            subject, text_body, html_body = _build_email(recipient)
            _smtp_send(recipient, subject, text_body, html_body)

    threading.Thread(target=_fire, name="notify", daemon=True).start()
