"""Send verification emails via SMTP (Google Workspace SMTP relay by default).

Uses STARTTLS on port 587. Optional SMTP AUTH if SMTP_USER/SMTP_PASS are set;
otherwise relies on IP-based authorization in Google Admin Console.
"""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

from config import config

log = logging.getLogger(__name__)


def send_verification_email(to_email: str, code: str, verify_url: str) -> bool:
    """Send a verification email containing both a 6-digit code and a click link.
    Returns True on success."""
    if not config.SMTP_HOST or not config.SMTP_FROM_EMAIL:
        log.error("email_sender: SMTP not configured (SMTP_HOST / SMTP_FROM_EMAIL missing)")
        return False

    msg = EmailMessage()
    msg["From"] = formataddr((config.SMTP_FROM_NAME, config.SMTP_FROM_EMAIL))
    msg["To"] = to_email
    msg["Subject"] = "Wi-Fi sign-in verification"

    msg.set_content(
        f"Your Wi-Fi sign-in code: {code}\n"
        f"\n"
        f"Or click this link to verify automatically:\n"
        f"{verify_url}\n"
        f"\n"
        f"This code expires in {config.EMAIL_VERIFY_TTL_MINUTES} minutes.\n"
        f"If you didn't request this, you can ignore the email.\n"
    )
    msg.add_alternative(
        f"""<!doctype html>
<html><body style="font-family:-apple-system,BlinkMacSystemFont,system-ui,Segoe UI,Roboto,sans-serif;color:#222">
<h2>Wi-Fi sign-in verification</h2>
<p>Your verification code:</p>
<p style="font-size:2em;font-family:ui-monospace,Menlo,monospace;letter-spacing:0.2em;background:#f4f4f4;padding:0.4em 0.6em;border-radius:6px;display:inline-block">{code}</p>
<p>Or just <a href="{verify_url}">click here to verify</a> on the device you're connecting.</p>
<p style="color:#888;font-size:0.9em">This code expires in {config.EMAIL_VERIFY_TTL_MINUTES} minutes.
If you didn't request this, you can ignore the email.</p>
</body></html>
""",
        subtype="html",
    )

    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            if config.SMTP_USER and config.SMTP_PASS:
                s.login(config.SMTP_USER, config.SMTP_PASS)
            s.send_message(msg)
        log.info("email_sender: sent verification to %s", to_email)
        return True
    except Exception as e:
        log.exception("email_sender: failed to send to %s: %s", to_email, e)
        return False
