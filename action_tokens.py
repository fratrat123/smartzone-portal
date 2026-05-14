"""Signed tokens for email approve/deny links.

The notification email to each admin includes two one-click links: approve and
deny. The token is the auth — there's no OAuth round-trip, so the click works
from any device (including phones that aren't on the network yet).

Security model:
  - Token signed with FLASK_SECRET_KEY via itsdangerous (HMAC-SHA256).
  - Payload binds (mac, recipient_email, action) so a forwarded link still
    carries the original recipient's identity.
  - Time-limited (default 7 days).
  - Recipient must still be in the admin list at click time — see
    routes/admin.py.
  - GET on the link only renders a confirm page; the actual mutation requires
    POST so email-prefetchers / link scanners (Outlook ATP, etc.) can't trigger
    approvals by following the URL.
"""
from __future__ import annotations

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from config import config

_SALT = "smartzone-portal:action-link:v1"
_MAX_AGE_SECONDS = 7 * 24 * 3600


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(config.SECRET_KEY, salt=_SALT)


def make_token(mac: str, recipient_email: str, action: str,
               *, duration_seconds: int | None = None) -> str:
    """Build a signed magic-link token.

    `duration_seconds` (optional, approve only): how long the approval lasts.
    0 = forever. None = use the operator's default at click time. Encoding
    this in the token lets the email offer one-click 'Approve forever' vs
    'Approve 1 day' buttons; the confirm page can still let the operator
    override before final submit.
    """
    if action not in ("approve", "deny"):
        raise ValueError(f"unsupported action: {action}")
    payload: dict = {"mac": mac, "to": recipient_email.lower(), "act": action}
    if duration_seconds is not None and action == "approve":
        payload["dur"] = int(duration_seconds)
    return _serializer().dumps(payload)


class TokenError(Exception):
    pass


def parse_token(token: str) -> tuple[str, str, str, int | None]:
    """Return (mac, recipient_email, action, duration_seconds_or_None).
    Raises TokenError on any failure."""
    try:
        data = _serializer().loads(token, max_age=_MAX_AGE_SECONDS)
    except SignatureExpired:
        raise TokenError("This link has expired.")
    except BadSignature:
        raise TokenError("This link is invalid.")
    try:
        mac = str(data["mac"])
        to = str(data["to"])
        act = str(data["act"])
    except (KeyError, TypeError):
        raise TokenError("This link is malformed.")
    dur = data.get("dur")
    return mac, to, act, (int(dur) if dur is not None else None)
