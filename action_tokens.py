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


def make_token(mac: str, recipient_email: str, action: str) -> str:
    if action not in ("approve", "deny"):
        raise ValueError(f"unsupported action: {action}")
    return _serializer().dumps({"mac": mac, "to": recipient_email.lower(), "act": action})


class TokenError(Exception):
    pass


def parse_token(token: str) -> tuple[str, str, str]:
    """Return (mac, recipient_email, action). Raises TokenError on any failure."""
    try:
        data = _serializer().loads(token, max_age=_MAX_AGE_SECONDS)
    except SignatureExpired:
        raise TokenError("This link has expired.")
    except BadSignature:
        raise TokenError("This link is invalid.")
    try:
        return str(data["mac"]), str(data["to"]), str(data["act"])
    except (KeyError, TypeError):
        raise TokenError("This link is malformed.")
