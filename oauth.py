"""Google OAuth via Authlib.

Which email domains are allowed to sign in is now a live Setting
("email_allowed_domains", comma-separated) instead of the hardcoded
GOOGLE_HOSTED_DOMAIN from .env. .env is still used as the fallback so
existing installs keep working. Empty list = accept any Google account.

If exactly one domain is configured we pass `hd=` to Google as a login-
screen hint. With multiple (or none) we skip the hint and verify against
the ID token's email claim server-side after the callback — the URL param
alone is spoofable, and the ID token claim is what we actually trust.
"""
from authlib.integrations.flask_client import OAuth
from flask import session

from config import config

oauth = OAuth()


def init_oauth(app):
    oauth.init_app(app)
    # No hd= baked in at init time: we compute it per-request in
    # oauth_login() so the Setting can be edited live without restarting.
    oauth.register(
        name="google",
        client_id=config.GOOGLE_CLIENT_ID,
        client_secret=config.GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )


def email_domains_state() -> tuple[bool, list[str]]:
    """Returns (is_explicitly_set, domains).

    - is_explicitly_set: True iff the admin has saved this Setting at least
      once, even to an empty value (which means "no restriction, allow any").
    - domains: normalized list, possibly empty. Empty + is_explicitly_set →
      no restriction. Empty + not is_explicitly_set → fall back to .env.

    Row-existence check (not value-truthiness) is what makes "save empty to
    allow any email" work — otherwise the empty string gets treated as
    "never touched" and we bounce back to the .env default forever.

    Wrapped in try/except so bootstrap mode (no DB / no tables) returns
    (False, []) and callers fall back to .env or accept-any.
    """
    try:
        from db import Setting, SessionLocal
        with SessionLocal() as s:
            row = s.get(Setting, "email_allowed_domains")
        if row is None:
            return False, []
        value = row.value or ""
        return True, [d.strip().lower() for d in value.split(",") if d.strip()]
    except Exception:
        return False, []


def allowed_email_domains() -> list[str]:
    """Current allowed-domain list, lowercased. Empty = any domain allowed.

    Priority: Setting (if explicitly saved, even to empty) > .env
    GOOGLE_HOSTED_DOMAIN > any-domain-allowed.
    """
    is_set, domains = email_domains_state()
    if is_set:
        return domains
    if config.GOOGLE_HOSTED_DOMAIN:
        return [config.GOOGLE_HOSTED_DOMAIN.lower()]
    return []


def domain_allowed(email: str) -> bool:
    """True if `email`'s domain is in the allowed list (or no restriction)."""
    domains = allowed_email_domains()
    if not domains:
        return True
    e = (email or "").lower()
    return any(e.endswith("@" + d) for d in domains)


def verify_workspace(claims: dict) -> bool:
    """Server-side check against the ID token's email claim. Runs at every
    OAuth callback so a domain removed from the Setting takes effect
    immediately for the next sign-in."""
    return domain_allowed(claims.get("email", ""))


def current_user() -> dict | None:
    return session.get("user")


def is_admin(user: dict | None = None) -> bool:
    user = user or current_user()
    if not user:
        return False
    email = user.get("email", "").lower()
    if email in config.ADMIN_EMAILS:
        return True
    # Lazy import to avoid circular dependency at module load.
    from db import Admin, SessionLocal
    with SessionLocal() as s:
        return s.get(Admin, email) is not None


def is_bootstrap_admin(email: str) -> bool:
    """Bootstrap admins (from .env) are permanent — they can't be removed via UI."""
    return (email or "").lower() in config.ADMIN_EMAILS
