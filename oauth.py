"""Google OAuth via Authlib.

The portal restricts to a single Workspace domain (config.GOOGLE_HOSTED_DOMAIN).
We pass `hd=` as a hint AND verify the `hd` claim server-side after token exchange,
because the URL parameter alone is spoofable.
"""
from authlib.integrations.flask_client import OAuth
from flask import session

from config import config

oauth = OAuth()


def init_oauth(app):
    oauth.init_app(app)
    extras = {}
    if config.GOOGLE_HOSTED_DOMAIN:
        extras["hd"] = config.GOOGLE_HOSTED_DOMAIN
    oauth.register(
        name="google",
        client_id=config.GOOGLE_CLIENT_ID,
        client_secret=config.GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile", **extras},
    )


def verify_workspace(claims: dict) -> bool:
    """Server-side check that the ID token came from the configured Workspace."""
    if not config.GOOGLE_HOSTED_DOMAIN:
        return True
    return claims.get("hd", "").lower() == config.GOOGLE_HOSTED_DOMAIN.lower()


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
