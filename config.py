import os
from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _csv(name: str) -> list[str]:
    v = os.getenv(name, "")
    return [x.strip().lower() for x in v.split(",") if x.strip()]


class Config:
    SECRET_KEY = os.environ["FLASK_SECRET_KEY"]
    PORTAL_BASE_URL = os.environ["PORTAL_BASE_URL"].rstrip("/")

    # --- Branding ---------------------------------------------------------
    # Shown on every page header, the OAuth/sign-in screen, and as the prefix
    # in outbound email subjects. The wizard collects this on first run.
    PORTAL_BRAND_NAME = os.getenv("PORTAL_BRAND_NAME", "Captive Portal")
    # Optional: shown to end users as the "need help?" contact. Blank hides it.
    PORTAL_SUPPORT_EMAIL = os.getenv("PORTAL_SUPPORT_EMAIL", "") or None
    # Placeholder text for the email input on the portal login page. If left
    # blank, derives one from GOOGLE_HOSTED_DOMAIN if set, else "you@example.com".
    PORTAL_EMAIL_PLACEHOLDER = os.getenv("PORTAL_EMAIL_PLACEHOLDER", "") or None
    # Optional override for the small logo mark in the header. URL or path
    # under /static/. If blank, the template renders the first letter of
    # PORTAL_BRAND_NAME in a colored tile.
    PORTAL_LOGO_URL = os.getenv("PORTAL_LOGO_URL", "") or None

    SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]

    RADIUS_LISTEN_HOST = os.getenv("RADIUS_LISTEN_HOST", "0.0.0.0")
    RADIUS_LISTEN_PORT = int(os.getenv("RADIUS_LISTEN_PORT", "1812"))
    RADIUS_SHARED_SECRET = os.environ["RADIUS_SHARED_SECRET"].encode()
    RADIUS_MAC_FORMAT = os.getenv("RADIUS_MAC_FORMAT", "lower_no_sep")

    SZ_HOST = os.environ["SZ_HOST"]
    SZ_PORT = int(os.getenv("SZ_PORT", "8443"))
    SZ_API_VERSION = os.getenv("SZ_API_VERSION", "v13_1")
    SZ_USERNAME = os.environ["SZ_USERNAME"]
    SZ_PASSWORD = os.environ["SZ_PASSWORD"]
    SZ_VERIFY_TLS = _bool("SZ_VERIFY_TLS", False)

    COA_HOST = os.environ["COA_HOST"]
    COA_PORT = int(os.getenv("COA_PORT", "3799"))
    COA_SECRET = os.environ["COA_SECRET"].encode()

    GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
    GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
    GOOGLE_HOSTED_DOMAIN = os.getenv("GOOGLE_HOSTED_DOMAIN") or None

    ADMIN_EMAILS = set(_csv("ADMIN_EMAILS"))

    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "") or None
    SMTP_PASS = os.getenv("SMTP_PASS", "") or None
    SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "")
    # Defaults to PORTAL_BRAND_NAME so outbound mail reads consistently.
    SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME") or PORTAL_BRAND_NAME
    EMAIL_VERIFY_TTL_MINUTES = int(os.getenv("EMAIL_VERIFY_TTL_MINUTES", "15"))

    NOTIFY_SLACK_WEBHOOK_URL = os.getenv("NOTIFY_SLACK_WEBHOOK_URL", "") or None
    NOTIFY_EMAILS = _csv("NOTIFY_EMAILS")

    EMAIL_VERIFY_RETENTION_DAYS = int(os.getenv("EMAIL_VERIFY_RETENTION_DAYS", "1"))
    AUDIT_LOG_RETENTION_DAYS = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "90"))


config = Config()
