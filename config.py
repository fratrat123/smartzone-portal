"""Environment configuration.

This module is intentionally permissive: every value loads even if its env var
is missing. That lets the app boot into a minimal "bootstrap mode" with a
blank .env so the setup wizard can collect the configuration and write it
back. `is_setup_complete()` is the canonical "are we configured?" check.
"""
import os
import secrets
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


def _int(name: str, default: int) -> int:
    v = os.getenv(name)
    try:
        return int(v) if v else default
    except ValueError:
        return default


# Keys that must be set for normal-mode operation. Used by the wizard to know
# what it still needs to collect, and by app.py to detect "SETUP_COMPLETE=true
# but the file is incomplete" misconfigurations.
REQUIRED_KEYS_FOR_NORMAL_MODE = [
    "FLASK_SECRET_KEY",
    "PORTAL_BASE_URL",
    "DATABASE_URL",
    "RADIUS_SHARED_SECRET",
    "SZ_HOST", "SZ_USERNAME", "SZ_PASSWORD",
    "COA_HOST", "COA_SECRET",
    "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
    "SMTP_HOST", "SMTP_FROM_EMAIL",
]


def is_setup_complete() -> bool:
    """True iff the portal should boot into normal mode.

    Logic:
    - If SETUP_COMPLETE is explicitly set in env (true/false), honor it. The
      wizard sets it to true on completion; the admin "Re-run wizard" button
      sets it to false.
    - If SETUP_COMPLETE is unset/blank, infer from whether the required keys
      are all populated. This keeps pre-wizard installs working on upgrade —
      a real, hand-edited .env counts as configured.
    """
    raw = os.getenv("SETUP_COMPLETE")
    if raw is not None and raw.strip():
        return _bool("SETUP_COMPLETE", False)
    return not missing_required_keys()


def missing_required_keys() -> list[str]:
    """Required keys that are unset or empty. Useful when SETUP_COMPLETE=true
    is claimed but some critical value is blank (typo, partial edit, etc.)."""
    return [k for k in REQUIRED_KEYS_FOR_NORMAL_MODE if not os.getenv(k, "").strip()]


class Config:
    # SECRET_KEY: if absent (bootstrap mode), generate an ephemeral one so
    # Flask can start. Wizard sessions won't survive a restart, which is fine —
    # the wizard is short-lived. In normal mode the .env value is used.
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY") or secrets.token_urlsafe(48)

    # Optional in bootstrap mode; the wizard collects it. Trailing slash is
    # stripped so url_for() builds clean URLs.
    PORTAL_BASE_URL = (os.getenv("PORTAL_BASE_URL") or "").rstrip("/")

    # --- Branding ---------------------------------------------------------
    PORTAL_BRAND_NAME = os.getenv("PORTAL_BRAND_NAME", "Captive Portal")
    PORTAL_SUPPORT_EMAIL = os.getenv("PORTAL_SUPPORT_EMAIL", "") or None
    PORTAL_EMAIL_PLACEHOLDER = os.getenv("PORTAL_EMAIL_PLACEHOLDER", "") or None
    PORTAL_LOGO_URL = os.getenv("PORTAL_LOGO_URL", "") or None

    # --- Database ---------------------------------------------------------
    # Sentinel default lets bootstrap mode start without a real DB. Normal
    # mode requires this to be set (validated via REQUIRED_KEYS_FOR_NORMAL_MODE).
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL") or "sqlite:///:memory:"

    # --- RADIUS -----------------------------------------------------------
    RADIUS_LISTEN_HOST = os.getenv("RADIUS_LISTEN_HOST", "0.0.0.0")
    RADIUS_LISTEN_PORT = _int("RADIUS_LISTEN_PORT", 1812)
    # Encode to bytes for pyrad. Empty bytes is harmless: RADIUS handler won't
    # be started in bootstrap mode.
    RADIUS_SHARED_SECRET = os.getenv("RADIUS_SHARED_SECRET", "").encode()
    RADIUS_MAC_FORMAT = os.getenv("RADIUS_MAC_FORMAT", "lower_no_sep")

    # --- SmartZone -------------------------------------------------------
    SZ_HOST = os.getenv("SZ_HOST", "")
    SZ_PORT = _int("SZ_PORT", 8443)
    SZ_API_VERSION = os.getenv("SZ_API_VERSION", "v11_1")
    SZ_USERNAME = os.getenv("SZ_USERNAME", "")
    SZ_PASSWORD = os.getenv("SZ_PASSWORD", "")
    SZ_VERIFY_TLS = _bool("SZ_VERIFY_TLS", False)

    # --- CoA -------------------------------------------------------------
    COA_HOST = os.getenv("COA_HOST", "")
    COA_PORT = _int("COA_PORT", 3799)
    COA_SECRET = os.getenv("COA_SECRET", "").encode()

    # --- Google OAuth ----------------------------------------------------
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GOOGLE_HOSTED_DOMAIN = os.getenv("GOOGLE_HOSTED_DOMAIN") or None

    # --- Admin authorization ---------------------------------------------
    ADMIN_EMAILS = set(_csv("ADMIN_EMAILS"))

    # --- Email -----------------------------------------------------------
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = _int("SMTP_PORT", 587)
    SMTP_USER = os.getenv("SMTP_USER", "") or None
    SMTP_PASS = os.getenv("SMTP_PASS", "") or None
    SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "")
    SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME") or PORTAL_BRAND_NAME
    EMAIL_VERIFY_TTL_MINUTES = _int("EMAIL_VERIFY_TTL_MINUTES", 15)

    # --- Notifications ---------------------------------------------------
    NOTIFY_SLACK_WEBHOOK_URL = os.getenv("NOTIFY_SLACK_WEBHOOK_URL", "") or None
    NOTIFY_EMAILS = _csv("NOTIFY_EMAILS")

    # --- Retention -------------------------------------------------------
    EMAIL_VERIFY_RETENTION_DAYS = _int("EMAIL_VERIFY_RETENTION_DAYS", 1)
    AUDIT_LOG_RETENTION_DAYS = _int("AUDIT_LOG_RETENTION_DAYS", 90)

    # --- TLS (in-process cert) -------------------------------------------
    # Paths to certbot's output (Cloudflare DNS-01). Read by the runner
    # script when binding 443. Blank in bootstrap mode.
    TLS_CERT_FILE = os.getenv("TLS_CERT_FILE", "") or None
    TLS_KEY_FILE = os.getenv("TLS_KEY_FILE", "") or None


config = Config()
