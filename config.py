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
    SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Wi-Fi Portal")
    EMAIL_VERIFY_TTL_MINUTES = int(os.getenv("EMAIL_VERIFY_TTL_MINUTES", "15"))


config = Config()
