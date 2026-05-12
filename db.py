from datetime import datetime
from sqlalchemy import create_engine, String, Text, DateTime, Enum, BigInteger, Integer, CHAR
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, scoped_session
from config import config


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "devices"

    mac: Mapped[str] = mapped_column(CHAR(12), primary_key=True)
    status: Mapped[str] = mapped_column(
        Enum("pending", "approved", "denied", "expired", "ignored",
             name="device_status"),
        default="pending",
    )
    hostname: Mapped[str | None] = mapped_column(String(255))
    device_type: Mapped[str | None] = mapped_column(String(64))
    friendly_name: Mapped[str | None] = mapped_column(String(128))
    note: Mapped[str | None] = mapped_column(Text)

    requested_by_email: Mapped[str | None] = mapped_column(String(255))
    requested_by_sub: Mapped[str | None] = mapped_column(String(64))
    requested_at: Mapped[datetime | None] = mapped_column(DateTime)

    decided_by_email: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    # Null = forever. Otherwise when this passes, the sweeper flips status to "expired".
    approved_until: Mapped[datetime | None] = mapped_column(DateTime)

    first_seen_ssid: Mapped[str | None] = mapped_column(String(64))
    first_seen_ap_mac: Mapped[str | None] = mapped_column(CHAR(17))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime)


class EmailVerification(Base):
    """A pending email magic-link / code verification.

    Created when a user enters their email on the portal. Cleared when verified
    (we leave the row but mark verified_at) or expired (sweeper could delete,
    not implemented yet).
    """
    __tablename__ = "email_verifications"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer(), "sqlite"),
        primary_key=True, autoincrement=True,
    )
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    code: Mapped[str] = mapped_column(String(8))
    email: Mapped[str] = mapped_column(String(255))
    mac: Mapped[str] = mapped_column(CHAR(12))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    attempts: Mapped[int] = mapped_column(Integer, default=0)


class Admin(Base):
    """Admins added through the UI. Bootstrap admins from .env's ADMIN_EMAILS
    are also trusted but NOT stored here — they're permanent and removable only
    by editing .env."""
    __tablename__ = "admins"

    email: Mapped[str] = mapped_column(String(255), primary_key=True)
    added_by_email: Mapped[str | None] = mapped_column(String(255))
    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    note: Mapped[str | None] = mapped_column(Text)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer(), "sqlite"),
        primary_key=True, autoincrement=True,
    )
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    actor_email: Mapped[str | None] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(32))
    mac: Mapped[str | None] = mapped_column(CHAR(12))
    details: Mapped[str | None] = mapped_column(Text)


_is_sqlite = config.SQLALCHEMY_DATABASE_URI.startswith("sqlite")
engine = create_engine(
    config.SQLALCHEMY_DATABASE_URI,
    pool_pre_ping=not _is_sqlite,
    pool_recycle=1800 if not _is_sqlite else -1,
    # SQLite + threads (RADIUS server runs in a thread alongside Flask)
    connect_args={"check_same_thread": False} if _is_sqlite else {},
)
SessionLocal = scoped_session(sessionmaker(bind=engine, expire_on_commit=False))


def init_db():
    """Create tables if they don't exist. Safe to call on every startup."""
    Base.metadata.create_all(engine)


def audit(session, action: str, *, mac: str | None = None, actor: str | None = None, details: str | None = None):
    session.add(AuditLog(action=action, mac=mac, actor_email=actor, details=details))
