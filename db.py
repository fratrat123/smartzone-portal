from datetime import datetime
from sqlalchemy import create_engine, String, Text, DateTime, Enum, BigInteger, Integer, CHAR, inspect, text
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
    last_seen_ssid: Mapped[str | None] = mapped_column(String(64))
    last_seen_ap_mac: Mapped[str | None] = mapped_column(CHAR(17))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime)


class DeviceSsidSeen(Base):
    """Per-(MAC, SSID) tally — every WLAN a device has hit, with first/last/count.
    Lets the device detail page show every WLAN the MAC has associated to, even
    though approval status stays global on Device."""
    __tablename__ = "device_ssid_seen"

    mac: Mapped[str] = mapped_column(CHAR(12), primary_key=True)
    ssid: Mapped[str] = mapped_column(String(64), primary_key=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    hit_count: Mapped[int] = mapped_column(Integer, default=1)


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
    _add_missing_columns()


def _add_missing_columns():
    """Lightweight ALTER TABLE for columns added after a DB was first created.

    SQLAlchemy's create_all only creates missing tables, not missing columns on
    existing tables. We inspect what's there and ADD COLUMN for anything new.
    Each entry: (table, column_name, column_ddl). Skip silently if the table
    doesn't exist yet (fresh DB — create_all already handled it).
    """
    additions = [
        ("devices", "last_seen_ssid", "VARCHAR(64)"),
        ("devices", "last_seen_ap_mac", "CHAR(17)"),
    ]
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, col, ddl in additions:
            if not insp.has_table(table):
                continue
            cols = {c["name"] for c in insp.get_columns(table)}
            if col in cols:
                continue
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))


def audit(session, action: str, *, mac: str | None = None, actor: str | None = None, details: str | None = None):
    session.add(AuditLog(action=action, mac=mac, actor_email=actor, details=details))
