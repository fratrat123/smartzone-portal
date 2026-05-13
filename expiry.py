"""Background sweeper for expired approvals.

Once a minute, scans for devices whose `approved_until` has passed and:
  - flips their status from 'approved' to 'expired'
  - sends a SmartZone disconnect so any active session drops immediately
  - writes an audit_log entry

Designed to run as a daemon thread alongside the RADIUS server thread.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from config import config
from db import AuditLog, Device, EmailVerification, SessionLocal, audit
from smartzone import sz_client

log = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS = 60


def _sweep_once() -> int:
    """Flip any approved devices past their expiry to status='expired'. Returns count."""
    now = datetime.now(timezone.utc)
    flipped = 0
    with SessionLocal() as s:
        expired = s.scalars(
            select(Device).where(
                Device.status == "approved",
                Device.approved_until.is_not(None),
                Device.approved_until < now,
            )
        ).all()
        for d in expired:
            mac = d.mac
            ap_mac = d.first_seen_ap_mac
            d.status = "expired"
            audit(s, "expired", mac=mac,
                  details=f"expired at {d.approved_until.isoformat()}")
            log.info("expiry: marked %s expired (was approved until %s)",
                     mac, d.approved_until.isoformat())
            flipped += 1
        s.commit()

        # Try to kick each one outside the DB session (network call).
        for d in expired:
            try:
                sz_client.disconnect_client(d.mac, d.first_seen_ap_mac)
            except Exception:
                log.exception("expiry: disconnect failed for %s", d.mac)
    return flipped


def _cleanup_email_verifications() -> int:
    """Delete email_verifications rows older than EMAIL_VERIFY_RETENTION_DAYS."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=config.EMAIL_VERIFY_RETENTION_DAYS)
    with SessionLocal() as s:
        result = s.execute(
            delete(EmailVerification).where(EmailVerification.created_at < cutoff)
        )
        s.commit()
        n = result.rowcount or 0
    if n:
        log.info("expiry: pruned %d old email_verifications", n)
    return n


def _cleanup_audit_log() -> int:
    """Delete audit_log rows older than AUDIT_LOG_RETENTION_DAYS (0 disables)."""
    if config.AUDIT_LOG_RETENTION_DAYS <= 0:
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=config.AUDIT_LOG_RETENTION_DAYS)
    with SessionLocal() as s:
        result = s.execute(
            delete(AuditLog).where(AuditLog.ts < cutoff)
        )
        s.commit()
        n = result.rowcount or 0
    if n:
        log.info("expiry: pruned %d old audit_log rows", n)
    return n


def _loop():
    log.info("expiry: sweeper started (interval=%ds)", SWEEP_INTERVAL_SECONDS)
    cleanup_tick = 0
    while True:
        try:
            _sweep_once()
            # Cleanup runs less frequently (once per hour) since rows accumulate slowly.
            cleanup_tick += 1
            if cleanup_tick >= 60:  # 60 minutes
                cleanup_tick = 0
                try:
                    _cleanup_email_verifications()
                    _cleanup_audit_log()
                except Exception:
                    log.exception("expiry: cleanup crashed")
        except Exception:
            log.exception("expiry: sweep crashed")
        time.sleep(SWEEP_INTERVAL_SECONDS)


def start_sweeper_thread() -> threading.Thread:
    t = threading.Thread(target=_loop, name="expiry-sweeper", daemon=True)
    t.start()
    return t
