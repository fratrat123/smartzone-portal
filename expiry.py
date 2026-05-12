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
from datetime import datetime, timezone

from sqlalchemy import select

from db import Device, SessionLocal, audit
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


def _loop():
    log.info("expiry: sweeper started (interval=%ds)", SWEEP_INTERVAL_SECONDS)
    while True:
        try:
            _sweep_once()
        except Exception:
            log.exception("expiry: sweep crashed")
        time.sleep(SWEEP_INTERVAL_SECONDS)


def start_sweeper_thread() -> threading.Thread:
    t = threading.Thread(target=_loop, name="expiry-sweeper", daemon=True)
    t.start()
    return t
