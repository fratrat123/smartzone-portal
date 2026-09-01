"""Admin routes — approve/deny pending devices, browse history."""
import logging
import os
import shutil
import signal
import threading
import time
from datetime import datetime, timedelta, timezone

from functools import wraps

from flask import (Blueprint, abort, current_app, flash, redirect,
                   render_template, request, url_for)
from werkzeug.utils import secure_filename
from sqlalchemy import func, select

from action_tokens import TokenError, parse_token
from coa import disconnect as coa_disconnect
from config import config
from db import (Admin, AuditLog, Device, DeviceSsidSeen, ExtraNotifyRecipient,
                SessionLocal, Setting, audit, get_setting, set_setting)
from device_types import DEVICE_TYPES_BY_KEY
from macfmt import display_colon
from oauth import (allowed_email_domains, current_user, domain_allowed,
                   email_domains_state, is_admin, is_bootstrap_admin)
from smartzone import sz_client

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.app_context_processor
def inject_admin_defaults():
    """Make the operator-configured default approval duration available to
    every template, so all the duration dropdowns can pre-select the right
    option without each route having to pass it explicitly."""
    try:
        with SessionLocal() as s:
            try:
                v = int(get_setting(s, "default_approval_seconds", "0"))
            except (ValueError, TypeError):
                v = 0
    except Exception:
        v = 0
    return {"default_approval_seconds": v}


def _default_approval_seconds() -> int:
    """Read the operator-configured default approval duration. 0 = forever.
    Defaults to 0 if unset (the appliance ships approving-forever)."""
    with SessionLocal() as s:
        try:
            return int(get_setting(s, "default_approval_seconds", "0"))
        except (ValueError, TypeError):
            return 0


def _kick_client(mac: str, ap_mac: str | None) -> tuple[bool, str, str]:
    """Try SmartZone Public API first, then CoA-Disconnect over RADIUS.

    Returns (ok, method, detail). `method` is the path that ultimately succeeded
    (or was attempted), `detail` is a short human-readable explanation for the
    audit log / admin flash messages."""
    # SmartZone API path: needs the AP MAC (learned from RADIUS Called-Station-Id).
    if ap_mac:
        try:
            if sz_client.disconnect_client(mac, ap_mac):
                return True, "sz_api", "ok"
        except Exception as e:
            log = logging.getLogger(__name__)
            log.exception("sz_api disconnect crashed for %s", mac)
            sz_detail = f"sz_api crashed: {e}"
        else:
            sz_detail = "sz_api rejected (check service-user role + Called-Station-Id=AP MAC)"
    else:
        sz_detail = "sz_api skipped (no AP MAC yet — device not seen on RADIUS)"

    # CoA fallback over RADIUS UDP 3799.
    try:
        if coa_disconnect(mac):
            return True, "coa_radius", "ok"
        coa_detail = "coa_radius no-ack (CoA-NAK or timeout — check SmartZone NAS IP + CoA secret)"
    except Exception as e:
        log = logging.getLogger(__name__)
        log.exception("coa_radius crashed for %s", mac)
        coa_detail = f"coa_radius crashed: {e}"

    return False, "none", f"{sz_detail}; {coa_detail}"


def _flash_kick_result(action: str, ok: bool, method: str, detail: str) -> None:
    """Flash a banner so the admin can see whether the kick worked.

    On success the message is short. On failure it spells out *which* path
    failed and what to check, because the SmartZone / CoA config is what
    operators tweak when this goes wrong (admin-role permissions, AAA Auth
    Service CoA flag, NAS IP)."""
    verb = {"approve": "Approved", "deny": "Denied",
            "ignore": "Ignored", "reset": "Reset"}.get(action, action.capitalize())
    if ok:
        flash(f"{verb}. Client kicked via {method} — they'll reassociate "
              f"and pick up the new status.", "success")
    else:
        flash(
            f"{verb}, but the client could NOT be kicked: {detail}. "
            "The DB is updated; the device will pick up the new status only "
            "after it manually disconnects and reassociates (or its session "
            "naturally expires). See the SmartZone page for troubleshooting.",
            "warning",
        )


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("portal.oauth_login"))
        if not is_admin(user):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@bp.route("/")
@admin_required
def queue():
    show_ignored = request.args.get("ignored") == "1"
    ssid_filter = (request.args.get("ssid") or "").strip() or None
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)

    def _apply_ssid(q):
        if not ssid_filter:
            return q
        # Match either last_seen_ssid OR any historical association in
        # device_ssid_seen. A device that hit SSID-A then SSID-B should still
        # appear under the SSID-A filter.
        sub = select(DeviceSsidSeen.mac).where(DeviceSsidSeen.ssid == ssid_filter)
        return q.where((Device.last_seen_ssid == ssid_filter) | (Device.mac.in_(sub)))

    with SessionLocal() as s:
        pending = s.scalars(
            _apply_ssid(select(Device).where(Device.status == "pending"))
            .order_by(Device.requested_at.desc().nullslast())
        ).all()
        recent = s.scalars(
            _apply_ssid(select(Device).where(Device.status.in_(("approved", "denied", "expired"))))
            .order_by(Device.decided_at.desc().nullslast()).limit(50)
        ).all()
        ignored = []
        if show_ignored:
            ignored = s.scalars(
                _apply_ssid(select(Device).where(Device.status == "ignored"))
                .order_by(Device.decided_at.desc().nullslast()).limit(100)
            ).all()
        ignored_count = s.scalar(
            select(func.count()).select_from(Device).where(Device.status == "ignored")
        ) or 0
        known_ssids = [r[0] for r in s.execute(
            select(DeviceSsidSeen.ssid).distinct().order_by(DeviceSsidSeen.ssid)
        ).all() if r[0]]
        # Per-MAC SSID list for the rows we're rendering — one query, then
        # group in Python, so the template can show a tooltip when a device
        # has been on more than one WLAN.
        macs_on_page = {d.mac for d in (*pending, *recent, *ignored)}
        ssids_by_mac: dict[str, list[str]] = {}
        if macs_on_page:
            for mac, ssid in s.execute(
                select(DeviceSsidSeen.mac, DeviceSsidSeen.ssid)
                .where(DeviceSsidSeen.mac.in_(macs_on_page))
                .order_by(DeviceSsidSeen.last_seen_at.desc())
            ).all():
                ssids_by_mac.setdefault(mac, []).append(ssid)

        # ---- Stats (lightweight; same query path the queue already touches) ----
        counts = {}
        for status, cnt in s.execute(
            select(Device.status, func.count()).group_by(Device.status)
        ).all():
            counts[status] = int(cnt)

        approved_now = counts.get("approved", 0)
        pending_count = counts.get("pending", 0)

        # Approvals expiring in the next 24h
        expiring_soon = s.scalar(
            select(func.count()).select_from(Device).where(
                Device.status == "approved",
                Device.approved_until.is_not(None),
                Device.approved_until < (now + timedelta(hours=24)),
            )
        ) or 0

        # New requests / approvals over the last 7 days, bucketed by day
        new_per_day = {}
        approved_per_day = {}
        for row in s.execute(
            select(Device.requested_at).where(Device.requested_at >= seven_days_ago)
        ).all():
            d = row[0].date() if row[0] else None
            if d:
                new_per_day[d] = new_per_day.get(d, 0) + 1
        for row in s.execute(
            select(Device.decided_at).where(
                Device.status == "approved",
                Device.decided_at >= seven_days_ago,
            )
        ).all():
            d = row[0].date() if row[0] else None
            if d:
                approved_per_day[d] = approved_per_day.get(d, 0) + 1

    # Build a 7-day series for the chart
    series = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).date()
        series.append({
            "label": day.strftime("%a"),
            "date": day.isoformat(),
            "new": new_per_day.get(day, 0),
            "approved": approved_per_day.get(day, 0),
        })
    series_max = max((max(s["new"], s["approved"]) for s in series), default=1) or 1

    stats = {
        "pending": pending_count,
        "approved": approved_now,
        "expiring_soon": int(expiring_soon),
        "denied": counts.get("denied", 0) + counts.get("expired", 0),
        "ignored": counts.get("ignored", 0),
        "series": series,
        "series_max": series_max,
    }

    return render_template(
        "admin_queue.html",
        pending=[_view(d, ssids_by_mac.get(d.mac)) for d in pending],
        recent=[_view(d, ssids_by_mac.get(d.mac)) for d in recent],
        ignored=[_view(d, ssids_by_mac.get(d.mac)) for d in ignored],
        ignored_count=int(ignored_count),
        show_ignored=show_ignored,
        stats=stats,
        known_ssids=known_ssids,
        ssid_filter=ssid_filter,
        user=current_user(),
    )


@bp.route("/devices")
@admin_required
def devices():
    """Full device list — every device the portal has ever seen, regardless of
    status. Filter by status, search by email/MAC/hostname/friendly name,
    paginate, bulk-act. This is the management view; /admin/queue stays as
    the 'what needs attention right now' view.
    """
    from sqlalchemy import or_
    from macfmt import canonical as _canonical

    status_filter = (request.args.get("status") or "").strip()
    q = (request.args.get("q") or "").strip()
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    per_page = 50

    with SessionLocal() as s:
        query = select(Device)
        if status_filter and status_filter != "all":
            query = query.where(Device.status == status_filter)
        if q:
            ql = q.lower()
            conditions = [
                Device.requested_by_email.ilike(f"%{ql}%"),
                Device.hostname.ilike(f"%{ql}%"),
                Device.friendly_name.ilike(f"%{ql}%"),
                Device.decided_by_email.ilike(f"%{ql}%"),
                Device.last_seen_ssid.ilike(f"%{ql}%"),
            ]
            # If the input parses as a MAC, also try exact match.
            try:
                conditions.append(Device.mac == _canonical(q))
            except ValueError:
                pass
            query = query.where(or_(*conditions))

        total = s.scalar(select(func.count()).select_from(query.subquery())) or 0
        total_pages = max(1, (total + per_page - 1) // per_page)
        rows = s.scalars(
            query.order_by(
                Device.requested_at.desc().nullslast(),
                Device.last_seen_at.desc().nullslast(),
            ).limit(per_page).offset((page - 1) * per_page)
        ).all()

        macs_on_page = {d.mac for d in rows}
        ssids_by_mac: dict[str, list[str]] = {}
        if macs_on_page:
            for mac, ssid in s.execute(
                select(DeviceSsidSeen.mac, DeviceSsidSeen.ssid)
                .where(DeviceSsidSeen.mac.in_(macs_on_page))
                .order_by(DeviceSsidSeen.last_seen_at.desc())
            ).all():
                ssids_by_mac.setdefault(mac, []).append(ssid)

        # Per-status counts for the filter dropdown labels.
        status_counts: dict[str, int] = {}
        for st, cnt in s.execute(
            select(Device.status, func.count()).group_by(Device.status)
        ).all():
            status_counts[st] = int(cnt)
        total_all = sum(status_counts.values())

    return render_template(
        "admin_devices.html",
        devices=[_view(d, ssids_by_mac.get(d.mac)) for d in rows],
        status_filter=status_filter,
        q=q,
        page=page,
        total=total,
        total_all=total_all,
        total_pages=total_pages,
        status_counts=status_counts,
        user=current_user(),
    )


@bp.route("/queue.json")
@admin_required
def queue_status():
    """Lightweight status digest for the admin page to poll.

    Returns just enough info to detect a change (new pending, decision made) —
    when the digest differs from what the page was rendered with, the page
    reloads to fetch the full table.
    """
    with SessionLocal() as s:
        pending_count = s.scalar(
            select(func.count()).select_from(Device).where(Device.status == "pending")
        ) or 0
        last_change = s.scalar(
            select(func.max(Device.decided_at))
        )
        last_request = s.scalar(
            select(func.max(Device.requested_at))
        )
    # A simple digest: combine the count and most recent timestamps.
    return {
        "pending_count": int(pending_count),
        "last_decided_at": last_change.isoformat() if last_change else None,
        "last_requested_at": last_request.isoformat() if last_request else None,
    }


@bp.route("/device/<mac>", methods=["GET", "POST"])
@admin_required
def device(mac):
    if request.method == "POST":
        return _device_post(mac)
    return _device_get(mac)


def _device_post(mac: str):
    """Handle approve/deny/ignore/reset/delete from the device detail form.

    Critical: any helper that opens its own `with SessionLocal() as s:` must
    be called BEFORE we enter our own outer `with` block, never inside it.
    SessionLocal is a `scoped_session` keyed on the thread, so a nested
    `with` resolves to the *same* session — and its inner __exit__ calls
    close()/expunge_all() on it, detaching every object loaded by the outer
    block (including `dev`). Subsequent attribute changes on `dev` then have
    no session to track them, so the commit() at the end of the outer block
    flushes nothing for the device row even though the audit row goes
    through fine. The previous bug-fix attempt moved the kick out of the
    outer with but left `_default_approval_seconds()` inside, so the device
    row UPDATE was still being silently dropped.
    """
    log = logging.getLogger(__name__)
    action = request.form.get("action")
    note = (request.form.get("note") or "").strip()[:1000] or None
    actor = current_user()["email"]
    log.info("device POST: mac=%s action=%s actor=%s", mac, action, actor)

    if action not in ("approve", "deny", "ignore", "reset", "delete"):
        abort(400)

    # Resolve approval duration *before* opening the outer session — see the
    # docstring above for why nesting matters.
    duration = 0
    if action == "approve":
        default = _default_approval_seconds()
        try:
            duration = int(request.form.get("duration", str(default)))
        except ValueError:
            duration = default

    ap_mac: str | None = None
    with SessionLocal() as s:
        dev = s.get(Device, mac)
        if not dev:
            abort(404)

        if action == "delete":
            s.execute(
                DeviceSsidSeen.__table__.delete().where(DeviceSsidSeen.mac == mac)
            )
            audit(s, "delete", mac=mac, actor=actor,
                  details=f"prev_status={dev.status} {note or ''}".strip())
            s.delete(dev)
            s.commit()
            flash("Device record deleted.", "success")
            return redirect(url_for("admin.queue"))

        now = datetime.now(timezone.utc)
        if action == "approve":
            dev.status = "approved"
            dev.decided_by_email = actor
            dev.decided_at = now
            dev.approved_until = (now + timedelta(seconds=duration)) if duration > 0 else None
        elif action == "deny":
            dev.status = "denied"
            dev.decided_by_email = actor
            dev.decided_at = now
            dev.approved_until = None
        elif action == "ignore":
            dev.status = "ignored"
            dev.decided_by_email = actor
            dev.decided_at = now
            dev.approved_until = None
        else:  # reset
            dev.status = "pending"
            dev.decided_by_email = None
            dev.decided_at = None
            dev.approved_until = None

        if note:
            dev.note = note

        audit_details = note or ""
        if action == "approve" and dev.approved_until:
            audit_details = f"until={dev.approved_until.isoformat()} {audit_details}".strip()
        audit(s, action, mac=mac, actor=actor, details=audit_details or None)
        # Capture before the session closes so the kick below doesn't try
        # to lazy-load on a detached / expired instance.
        ap_mac = dev.first_seen_ap_mac
        s.commit()
    # ---- with s: closed; status change is durably persisted ----

    # Kick the client on a separate session-scope so the close() that the
    # kick-audit triggers can't roll back / hide the status update above.
    kicked, method, detail = _kick_client(mac, ap_mac)
    with SessionLocal() as s2:
        audit(s2, "kick_sent", mac=mac, actor=actor,
              details=f"method={method} ok={kicked} ap_mac={ap_mac} {detail}")
        s2.commit()
    _flash_kick_result(action, kicked, method, detail)

    if action == "reset":
        return redirect(url_for("admin.device", mac=mac))
    return redirect(url_for("admin.queue"))


def _device_get(mac: str):
    with SessionLocal() as s:
        dev = s.get(Device, mac)
        if not dev:
            abort(404)
        history = s.scalars(
            select(AuditLog).where(AuditLog.mac == mac).order_by(AuditLog.ts.desc()).limit(50)
        ).all()
        ssid_rows = s.scalars(
            select(DeviceSsidSeen).where(DeviceSsidSeen.mac == mac)
            .order_by(DeviceSsidSeen.last_seen_at.desc())
        ).all()
        ssids_seen_view = [
            {
                "ssid": r.ssid,
                "first_seen_at": r.first_seen_at,
                "last_seen_at": r.last_seen_at,
                "hit_count": r.hit_count,
            }
            for r in ssid_rows
        ]
        view = _view(dev, [r["ssid"] for r in ssids_seen_view])

    return render_template(
        "admin_device.html",
        d=view,
        history=history,
        ssids_seen=ssids_seen_view,
    )


@bp.route("/bulk", methods=["POST"])
@admin_required
def bulk():
    """Apply one action to multiple selected MACs from the queue."""
    action = request.form.get("bulk_action")
    macs = request.form.getlist("mac")
    if not macs or action not in ("approve", "deny", "ignore", "delete"):
        return redirect(url_for("admin.queue"))

    actor = current_user()["email"]
    now = datetime.now(timezone.utc)
    default = _default_approval_seconds()
    try:
        duration = int(request.form.get("duration", str(default)))
    except ValueError:
        duration = default

    ap_macs_for_kick: list[tuple[str, str | None]] = []
    with SessionLocal() as s:
        for mac in macs:
            dev = s.get(Device, mac)
            if not dev:
                continue
            if action == "delete":
                s.execute(
                    DeviceSsidSeen.__table__.delete().where(DeviceSsidSeen.mac == mac)
                )
                audit(s, "delete", mac=mac, actor=actor,
                      details=f"bulk prev_status={dev.status}")
                s.delete(dev)
                continue   # no kick to send; row's gone
            if action == "approve":
                dev.status = "approved"
                dev.decided_by_email = actor
                dev.decided_at = now
                dev.approved_until = (now + timedelta(seconds=duration)) if duration > 0 else None
            elif action == "deny":
                dev.status = "denied"
                dev.decided_by_email = actor
                dev.decided_at = now
                dev.approved_until = None
            elif action == "ignore":
                dev.status = "ignored"
                dev.decided_by_email = actor
                dev.decided_at = now
                dev.approved_until = None
            audit(s, action, mac=mac, actor=actor, details="bulk")
            ap_macs_for_kick.append((mac, dev.first_seen_ap_mac))
        s.commit()

    # Fire kicks outside the DB session (network calls). Tally results so the
    # admin sees an aggregate banner instead of a wall of per-device flashes.
    kicked_n = 0
    failed: list[tuple[str, str]] = []  # (mac, detail)
    for mac, ap_mac in ap_macs_for_kick:
        ok, method, detail = _kick_client(mac, ap_mac)
        if ok:
            kicked_n += 1
        else:
            failed.append((mac, detail))
        with SessionLocal() as s3:
            audit(s3, "kick_sent", mac=mac, actor=actor,
                  details=f"bulk method={method} ok={ok} ap_mac={ap_mac} {detail}")
            s3.commit()

    total = len(ap_macs_for_kick)
    if action == "delete" or total == 0:
        pass  # nothing to flash about kicks
    elif not failed:
        flash(f"{action.capitalize()}d {total} device(s); all clients kicked.", "success")
    else:
        # Pick one representative detail (they're usually the same root cause).
        sample = failed[0][1]
        flash(
            f"{action.capitalize()}d {total} device(s); "
            f"{kicked_n} kicked OK, {len(failed)} could NOT be kicked. "
            f"Affected devices will pick up the new status only after they "
            f"manually disconnect and reassociate. "
            f"First failure: {sample}",
            "warning",
        )

    return redirect(url_for("admin.queue"))


@bp.route("/audit")
@admin_required
def audit_view():
    action = (request.args.get("action") or "").strip()
    mac_q = (request.args.get("mac") or "").strip().lower().replace(":", "").replace("-", "")
    actor_q = (request.args.get("actor") or "").strip().lower()
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    per_page = 50

    with SessionLocal() as s:
        q = select(AuditLog)
        if action:
            q = q.where(AuditLog.action == action)
        if mac_q:
            q = q.where(AuditLog.mac == mac_q)
        if actor_q:
            q = q.where(AuditLog.actor_email.ilike(f"%{actor_q}%"))
        q = q.order_by(AuditLog.ts.desc())
        total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
        rows = s.scalars(q.limit(per_page).offset((page - 1) * per_page)).all()
        # Distinct action types for the filter dropdown
        actions = [r[0] for r in s.execute(
            select(AuditLog.action).distinct().order_by(AuditLog.action)
        ).all()]
        view_rows = [{
            "ts": r.ts,
            "action": r.action,
            "actor_email": r.actor_email,
            "mac": r.mac,
            "mac_display": display_colon(r.mac) if r.mac else "",
            "details": r.details,
        } for r in rows]

    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template(
        "admin_audit.html",
        rows=view_rows,
        actions=actions,
        action=action,
        mac=request.args.get("mac", ""),
        actor=actor_q,
        page=page,
        total_pages=total_pages,
        total=total,
    )


@bp.route("/settings", methods=["GET", "POST"])
@bp.route("/admins", methods=["GET", "POST"])    # backward compat
@admin_required
def settings():
    actor = current_user()["email"]
    error = None

    if request.method == "POST":
        action = request.form.get("action")
        email = (request.form.get("email") or "").strip().lower()

        if action == "add":
            # Validate: must be in the configured Workspace domain so OAuth
            # actually works for the new admin.
            if not email or "@" not in email:
                error = "Enter a valid email address."
            elif not domain_allowed(email):
                _doms = allowed_email_domains()
                error = ("Email must be in @" + " or @".join(_doms)
                         if _doms else "That email domain is not allowed.")
            elif is_bootstrap_admin(email):
                error = "That email is already a bootstrap admin (set in .env)."
            else:
                with SessionLocal() as s:
                    if s.get(Admin, email):
                        error = f"{email} is already an admin."
                    else:
                        s.add(Admin(
                            email=email,
                            added_by_email=actor,
                            note=(request.form.get("note") or "").strip()[:1000] or None,
                        ))
                        audit(s, "admin_add", actor=actor, details=f"added {email}")
                        s.commit()

        elif action == "remove":
            target = email
            if is_bootstrap_admin(target):
                error = "Bootstrap admins can only be removed by editing .env."
            elif target == actor:
                error = "You can't remove yourself."
            else:
                with SessionLocal() as s:
                    row = s.get(Admin, target)
                    if row:
                        s.delete(row)
                        audit(s, "admin_remove", actor=actor, details=f"removed {target}")
                        s.commit()

        elif action == "notify_add":
            # Additional non-admin email that should receive new-pending alerts.
            # No domain restriction (unlike admins) — these can be shared
            # mailboxes, audit aliases, external on-call addresses, etc.
            if not email or "@" not in email:
                error = "Enter a valid email address."
            else:
                with SessionLocal() as s:
                    if s.get(ExtraNotifyRecipient, email):
                        error = f"{email} is already on the notify list."
                    else:
                        s.add(ExtraNotifyRecipient(
                            email=email,
                            added_by_email=actor,
                            note=(request.form.get("note") or "").strip()[:1000] or None,
                        ))
                        audit(s, "notify_add", actor=actor, details=f"added {email}")
                        s.commit()

        elif action == "notify_remove":
            with SessionLocal() as s:
                row = s.get(ExtraNotifyRecipient, email)
                if row:
                    s.delete(row)
                    audit(s, "notify_remove", actor=actor, details=f"removed {email}")
                    s.commit()

        elif action == "set_default_approval":
            raw = (request.form.get("default_approval") or "").strip()
            try:
                seconds = int(raw)
            except ValueError:
                error = "Invalid duration."
            else:
                if seconds < 0:
                    error = "Duration must be 0 (forever) or positive."
                else:
                    with SessionLocal() as s:
                        set_setting(s, "default_approval_seconds", str(seconds), actor=actor)
                        audit(s, "setting_update", actor=actor,
                              details=f"default_approval_seconds={seconds}")
                        s.commit()

        elif action == "upload_logo":
            error = _handle_logo_upload(actor)

        elif action == "remove_logo":
            _handle_logo_remove(actor)

        elif action == "set_email_domains":
            # Comma-separated list. Normalize: strip, lowercase, drop empties,
            # drop leading @, dedup. Empty string means "any domain allowed".
            raw = (request.form.get("email_domains") or "").strip()
            seen = []
            for part in raw.split(","):
                d = part.strip().lower().lstrip("@")
                if d and d not in seen:
                    seen.append(d)
            normalized = ", ".join(seen)
            with SessionLocal() as s:
                set_setting(s, "email_allowed_domains", normalized, actor=actor)
                audit(s, "setting_update", actor=actor,
                      details=f"email_allowed_domains={normalized or '<any>'}")
                s.commit()

        if not error:
            return redirect(url_for("admin.settings"))

    with SessionLocal() as s:
        default_approval = get_setting(s, "default_approval_seconds", "0")
        current_logo_url = get_setting(s, "portal_logo_url", "") or config.PORTAL_LOGO_URL or ""

    # Read the domain Setting outside the SessionLocal above because
    # email_domains_state() opens its own — nested scoped-sessions would
    # detach the ORM instances we already loaded (same trap as the device
    # approve bug earlier). See oauth.email_domains_state docstring.
    is_email_domains_set, email_domains_list = email_domains_state()
    current_email_domains = ", ".join(email_domains_list) if is_email_domains_set else ""

    with SessionLocal() as s:
        db_admins = s.scalars(
            select(Admin).order_by(Admin.added_at.desc())
        ).all()
        db_admins_view = [
            {
                "email": a.email,
                "added_by_email": a.added_by_email,
                "added_at": a.added_at,
                "note": a.note,
            }
            for a in db_admins
        ]
        notify_recipients = s.scalars(
            select(ExtraNotifyRecipient).order_by(ExtraNotifyRecipient.added_at.desc())
        ).all()
        notify_view = [
            {
                "email": r.email,
                "added_by_email": r.added_by_email,
                "added_at": r.added_at,
                "note": r.note,
            }
            for r in notify_recipients
        ]

    bootstrap = sorted(config.ADMIN_EMAILS)
    env_notify = sorted(config.NOTIFY_EMAILS)
    return render_template(
        "admin_settings.html",
        bootstrap_admins=bootstrap,
        db_admins=db_admins_view,
        env_notify=env_notify,
        notify_recipients=notify_view,
        domain=config.GOOGLE_HOSTED_DOMAIN,
        default_approval=int(default_approval),
        current_email_domains=current_email_domains,
        is_email_domains_set=is_email_domains_set,
        env_hosted_domain=config.GOOGLE_HOSTED_DOMAIN,
        current_logo_url=current_logo_url,
        user=current_user(),
        error=error,
    )


# ---- Logo upload helpers --------------------------------------------------

# Conservative: PNG/JPG/GIF/WebP/SVG cover everything anyone reasonably
# brands a portal with. .ico shows up too poorly at the rendered size.
_ALLOWED_LOGO_EXTS = {"png", "jpg", "jpeg", "gif", "webp", "svg"}


def _handle_logo_upload(actor: str) -> str | None:
    """Save an uploaded logo into static/uploads and point Setting at it.

    Returns an error message string on failure, or None on success.
    """
    f = request.files.get("logo")
    if not f or not f.filename:
        return "No file selected."

    safe = secure_filename(f.filename)
    if "." not in safe:
        return "File has no extension; can't determine type."
    ext = safe.rsplit(".", 1)[1].lower()
    if ext not in _ALLOWED_LOGO_EXTS:
        return f"Unsupported file type .{ext}. Use {', '.join(sorted(_ALLOWED_LOGO_EXTS))}."

    # Always write to the same canonical name (logo.<ext>) so the old logo
    # gets overwritten on each upload. Clean up any other-extension copies
    # first so /static/uploads doesn't accumulate orphans.
    upload_dir = os.path.join(current_app.static_folder, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    for old_ext in _ALLOWED_LOGO_EXTS:
        old_path = os.path.join(upload_dir, f"logo.{old_ext}")
        if old_ext != ext and os.path.exists(old_path):
            try:
                os.unlink(old_path)
            except OSError:
                pass

    target_path = os.path.join(upload_dir, f"logo.{ext}")
    f.save(target_path)
    # Cache-bust the URL so browsers immediately pick up the new image.
    url = url_for("static", filename=f"uploads/logo.{ext}") + f"?v={int(time.time())}"

    with SessionLocal() as s:
        set_setting(s, "portal_logo_url", url, actor=actor)
        audit(s, "setting_update", actor=actor,
              details=f"portal_logo_url <- uploaded {safe} ({os.path.getsize(target_path)} bytes)")
        s.commit()
    return None


def _handle_logo_remove(actor: str) -> None:
    """Clear the logo Setting and delete any uploaded file under static/uploads."""
    upload_dir = os.path.join(current_app.static_folder, "uploads")
    for ext in _ALLOWED_LOGO_EXTS:
        p = os.path.join(upload_dir, f"logo.{ext}")
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
        except OSError:
            pass
    with SessionLocal() as s:
        set_setting(s, "portal_logo_url", "", actor=actor)
        audit(s, "setting_update", actor=actor, details="portal_logo_url cleared")
        s.commit()


@bp.route("/link/<token>", methods=["GET", "POST"])
def link_action(token: str):
    """Magic-link approve/deny from a notification email.

    Auth is the signed token itself (recipient + mac + action are baked in and
    HMAC'd). GET renders a confirm page; POST executes. The POST split exists
    so email prefetchers (Outlook ATP / link scanners) following GETs can't
    auto-trigger decisions.
    """
    try:
        mac, recipient_email, action, token_duration = parse_token(token)
    except TokenError as e:
        return render_template("admin_link_error.html", error=str(e)), 400

    # Recipient must still be an admin at click time. Reuse is_admin() with a
    # synthetic user dict so removed admins lose link access immediately.
    if not is_admin({"email": recipient_email}):
        return render_template("admin_link_error.html",
            error=f"{recipient_email} is no longer authorized to make this decision."), 403

    with SessionLocal() as s:
        dev = s.get(Device, mac)
        if not dev:
            return render_template("admin_link_error.html",
                error="That device is no longer on file."), 404

        if dev.status != "pending":
            return render_template(
                "admin_link_done.html",
                d=_view(dev),
                already=True,
                action_taken=action,
            )

        if request.method == "GET":
            return render_template(
                "admin_link_confirm.html",
                d=_view(dev),
                action=action,
                recipient_email=recipient_email,
                token=token,
                # Pre-select what the email link asked for. Falls back to
                # the operator's configured default if the token doesn't
                # carry one (older links from before the duration encoding).
                preselect_duration=(
                    token_duration if token_duration is not None
                    else _default_approval_seconds()
                ),
            )

        # POST: do it.
        now = datetime.now(timezone.utc)
        if action == "approve":
            # Order of preference: explicit form value > token-encoded > default.
            fallback = token_duration if token_duration is not None \
                else _default_approval_seconds()
            try:
                duration = int(request.form.get("duration", str(fallback)))
            except ValueError:
                duration = fallback
            dev.status = "approved"
            dev.approved_until = (now + timedelta(seconds=duration)) if duration > 0 else None
        elif action == "deny":
            dev.status = "denied"
            dev.approved_until = None
        else:
            abort(400)
        dev.decided_by_email = recipient_email
        dev.decided_at = now
        audit_details = "via=magic_link"
        if action == "approve" and dev.approved_until:
            audit_details = f"until={dev.approved_until.isoformat()} {audit_details}"
        elif action == "approve":
            audit_details = f"forever {audit_details}"
        audit(s, action, mac=mac, actor=recipient_email, details=audit_details)
        s.commit()

        ap_mac = dev.first_seen_ap_mac
        kicked, method, detail = _kick_client(mac, ap_mac)
        with SessionLocal() as s2:
            audit(s2, "kick_sent", mac=mac, actor=recipient_email,
                  details=f"method={method} ok={kicked} ap_mac={ap_mac} via=magic_link {detail}")
            s2.commit()

        return render_template(
            "admin_link_done.html",
            d=_view(dev),
            already=False,
            action_taken=action,
            kicked=kicked,
            kick_method=method,
            kick_detail=detail,
        )


@bp.route("/smartzone-config")
@admin_required
def smartzone_config():
    """Reference page: the values an operator needs to enter into the
    SmartZone controller. Same content as the wizard's WLAN checklist step,
    but rendered from the current .env so admins can come back to it any time
    (e.g. when adding a new WLAN, reconfiguring AAA, or recovering a forgotten
    shared secret). Admin-auth required; the page exposes the RADIUS shared
    secret behind a show/hide toggle."""
    from urllib.parse import urlparse
    base = (config.PORTAL_BASE_URL or "").rstrip("/")
    parsed = urlparse(base) if base else None
    portal_hostname = parsed.hostname if parsed else "your-portal-hostname"

    radius_secret = config.RADIUS_SHARED_SECRET.decode("utf-8", "replace") \
        if config.RADIUS_SHARED_SECRET else ""

    return render_template(
        "admin_smartzone_config.html",
        portal_hostname=portal_hostname,
        portal_logon_url=f"{base}/portal" if base else "(set PORTAL_BASE_URL in .env)",
        radius_listen_host=config.RADIUS_LISTEN_HOST,
        radius_listen_port=config.RADIUS_LISTEN_PORT,
        radius_secret=radius_secret,
        radius_mac_format=config.RADIUS_MAC_FORMAT,
        coa_host=config.COA_HOST,
        coa_port=config.COA_PORT,
    )


@bp.route("/factory-reset", methods=["POST"])
@admin_required
def factory_reset():
    """Wipe portal state back to wizard-default — admin-triggered factory
    reset. Same effect as running deploy/reset-wizard.sh, but no SSH needed.

    Wipes: portal.db, .bootstrap-secret, .wizard-state/, .env (reset to
    .env.example). Does NOT change network/hostname/packages/cert files.

    After the wipe, sends SIGTERM to the gunicorn master so systemd restarts
    the service. Without SETUP_COMPLETE=true in .env it'll come up in
    bootstrap mode at the wizard.
    """
    actor = current_user()["email"]
    log = logging.getLogger(__name__)
    log.warning("admin: factory reset requested by %s", actor)

    # Audit *before* we wipe so the request is recorded somewhere.
    # Cheap protection — the DB is about to be deleted anyway, but the
    # audit entry will be persisted via SQLite's WAL flush before we exit.
    with SessionLocal() as s:
        audit(s, "factory_reset", actor=actor, details="initiated")
        s.commit()

    app_dir = "/opt/captive-portal"

    def _do_reset():
        # Tiny delay so the HTTP response definitely makes it out.
        time.sleep(1.5)
        # Wipe portal state
        for fname in ("portal.db", "portal.db-journal",
                      "portal.db-wal", "portal.db-shm", ".bootstrap-secret"):
            try:
                os.unlink(os.path.join(app_dir, fname))
            except FileNotFoundError:
                pass
            except OSError as e:
                log.warning("factory reset: unlink %s failed: %s", fname, e)
        try:
            shutil.rmtree(os.path.join(app_dir, ".wizard-state"), ignore_errors=True)
        except Exception:
            log.exception("factory reset: rmtree .wizard-state failed")
        # Reset .env from .env.example so service comes back in bootstrap.
        try:
            src = os.path.join(app_dir, ".env.example")
            dst = os.path.join(app_dir, ".env")
            shutil.copy2(src, dst)
            try:
                import pwd
                uid = pwd.getpwnam("captive-portal").pw_uid
                os.chown(dst, uid, uid)
                os.chmod(dst, 0o640)
            except (KeyError, OSError):
                pass
        except Exception:
            log.exception("factory reset: failed to reset .env from .env.example")

        # SIGTERM gunicorn master so systemd restarts the whole service
        # and the new master reads the wiped .env (= bootstrap mode).
        if os.environ.get("INVOCATION_ID"):
            log.warning("factory reset: signaling master to restart")
            try:
                os.kill(os.getppid(), signal.SIGTERM)
            except OSError as e:
                log.warning("factory reset: SIGTERM failed: %s", e)
            time.sleep(2)
        os._exit(0)

    threading.Thread(target=_do_reset, name="factory-reset", daemon=True).start()

    return render_template("admin_factory_reset_done.html", actor=actor)


def _view(dev: Device, ssids_seen: list[str] | None = None) -> dict:
    return {
        "mac": dev.mac,
        "mac_display": display_colon(dev.mac),
        "status": dev.status,
        "hostname": dev.hostname or "(unknown)",
        "device_type_label": (DEVICE_TYPES_BY_KEY.get(dev.device_type) or {}).get("label", dev.device_type or "—"),
        "friendly_name": dev.friendly_name,
        "requested_by_email": dev.requested_by_email,
        "requested_at": dev.requested_at,
        "decided_by_email": dev.decided_by_email,
        "decided_at": dev.decided_at,
        "approved_until": dev.approved_until,
        "first_seen_ssid": dev.first_seen_ssid,
        "last_seen_ssid": dev.last_seen_ssid or dev.first_seen_ssid,
        "ssids_seen": ssids_seen or [],
        "last_seen_at": dev.last_seen_at,
        "note": dev.note,
    }
