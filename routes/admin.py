"""Admin routes — approve/deny pending devices, browse history."""
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Blueprint, abort, redirect, render_template, request, url_for
from sqlalchemy import func, select

from coa import disconnect as coa_disconnect
from config import config
from db import Admin, AuditLog, Device, SessionLocal, audit
from device_types import DEVICE_TYPES_BY_KEY
from macfmt import display_colon
from oauth import current_user, is_admin, is_bootstrap_admin
from smartzone import sz_client

bp = Blueprint("admin", __name__, url_prefix="/admin")


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
    with SessionLocal() as s:
        pending = s.scalars(
            select(Device).where(Device.status == "pending").order_by(Device.requested_at.desc().nullslast())
        ).all()
        recent = s.scalars(
            select(Device).where(Device.status.in_(("approved", "denied", "expired")))
            .order_by(Device.decided_at.desc().nullslast()).limit(50)
        ).all()
        ignored = []
        if show_ignored:
            ignored = s.scalars(
                select(Device).where(Device.status == "ignored")
                .order_by(Device.decided_at.desc().nullslast()).limit(100)
            ).all()
        ignored_count = s.scalar(
            select(func.count()).select_from(Device).where(Device.status == "ignored")
        ) or 0
    return render_template(
        "admin_queue.html",
        pending=[_view(d) for d in pending],
        recent=[_view(d) for d in recent],
        ignored=[_view(d) for d in ignored],
        ignored_count=int(ignored_count),
        show_ignored=show_ignored,
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
    with SessionLocal() as s:
        dev = s.get(Device, mac)
        if not dev:
            abort(404)

        if request.method == "POST":
            action = request.form.get("action")
            note = (request.form.get("note") or "").strip()[:1000] or None
            actor = current_user()["email"]

            if action in ("approve", "deny", "ignore", "reset"):
                now = datetime.now(timezone.utc)
                if action == "approve":
                    # Duration in seconds; 0 = forever
                    try:
                        duration = int(request.form.get("duration", "86400"))
                    except ValueError:
                        duration = 86400  # 1 day default
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
                s.commit()

                # Kick the client so the new status takes effect on reassociation.
                # Approve  -> rejoin silently via MAC auth Accept
                # Deny     -> rejoin attempt is rejected, stays off the network
                # Reset    -> falls back to captive portal (pending again)
                #
                # Try SmartZone Public API first (most reliable on Ruckus).
                # If it fails (e.g. no AP MAC yet, or API error), fall back to
                # RFC 5176 CoA-Disconnect over RADIUS.
                ap_mac = dev.first_seen_ap_mac
                kicked = sz_client.disconnect_client(mac, ap_mac)
                method = "sz_api"
                if not kicked:
                    kicked = coa_disconnect(mac)
                    method = "coa_radius"
                with SessionLocal() as s2:
                    audit(s2, "kick_sent", mac=mac, actor=actor,
                          details=f"method={method} ok={kicked} ap_mac={ap_mac}")
                    s2.commit()

                if action == "reset":
                    return redirect(url_for("admin.device", mac=mac))
                return redirect(url_for("admin.queue"))

            abort(400)

        history = s.scalars(
            select(AuditLog).where(AuditLog.mac == mac).order_by(AuditLog.ts.desc()).limit(50)
        ).all()

    return render_template("admin_device.html", d=_view(dev), history=history)


@bp.route("/admins", methods=["GET", "POST"])
@admin_required
def admins():
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
            elif config.GOOGLE_HOSTED_DOMAIN and not email.endswith("@" + config.GOOGLE_HOSTED_DOMAIN.lower()):
                error = f"Email must be in @{config.GOOGLE_HOSTED_DOMAIN}."
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

        if not error:
            return redirect(url_for("admin.admins"))

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

    bootstrap = sorted(config.ADMIN_EMAILS)
    return render_template(
        "admin_admins.html",
        bootstrap_admins=bootstrap,
        db_admins=db_admins_view,
        domain=config.GOOGLE_HOSTED_DOMAIN,
        user=current_user(),
        error=error,
    )


def _view(dev: Device) -> dict:
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
        "last_seen_at": dev.last_seen_at,
        "note": dev.note,
    }
