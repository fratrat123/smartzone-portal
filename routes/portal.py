"""Captive portal routes.

SmartZone redirects unauthenticated clients here with their MAC in the query
string. Flow:

  /portal           -> CNA detection, then -> /portal/start
  /portal/start     -> shows 'Sign in with Google'
  /oauth/login      -> kick off OAuth
  /oauth/callback   -> verify hd, store session, -> /portal/register
  /portal/register  -> show MAC + hostname, device-type picker, submit
  /portal/pending   -> 'request submitted, waiting for approval'
"""
import logging
import random
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, redirect, render_template, request, session, url_for
from sqlalchemy import select

from arp import hostname_for_ip, mac_for_ip
from config import config, public_url
from db import Device, EmailVerification, SessionLocal, audit
from device_types import DEVICE_TYPES, DEVICE_TYPES_BY_KEY, infer_device_type
from email_sender import send_verification_email
from macfmt import canonical, display_colon
from notifications import notify_new_pending
from oauth import (allowed_email_domains, current_user, domain_allowed,
                   is_admin, oauth, verify_workspace)
import rate_limit
from smartzone import sz_client


# Rate limits for /portal/email/send. Tuned for the captive portal flow:
# a real user might typo once and retry, but shouldn't need many sends.
#   per-IP:    5 sends / minute  — stops a single attacker on the SSID
#   per-email: 5 sends / hour    — stops spamming a target inbox
_RL_SEND_IP_LIMIT = 5
_RL_SEND_IP_WINDOW = 60
_RL_SEND_DEST_LIMIT = 5
_RL_SEND_DEST_WINDOW = 3600

log = logging.getLogger(__name__)

bp = Blueprint("portal", __name__)


def _as_utc(dt: datetime) -> datetime:
    """SQLite drops tzinfo on round-trip; re-attach UTC so comparisons with
    timezone-aware 'now' don't crash with TypeError."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

# SmartZone WISPr redirect *may* pass the client MAC as one of these — but in
# practice on SZ 6.1.1 the plaintext `mac=` field is the AP MAC and `client_mac`
# is encrypted (ENC...). We therefore prefer ARP lookup of the client's source
# IP and only fall back to URL params if ARP fails.
_MAC_PARAMS = ("uemac",)  # rarely populated; included for completeness
_CNA_UA = re.compile(r"CaptiveNetworkSupport", re.I)


def _derive_client_mac() -> str | None:
    """Determine the actual client MAC. ARP first, URL params as fallback."""
    # ARP lookup of the client's source IP — most reliable.
    client_ip = request.remote_addr
    if client_ip:
        mac = mac_for_ip(client_ip)
        if mac:
            try:
                resolved = canonical(mac)
                log.info("portal: resolved client MAC via ARP: ip=%s mac=%s",
                         client_ip, resolved)
                return resolved
            except ValueError:
                pass
        else:
            log.warning("portal: ARP lookup failed for client ip=%s", client_ip)

    # Fallback: try URL params, skipping any "ENC..." encrypted values.
    for key in _MAC_PARAMS:
        v = request.args.get(key)
        if v and not v.upper().startswith("ENC"):
            try:
                return canonical(v)
            except ValueError:
                pass
    return None


@bp.route("/portal")
def landing():
    # Always re-derive on entry so stale session state from a prior client
    # can't make us reuse the wrong MAC.
    mac = _derive_client_mac()
    if mac:
        session["pending_mac"] = mac

        url_ap_mac = request.args.get("mac")
        client_ip = request.remote_addr

        # Reverse-DNS lookup the client's IP — Windows clients with AD dynamic
        # DNS registration get a PTR record we can use as a hostname.
        dns_hostname = hostname_for_ip(client_ip) if client_ip else None

        with SessionLocal() as s:
            dev = s.get(Device, mac)
            if dev:
                # SmartZone's portal redirect URL has `mac=` which is the AP's
                # *base MAC* (not the client's). Overwrite whatever RADIUS stored
                # (which is a BSSID and SmartZone's APIs reject it).
                if url_ap_mac:
                    try:
                        ap_canonical = canonical(url_ap_mac)
                        if dev.first_seen_ap_mac != ap_canonical:
                            dev.first_seen_ap_mac = ap_canonical
                            log.info("portal: stored AP MAC for %s: %s", mac, ap_canonical)
                    except ValueError:
                        pass
                # Best-effort hostname enrichment. Only fill in if empty so we
                # don't clobber what SmartZone's profiling told us.
                if not dev.hostname and dns_hostname:
                    dev.hostname = dns_hostname
                    log.info("portal: filled hostname for %s from DNS: %s", mac, dns_hostname)
                s.commit()

    if _CNA_UA.search(request.headers.get("User-Agent", "")):
        return render_template("portal_cna.html")
    return redirect(url_for("portal.start"))


@bp.route("/portal/start")
def start():
    mac = session.get("pending_mac")
    if not mac:
        return render_template("portal_no_mac.html"), 400
    # If the admin already denied this device, render the login page with
    # the denial state pre-loaded. The page's polling script catches
    # denials that happen while the user is mid-entry too — this just
    # avoids showing the email form for a moment before polling kicks in.
    denied_note = None
    with SessionLocal() as s:
        dev = s.get(Device, mac)
    if dev and dev.status == "denied":
        denied_note = dev.note or None
    return render_template("portal_login.html", denied_note=denied_note,
                           denied=bool(dev and dev.status == "denied"))


@bp.route("/oauth/login")
def oauth_login():
    # Build redirect_uri from the *current request* (not config.PORTAL_BASE_URL)
    # so it works whether the operator hit us via:
    #   - https://portal.hillmanschools.com/   (TLS, after cert is issued)
    #   - http://portal.hillmanschools.com/    (plain HTTP, while no cert)
    #   - http://localhost/                     (dev / direct)
    # Each of those needs its own redirect_uri matching what's in Google's
    # authorized list for the OAuth client. ProxyFix has already mapped any
    # X-Forwarded-Proto so url_for picks the right scheme.
    redirect_uri = url_for("portal.oauth_callback", _external=True)
    # `hd=` is a login-screen hint — only useful when exactly one domain is
    # allowed. With multiple or none, we omit it and let Google show any
    # account; verify_workspace() catches the wrong domain server-side.
    domains = allowed_email_domains()
    hd_hint = {"hd": domains[0]} if len(domains) == 1 else {}
    return oauth.google.authorize_redirect(redirect_uri, **hd_hint)


@bp.route("/oauth/callback")
def oauth_callback():
    token = oauth.google.authorize_access_token()
    claims = token.get("userinfo") or oauth.google.parse_id_token(token, nonce=None)
    if not verify_workspace(claims):
        abort(403, "Account not in the allowed Workspace domain")

    session["user"] = {
        "sub": claims["sub"],
        "email": claims["email"].lower(),
        "name": claims.get("name"),
        "picture": claims.get("picture"),
    }
    if session.get("pending_mac"):
        return redirect(url_for("portal.register"))
    return redirect(url_for("admin.queue"))


@bp.route("/oauth/logout")
def oauth_logout():
    # Two distinct flows hit this route:
    #   - Admin "Sign out" from the topbar → wants a real logout
    #   - Portal user "switch account" → wants to keep the device's MAC in
    #     session so they can sign in with a different email for the same device
    # Distinguish by admin status of the currently-signed-in user.
    user = current_user()
    is_an_admin = bool(user) and is_admin(user)
    mac = None if is_an_admin else session.get("pending_mac")
    session.clear()
    if mac:
        session["pending_mac"] = mac
        return redirect(url_for("portal.start"))
    return render_template("signed_out.html")


# ---------------------------------------------------------------------------
# Email magic-link / verification code flow
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _email_allowed(email: str) -> bool:
    if not _EMAIL_RE.match(email):
        return False
    return domain_allowed(email)


@bp.route("/portal/email/send", methods=["POST"])
def email_send():
    """User submits their email on the login page. Generate a code/token, send email."""
    mac = session.get("pending_mac")
    if not mac:
        return render_template("portal_no_mac.html"), 400

    email = (request.form.get("email") or "").strip().lower()
    if not _email_allowed(email):
        domains = allowed_email_domains()
        if len(domains) == 1:
            hint = f"a @{domains[0]}"
        elif domains:
            hint = "an allowed (@" + ", @".join(domains) + ")"
        else:
            hint = "a valid"
        return render_template(
            "portal_login.html",
            error=f"Please use {hint} email address.",
            prefill_email=email,
        )

    # Rate limit. Two scopes:
    #   per source IP — stops one bad actor from spamming many addresses
    #   per destination — stops one bad actor from spamming one address
    # We always show the same 'check your email' UX whether or not we
    # actually sent, so we don't leak whether an address is real / rate-limited.
    client_ip = request.remote_addr or ""
    rate_limit.gc()
    ip_ok = rate_limit.check("email-send-ip", client_ip,
                             limit=_RL_SEND_IP_LIMIT,
                             window_seconds=_RL_SEND_IP_WINDOW)
    dest_ok = rate_limit.check("email-send-dest", email,
                               limit=_RL_SEND_DEST_LIMIT,
                               window_seconds=_RL_SEND_DEST_WINDOW)
    if not (ip_ok and dest_ok):
        log.warning("portal: email send rate-limited (ip=%s dest=%s ip_ok=%s dest_ok=%s)",
                    client_ip, email, ip_ok, dest_ok)
        return render_template(
            "portal_login.html",
            error="Too many requests just now. Please wait a minute and try again.",
            prefill_email=email,
        )

    now = datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)
    code = f"{random.randint(0, 999999):06d}"
    ttl = timedelta(minutes=config.EMAIL_VERIFY_TTL_MINUTES)

    with SessionLocal() as s:
        ev = EmailVerification(
            token=token,
            code=code,
            email=email,
            mac=mac,
            created_at=now,
            expires_at=now + ttl,
        )
        s.add(ev)
        s.commit()
        ev_id = ev.id

    session["ev_id"] = ev_id

    verify_url = public_url(url_for("portal.email_verify_link", token=token))
    sent = send_verification_email(email, code, verify_url)
    if not sent:
        return render_template(
            "portal_login.html",
            error="Couldn't send the verification email. Contact IT.",
            prefill_email=email,
        )

    return redirect(url_for("portal.email_wait"))


@bp.route("/portal/email/wait", methods=["GET", "POST"])
def email_wait():
    """The 'check your email' page. Shows the code entry form, polls for link-click verification."""
    ev_id = session.get("ev_id")
    if not ev_id:
        return redirect(url_for("portal.start"))

    error = None
    if request.method == "POST":
        entered = re.sub(r"\D", "", request.form.get("code") or "")[:6]
        if len(entered) != 6:
            error = "Enter the 6-digit code from the email."
        else:
            ok, msg = _try_verify_with_code(ev_id, entered)
            if ok:
                return redirect(url_for("portal.register"))
            error = msg

    with SessionLocal() as s:
        ev = s.get(EmailVerification, ev_id)
        if not ev:
            session.pop("ev_id", None)
            return redirect(url_for("portal.start"))
        email = ev.email
        expires_at = ev.expires_at

    return render_template(
        "portal_email_wait.html",
        email=email,
        error=error,
        expires_at=expires_at,
    )


@bp.route("/portal/email/admin-assist", methods=["POST"])
def email_admin_assist():
    """User can't get to their email (iOS CNA popup closes on app-switch,
    email is delayed, whatever) — let them punt to a human. This creates the
    device row in the pending queue with the email they typed and fires the
    same admin notification as a normal registration, without ever verifying
    the email. Admin decides in-person whether to approve.

    No visible "email not verified" flag on the queue row — the admin is the
    gatekeeper here and is expected to know who they're approving. The audit
    trail records the bypass separately (action=admin_assist_request)."""
    ev_id = session.get("ev_id")
    mac = session.get("pending_mac")
    if not ev_id or not mac:
        return redirect(url_for("portal.start"))

    with SessionLocal() as s:
        ev = s.get(EmailVerification, ev_id)
        if not ev:
            session.pop("ev_id", None)
            return redirect(url_for("portal.start"))
        email = ev.email
        now = datetime.now(timezone.utc)

        # Same effect as a completed portal.register submission: attach the
        # email to the device row and re-open its pending state so the queue
        # picks it up. Device type / friendly name are left blank — admin can
        # fill those in from the detail page after approving.
        dev = s.get(Device, mac)
        if not dev:
            dev = Device(mac=mac, status="pending")
            s.add(dev)
        elif dev.status in ("denied", "expired"):
            dev.status = "pending"
            dev.decided_by_email = None
            dev.decided_at = None
            dev.approved_until = None
        # Don't touch approved / ignored — approved doesn't need re-queuing,
        # ignored is intentional silence and shouldn't bubble back up.
        if dev.status not in ("approved", "ignored"):
            dev.requested_by_email = email
            dev.requested_by_sub = f"email:{email}"
            dev.requested_at = now
            if not dev.hostname:
                try:
                    dev.hostname = sz_client.get_hostname(mac)
                except Exception:
                    pass

        # Mark the EmailVerification as consumed so the polling loop / code
        # entry stop showing it as pending; store a signal so the audit is
        # accurate but the queue UI stays clean.
        ev.verified_at = now
        audit(s, "admin_assist_request", mac=mac,
              actor=email,
              details="user requested admin-assist bypass of email verification")
        s.commit()

        # Snapshot for the notification outside the session
        friendly = dev.friendly_name
        hostname = dev.hostname
        device_type = dev.device_type
        last_ssid = dev.last_seen_ssid or dev.first_seen_ssid
        current_status = dev.status

    # Sign the user in via session so /portal/pending shows the right state.
    session["user"] = {
        "email": email,
        "sub": f"email:{email}",
        "name": email.split("@", 1)[0],
        "verified_via": "admin_assist",
    }

    # Only notify if the device actually landed in pending. If it was already
    # approved / ignored, there's nothing for admins to act on.
    if current_status == "pending":
        notify_new_pending(
            mac=mac,
            mac_display=display_colon(mac),
            requested_by_email=email,
            friendly_name=friendly,
            hostname=hostname,
            device_type=(DEVICE_TYPES_BY_KEY.get(device_type, {}).get("label", device_type)
                         if device_type else None),
            ssid=last_ssid,
        )

    return redirect(url_for("portal.pending"))


@bp.route("/portal/email/status")
def email_status():
    """JSON poll endpoint — has the email been verified (e.g. by clicking the link)?"""
    ev_id = session.get("ev_id")
    if not ev_id:
        return {"status": "no_request"}, 400
    with SessionLocal() as s:
        ev = s.get(EmailVerification, ev_id)
        if not ev:
            return {"status": "no_request"}, 404
        verified_at = ev.verified_at
        expires_at = ev.expires_at
        email = ev.email

    if verified_at:
        # The link was clicked or the code accepted — populate the user session
        # so /portal/register treats them as authenticated.
        session["user"] = {
            "email": email,
            "sub": f"email:{email}",
            "name": email.split("@", 1)[0],
            "verified_via": "magic_link",
        }
        return {"status": "verified"}
    if _as_utc(expires_at) < datetime.now(timezone.utc):
        return {"status": "expired"}
    return {"status": "pending"}


@bp.route("/portal/email/verify")
def email_verify_link():
    """User clicked the link in their email. Marks the verification as good.

    Note this can be opened in any browser context — same tab, new tab, even a
    different device. We mark verified_at on the row; the original device's
    /portal/email/wait page polls /portal/email/status and proceeds when it
    sees verified.
    """
    token = request.args.get("token", "")
    if not token:
        return render_template("portal_email_link_done.html",
                               ok=False, message="Missing token."), 400
    now = datetime.now(timezone.utc)
    with SessionLocal() as s:
        ev = s.scalars(
            select(EmailVerification).where(EmailVerification.token == token)
        ).first()
        if not ev:
            return render_template("portal_email_link_done.html",
                                   ok=False, message="Link not found. It may have already been used."), 404
        if _as_utc(ev.expires_at) < now:
            return render_template("portal_email_link_done.html",
                                   ok=False, message="This link has expired. Request a new one."), 400
        if not ev.verified_at:
            ev.verified_at = now
            s.commit()

    return render_template("portal_email_link_done.html",
                           ok=True,
                           message="You're verified! Return to the sign-in page on your device — it will continue automatically.")


def _try_verify_with_code(ev_id: int, code: str) -> tuple[bool, str | None]:
    """Verify by user-typed code. Returns (success, error_message_if_fail)."""
    now = datetime.now(timezone.utc)
    email = None
    with SessionLocal() as s:
        ev = s.get(EmailVerification, ev_id)
        if not ev:
            return False, "Request not found. Start over."
        if ev.verified_at:
            # Already verified (probably via link). Capture identity, sign in.
            email = ev.email
        else:
            if _as_utc(ev.expires_at) < now:
                return False, "This code has expired. Start over."
            if ev.attempts >= 5:
                return False, "Too many wrong attempts. Start over."
            ev.attempts += 1
            if ev.code != code:
                s.commit()
                return False, f"Wrong code. {5 - ev.attempts} attempts left."
            ev.verified_at = now
            email = ev.email
            s.commit()

    session["user"] = {
        "email": email,
        "sub": f"email:{email}",
        "name": email.split("@", 1)[0],
        "verified_via": "magic_link",
    }
    return True, None


@bp.route("/portal/register", methods=["GET", "POST"])
def register():
    user = current_user()
    if not user:
        return redirect(url_for("portal.start"))
    mac = session.get("pending_mac")
    if not mac:
        return render_template("portal_no_mac.html"), 400

    with SessionLocal() as s:
        dev = s.get(Device, mac)
        if dev and dev.status == "approved":
            return render_template("portal_already_approved.html", mac=display_colon(mac))

        if request.method == "POST":
            device_type = request.form.get("device_type", "other")
            friendly_name = (request.form.get("friendly_name") or "").strip()[:128] or None
            if device_type not in DEVICE_TYPES_BY_KEY:
                device_type = "other"

            if not dev:
                dev = Device(mac=mac, status="pending")
                s.add(dev)
            elif dev.status in ("denied", "expired"):
                # Allow user to re-request after a denial or expiration — back into the queue.
                dev.status = "pending"
                dev.decided_by_email = None
                dev.decided_at = None
                dev.approved_until = None
            # If status is 'ignored', we silently keep it ignored so spam re-requests
            # don't bubble back up to the admin queue.
            dev.device_type = device_type
            dev.friendly_name = friendly_name
            dev.requested_by_email = user["email"]
            dev.requested_by_sub = user["sub"]
            dev.requested_at = datetime.now(timezone.utc)
            if not dev.hostname:
                dev.hostname = sz_client.get_hostname(mac)
            audit(s, "request", mac=mac, actor=user["email"],
                  details=f"type={device_type} name={friendly_name or ''}")
            s.commit()
            # Ping admins now that we have a real user attached to this MAC
            notify_new_pending(
                mac=mac,
                mac_display=display_colon(mac),
                requested_by_email=user["email"],
                friendly_name=friendly_name,
                hostname=dev.hostname,
                device_type=DEVICE_TYPES_BY_KEY.get(device_type, {}).get("label", device_type),
                ssid=dev.last_seen_ssid or dev.first_seen_ssid,
            )
            return redirect(url_for("portal.pending"))

        # GET — first render. Make sure hostname has been attempted.
        hostname = (dev.hostname if dev else None) or sz_client.get_hostname(mac)
        if dev and not dev.hostname and hostname:
            dev.hostname = hostname
            s.commit()

    inferred_type = infer_device_type(request.headers.get("User-Agent"))
    # If we already have a device_type stored from a previous submission, prefer that.
    pre_selected = (dev.device_type if dev and dev.device_type else inferred_type)

    return render_template(
        "portal_register.html",
        mac_display=display_colon(mac),
        hostname=hostname,
        user=user,
        device_types=DEVICE_TYPES,
        pre_selected_type=pre_selected,
    )


@bp.route("/me")
def my_devices():
    """Self-service: a user sees the devices they've registered."""
    user = current_user()
    if not user:
        # Send them through the magic-link flow, then return here.
        session["post_login_next"] = "/me"
        return redirect(url_for("portal.start"))

    with SessionLocal() as s:
        rows = s.scalars(
            select(Device)
            .where(Device.requested_by_email == user["email"])
            .order_by(Device.requested_at.desc().nullslast())
        ).all()
        devices = [{
            "mac": d.mac,
            "mac_display": display_colon(d.mac),
            "status": d.status,
            "hostname": d.hostname,
            "friendly_name": d.friendly_name,
            "device_type": (DEVICE_TYPES_BY_KEY.get(d.device_type) or {}).get("label", d.device_type or "—"),
            "requested_at": d.requested_at,
            "decided_at": d.decided_at,
            "approved_until": d.approved_until,
            "last_seen_at": d.last_seen_at,
        } for d in rows]
    return render_template("portal_my_devices.html", user=user, devices=devices)


@bp.route("/me/remove/<mac>", methods=["POST"])
def my_devices_remove(mac):
    """A user removes one of their own devices. We mark it denied so it can't
    rejoin via MAC auth, and CoA-kick if currently associated."""
    user = current_user()
    if not user:
        abort(403)
    try:
        mac = canonical(mac)
    except ValueError:
        abort(400)

    with SessionLocal() as s:
        dev = s.get(Device, mac)
        if not dev:
            abort(404)
        # A user can only remove their own devices.
        if (dev.requested_by_email or "").lower() != user["email"].lower():
            abort(403)
        ap_mac = dev.first_seen_ap_mac
        dev.status = "denied"
        dev.decided_by_email = user["email"]
        dev.decided_at = datetime.now(timezone.utc)
        dev.approved_until = None
        audit(s, "self_remove", mac=mac, actor=user["email"])
        s.commit()

    # Best-effort kick. If they're not connected this just no-ops.
    try:
        sz_client.disconnect_client(mac, ap_mac)
    except Exception:
        pass

    return redirect(url_for("portal.my_devices"))


@bp.route("/portal/pending")
def pending():
    mac = session.get("pending_mac")
    if not mac:
        return render_template("portal_no_mac.html"), 400
    with SessionLocal() as s:
        dev = s.get(Device, mac)
    if dev and dev.status == "approved":
        return render_template("portal_already_approved.html", mac=display_colon(mac))
    return render_template("portal_pending.html", mac=display_colon(mac), device=dev)


@bp.route("/portal/pending/status")
def pending_status():
    """JSON endpoint for the portal pages to poll. Returns current status plus
    the admin's note (so the user sees the reason on denial). The login page
    polls this too, so a denial that happens while someone is still on the
    email-entry screen surfaces immediately instead of waiting for them to
    submit and reach the pending page."""
    mac = session.get("pending_mac")
    if not mac:
        return {"status": "unknown"}, 400
    with SessionLocal() as s:
        dev = s.get(Device, mac)
    return {
        "status": dev.status if dev else "unknown",
        "mac": display_colon(mac),
        "note": (dev.note if dev else None) or "",
    }
