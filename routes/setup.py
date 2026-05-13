"""First-run setup wizard.

Linear, multi-step form. Each step collects a slice of configuration, holds
it in session, and the final review step writes everything to .env and sets
SETUP_COMPLETE=true so systemd brings the portal back up in normal mode.

The wizard is reachable in both modes:
- Bootstrap mode (default landing): app.py routes everything here.
- Normal mode (re-config): operator clicks "Re-run setup wizard" in admin UI,
  which flips SETUP_COMPLETE=false and restarts. They come back into this.
"""
from __future__ import annotations

import os
import secrets
import sys
import threading
import time

from flask import (Blueprint, abort, current_app, redirect, render_template,
                   request, session, url_for)

from config import is_setup_complete
from env_writer import read_env, write_env

bp = Blueprint("setup", __name__, url_prefix="/setup")


# Single source of truth for the wizard flow. (key, label, has_test_button)
# The label is shown in the progress bar; the key is the URL slug.
STEPS = [
    ("welcome",        "Welcome",           False),
    ("branding",       "Branding",          False),
    ("storage",        "Storage",           False),
    ("smtp",           "Email",             True),
    ("oauth",          "Google OAuth",      False),
    ("admins",         "Admins",            False),
    ("smartzone",      "SmartZone API",     True),
    ("radius",         "RADIUS",            False),
    ("tls",            "TLS",               True),
    ("smartzone_wlan", "SmartZone WLAN",    False),
    ("review",         "Review & finish",   False),
]


def _step_index(key: str) -> int:
    for i, (k, _, _) in enumerate(STEPS):
        if k == key:
            return i
    return -1


def _step_label(key: str) -> str:
    for k, label, _ in STEPS:
        if k == key:
            return label
    return key


def _next_url(key: str) -> str:
    i = _step_index(key)
    if 0 <= i < len(STEPS) - 1:
        return url_for(f"setup.{STEPS[i + 1][0]}")
    return url_for("setup.welcome")


def _prev_url(key: str) -> str | None:
    i = _step_index(key)
    if i > 0:
        return url_for(f"setup.{STEPS[i - 1][0]}")
    return None


def _wizard_state() -> dict:
    """All collected wizard input lives under one session key so we can clear
    it at the end with `session.pop('wizard', None)`."""
    return session.setdefault("wizard", {})


def _save(key: str, **values) -> None:
    """Save this step's input into session under a stable key."""
    state = _wizard_state()
    state[key] = {k: v for k, v in values.items() if v is not None}
    session.modified = True


def _render(step_key: str, template: str, **ctx) -> str:
    """Common context every step template gets — progress bar info, nav URLs,
    label of the current step."""
    return render_template(
        template,
        step_key=step_key,
        step_label=_step_label(step_key),
        step_index=_step_index(step_key),
        step_total=len(STEPS),
        steps=STEPS,
        next_url=_next_url(step_key),
        prev_url=_prev_url(step_key),
        state=_wizard_state(),
        **ctx,
    )


@bp.before_request
def _gate_wizard():
    """When the portal is in normal mode, only admins can reach /setup/*.
    In bootstrap mode there are no admins yet — the wizard is open by design,
    since access to the box at all is the only admission control."""
    if not is_setup_complete():
        return None  # bootstrap mode: wizard is open
    # Lazy import: oauth/db aren't initialized in bootstrap mode.
    from oauth import current_user, is_admin
    user = current_user()
    if not user or not is_admin(user):
        abort(403)
    return None


# ============================================================================
# Steps
# ============================================================================


@bp.route("/")
@bp.route("/welcome")
def welcome():
    return _render("welcome", "setup_welcome.html")


@bp.route("/reconfigure", methods=["POST"])
def reconfigure():
    """Admin-only entry point from the running portal: seed the wizard session
    from the current .env and redirect to the welcome step. The actual restart
    happens when the operator clicks "Save and restart" on the review step.
    Admin check is handled by the blueprint's before_request hook."""
    current = read_env()
    state: dict[str, dict[str, str]] = {}

    def assign(step: str, *keys: str) -> None:
        bucket = {k: current[k] for k in keys if k in current and current[k]}
        if bucket:
            state[step] = bucket

    assign("branding", "PORTAL_BRAND_NAME", "PORTAL_BASE_URL",
           "PORTAL_SUPPORT_EMAIL", "PORTAL_EMAIL_PLACEHOLDER")
    assign("storage", "DATABASE_URL")
    assign("smtp", "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS",
           "SMTP_FROM_EMAIL", "SMTP_FROM_NAME")
    assign("oauth", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
           "GOOGLE_HOSTED_DOMAIN")
    assign("admins", "ADMIN_EMAILS")
    assign("smartzone", "SZ_HOST", "SZ_PORT", "SZ_API_VERSION",
           "SZ_USERNAME", "SZ_PASSWORD", "SZ_VERIFY_TLS")
    assign("radius", "RADIUS_SHARED_SECRET", "RADIUS_LISTEN_HOST",
           "RADIUS_LISTEN_PORT", "RADIUS_MAC_FORMAT",
           "COA_HOST", "COA_PORT", "COA_SECRET")
    assign("tls", "CLOUDFLARE_API_TOKEN", "TLS_HOSTNAME", "TLS_EMAIL")

    session["wizard"] = state
    session.modified = True
    return redirect(url_for("setup.welcome"))


@bp.route("/branding", methods=["GET", "POST"])
def branding():
    if request.method == "POST":
        _save("branding",
              PORTAL_BRAND_NAME=(request.form.get("brand_name") or "").strip() or "Captive Portal",
              PORTAL_BASE_URL=(request.form.get("base_url") or "").strip().rstrip("/"),
              PORTAL_SUPPORT_EMAIL=(request.form.get("support_email") or "").strip() or None,
              PORTAL_EMAIL_PLACEHOLDER=(request.form.get("email_placeholder") or "").strip() or None)
        return redirect(_next_url("branding"))
    return _render("branding", "setup_branding.html")


@bp.route("/storage", methods=["GET", "POST"])
def storage():
    if request.method == "POST":
        choice = request.form.get("backend") or "sqlite"
        if choice == "sqlite":
            uri = "sqlite:///portal.db"
        else:
            uri = (request.form.get("database_url") or "").strip()
        _save("storage", DATABASE_URL=uri)
        return redirect(_next_url("storage"))
    return _render("storage", "setup_storage.html")


@bp.route("/smtp", methods=["GET", "POST"])
def smtp():
    test_result = None
    if request.method == "POST":
        form = {
            "SMTP_HOST": (request.form.get("smtp_host") or "").strip(),
            "SMTP_PORT": (request.form.get("smtp_port") or "587").strip(),
            "SMTP_USER": (request.form.get("smtp_user") or "").strip() or None,
            "SMTP_PASS": (request.form.get("smtp_pass") or "") or None,
            "SMTP_FROM_EMAIL": (request.form.get("smtp_from_email") or "").strip(),
            "SMTP_FROM_NAME": (request.form.get("smtp_from_name") or "").strip() or None,
        }
        _save("smtp", **form)
        if request.form.get("action") == "test":
            test_result = _test_smtp(form)
            return _render("smtp", "setup_smtp.html", test_result=test_result)
        return redirect(_next_url("smtp"))
    return _render("smtp", "setup_smtp.html", test_result=None)


def _test_smtp(form: dict) -> dict:
    """Try a STARTTLS handshake + (optional) AUTH. Returns {ok, detail}."""
    import smtplib
    host = form["SMTP_HOST"]
    if not host:
        return {"ok": False, "detail": "SMTP host is required."}
    try:
        port = int(form.get("SMTP_PORT") or 587)
    except ValueError:
        return {"ok": False, "detail": "SMTP port must be a number."}
    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            if form.get("SMTP_USER") and form.get("SMTP_PASS"):
                s.login(form["SMTP_USER"], form["SMTP_PASS"])
        return {"ok": True, "detail": f"Connected to {host}:{port} OK"
                + (" (auth succeeded)" if form.get("SMTP_USER") else " (no auth attempted)")}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}


@bp.route("/oauth", methods=["GET", "POST"])
def oauth():
    if request.method == "POST":
        _save("oauth",
              GOOGLE_CLIENT_ID=(request.form.get("client_id") or "").strip(),
              GOOGLE_CLIENT_SECRET=(request.form.get("client_secret") or "").strip(),
              GOOGLE_HOSTED_DOMAIN=(request.form.get("hosted_domain") or "").strip() or None)
        return redirect(_next_url("oauth"))
    # Derive the redirect URI the operator needs to paste into Google Cloud
    # Console from the branding step they've already filled in.
    base = _wizard_state().get("branding", {}).get("PORTAL_BASE_URL", "https://your-host")
    return _render("oauth", "setup_oauth.html", redirect_uri=f"{base}/oauth/callback")


@bp.route("/admins", methods=["GET", "POST"])
def admins():
    if request.method == "POST":
        raw = (request.form.get("admin_emails") or "").strip()
        # Normalize: split on commas + whitespace, lowercase, dedupe-preserve-order.
        seen: list[str] = []
        for part in raw.replace("\n", ",").split(","):
            p = part.strip().lower()
            if p and p not in seen:
                seen.append(p)
        _save("admins", ADMIN_EMAILS=",".join(seen))
        return redirect(_next_url("admins"))
    return _render("admins", "setup_admins.html")


@bp.route("/smartzone", methods=["GET", "POST"])
def smartzone():
    test_result = None
    if request.method == "POST":
        form = {
            "SZ_HOST": (request.form.get("sz_host") or "").strip(),
            "SZ_PORT": (request.form.get("sz_port") or "8443").strip(),
            "SZ_API_VERSION": (request.form.get("sz_api_version") or "v11_1").strip(),
            "SZ_USERNAME": (request.form.get("sz_username") or "").strip(),
            "SZ_PASSWORD": request.form.get("sz_password") or "",
            "SZ_VERIFY_TLS": "true" if request.form.get("sz_verify_tls") else "false",
        }
        _save("smartzone", **form)
        if request.form.get("action") == "test":
            test_result = _test_smartzone(form)
            return _render("smartzone", "setup_smartzone.html", test_result=test_result)
        return redirect(_next_url("smartzone"))
    return _render("smartzone", "setup_smartzone.html", test_result=None)


def _test_smartzone(form: dict) -> dict:
    """Hit /serviceTicket against the SmartZone Public API and report back."""
    import requests
    host = form["SZ_HOST"]
    if not host:
        return {"ok": False, "detail": "SmartZone host is required."}
    try:
        port = int(form.get("SZ_PORT") or 8443)
    except ValueError:
        return {"ok": False, "detail": "Port must be a number."}
    verify = (form.get("SZ_VERIFY_TLS") or "false").lower() == "true"
    url = f"https://{host}:{port}/wsg/api/public/{form['SZ_API_VERSION']}/serviceTicket"
    try:
        r = requests.post(url, json={"username": form["SZ_USERNAME"],
                                     "password": form["SZ_PASSWORD"]},
                          verify=verify, timeout=10)
        if r.status_code == 200 and "serviceTicket" in (r.json() or {}):
            return {"ok": True, "detail": f"Auth OK via {form['SZ_API_VERSION']}"}
        return {"ok": False, "detail": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}


@bp.route("/radius", methods=["GET", "POST"])
def radius():
    if request.method == "POST":
        secret_value = (request.form.get("shared_secret") or "").strip()
        if not secret_value:
            secret_value = secrets.token_urlsafe(32)
        _save("radius",
              RADIUS_SHARED_SECRET=secret_value,
              COA_SECRET=secret_value,  # Ruckus reuses RADIUS secret for CoA by default
              RADIUS_LISTEN_HOST=(request.form.get("listen_host") or "0.0.0.0").strip(),
              RADIUS_LISTEN_PORT=(request.form.get("listen_port") or "1812").strip(),
              RADIUS_MAC_FORMAT=(request.form.get("mac_format") or "lower_no_sep").strip(),
              COA_HOST=(request.form.get("coa_host") or "").strip()
                       or _wizard_state().get("smartzone", {}).get("SZ_HOST", ""),
              COA_PORT=(request.form.get("coa_port") or "3799").strip())
        return redirect(_next_url("radius"))
    # Pre-fill: generate a strong default secret if nothing in session yet.
    state = _wizard_state().get("radius", {})
    suggested_secret = state.get("RADIUS_SHARED_SECRET") or secrets.token_urlsafe(32)
    return _render("radius", "setup_radius.html", suggested_secret=suggested_secret)


@bp.route("/tls", methods=["GET", "POST"])
def tls():
    test_result = None
    if request.method == "POST":
        form = {
            "CLOUDFLARE_API_TOKEN": (request.form.get("cf_token") or "").strip(),
            "TLS_HOSTNAME": (request.form.get("tls_hostname") or "").strip(),
            "TLS_EMAIL": (request.form.get("tls_email") or "").strip(),
        }
        _save("tls", **form)
        if request.form.get("action") == "test":
            test_result = _test_cloudflare(form)
            return _render("tls", "setup_tls.html", test_result=test_result)
        return redirect(_next_url("tls"))
    return _render("tls", "setup_tls.html", test_result=None)


def _test_cloudflare(form: dict) -> dict:
    """Verify the API token by hitting Cloudflare's /user/tokens/verify."""
    import requests
    token = form.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not token:
        return {"ok": False, "detail": "API token is required."}
    try:
        r = requests.get(
            "https://api.cloudflare.com/client/v4/user/tokens/verify",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        data = r.json() if r.headers.get("Content-Type", "").startswith("application/json") else {}
        if r.status_code == 200 and data.get("success"):
            status = (data.get("result") or {}).get("status", "active")
            return {"ok": True, "detail": f"Cloudflare token is {status}."}
        errs = data.get("errors") or [{"message": r.text[:200]}]
        return {"ok": False, "detail": "; ".join(e.get("message", "?") for e in errs)}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}


@bp.route("/smartzone_wlan")
def smartzone_wlan():
    """Display-only checklist. The operator has to do this in SmartZone's UI;
    we just show them the exact values to enter, pre-filled from earlier steps."""
    state = _wizard_state()
    base = state.get("branding", {}).get("PORTAL_BASE_URL", "https://your-host")
    hostname = base.removeprefix("https://").removeprefix("http://").rstrip("/")
    radius_state = state.get("radius", {})
    return _render(
        "smartzone_wlan",
        "setup_smartzone_wlan.html",
        portal_hostname=hostname,
        portal_logon_url=f"{base}/portal",
        radius_secret=radius_state.get("RADIUS_SHARED_SECRET", "(set on RADIUS step)"),
        radius_port=radius_state.get("RADIUS_LISTEN_PORT", "1812"),
        mac_format=radius_state.get("RADIUS_MAC_FORMAT", "lower_no_sep"),
    )


@bp.route("/review", methods=["GET", "POST"])
def review():
    state = _wizard_state()
    flat = _flatten_state(state)
    if request.method == "POST":
        return _finalize(flat)
    return _render("review", "setup_review.html", flat=flat)


def _flatten_state(state: dict) -> dict[str, str]:
    """Collapse {step_key: {ENV: val, ...}, ...} into a flat {ENV: val} dict.
    The TLS step's keys are stripped out — they don't go into .env directly,
    they're consumed by _issue_tls_cert() which writes back TLS_CERT_FILE /
    TLS_KEY_FILE pointing at certbot's output."""
    flat: dict[str, str] = {}
    tls_only = {"CLOUDFLARE_API_TOKEN", "TLS_HOSTNAME", "TLS_EMAIL"}
    for step_data in state.values():
        for k, v in step_data.items():
            if v is None or k in tls_only:
                continue
            flat[k] = str(v)
    return flat


def _issue_tls_cert(state: dict) -> tuple[bool, str, dict[str, str]]:
    """Attempt to issue a Let's Encrypt cert via certbot's Cloudflare DNS-01.

    Returns (ok, message, extra_env). extra_env contains TLS_CERT_FILE and
    TLS_KEY_FILE on success; empty on failure. Failures are non-fatal — the
    wizard still saves .env and restarts, but the operator will need to fix
    TLS by hand. On Windows (no certbot binary, no /etc/letsencrypt) we no-op
    so the wizard remains usable for development."""
    import shutil
    import subprocess

    tls = state.get("tls", {})
    token = tls.get("CLOUDFLARE_API_TOKEN")
    hostname = tls.get("TLS_HOSTNAME")
    email = tls.get("TLS_EMAIL")
    if not (token and hostname and email):
        return False, "Cloudflare credentials missing — skipping cert issuance.", {}

    certbot = shutil.which("certbot")
    if not certbot:
        return False, ("certbot is not installed on this host — the cert wasn't "
                       "issued. On Debian: apt-get install certbot python3-certbot-dns-cloudflare."), {}

    cf_creds = "/etc/letsencrypt/cloudflare.ini"
    try:
        os.makedirs("/etc/letsencrypt", exist_ok=True)
        # 0600 — token has zone DNS-edit perms, treat it like a password.
        fd = os.open(cf_creds, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"dns_cloudflare_api_token = {token}\n")
    except Exception as e:
        return False, f"Couldn't write {cf_creds}: {e}", {}

    cmd = [
        certbot, "certonly", "--non-interactive", "--agree-tos",
        "--dns-cloudflare", "--dns-cloudflare-credentials", cf_creds,
        "--dns-cloudflare-propagation-seconds", "30",
        "-m", email, "-d", hostname,
        # Certbot's default is to fail on existing certs; --keep-until-expiring
        # makes re-runs idempotent (used by the "Re-run wizard" flow).
        "--keep-until-expiring",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except Exception as e:
        return False, f"certbot run failed: {e}", {}
    if proc.returncode != 0:
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-10:]
        return False, "certbot failed:\n" + "\n".join(tail), {}

    cert_dir = f"/etc/letsencrypt/live/{hostname}"
    cert = f"{cert_dir}/fullchain.pem"
    key = f"{cert_dir}/privkey.pem"
    if not (os.path.exists(cert) and os.path.exists(key)):
        return False, f"certbot reported success but cert files at {cert_dir} are missing.", {}
    return True, f"Cert issued for {hostname}.", {"TLS_CERT_FILE": cert, "TLS_KEY_FILE": key}


def _finalize(flat: dict[str, str]):
    """Generate FLASK_SECRET_KEY, issue TLS cert via certbot, write .env, set
    SETUP_COMPLETE=true, then exit so systemd restarts in normal mode."""
    flat.setdefault("FLASK_SECRET_KEY", secrets.token_urlsafe(48))
    flat["SETUP_COMPLETE"] = "true"

    # Cert issuance is best-effort: even if it fails the operator can fix TLS
    # later and the rest of the portal still boots. We surface the result on
    # the finished page.
    cert_ok, cert_msg, cert_env = _issue_tls_cert(_wizard_state())
    flat.update(cert_env)

    try:
        path = write_env(flat)
    except Exception as e:
        return _render("review", "setup_review.html", flat=flat,
                       error=f"Failed to write .env: {e}"), 500

    session.pop("wizard", None)
    threading.Timer(1.0, _exit_for_restart).start()
    return render_template("setup_finished.html",
                           env_path=str(path),
                           cert_ok=cert_ok,
                           cert_msg=cert_msg)


def _exit_for_restart():
    current_app.logger.info("setup wizard: configuration saved, exiting for systemd restart")
    time.sleep(0.5)
    os._exit(0)
