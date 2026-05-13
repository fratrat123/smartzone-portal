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
    ("network",        "Network",           False),
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


@bp.route("/network", methods=["GET", "POST"])
def network():
    if request.method == "POST":
        _save("network",
              NET_IP_CIDR=(request.form.get("ip_cidr") or "").strip(),
              NET_GATEWAY=(request.form.get("gateway") or "").strip(),
              NET_DNS=(request.form.get("dns") or "").strip(),
              NET_HOSTNAME=(request.form.get("hostname") or "").strip() or "portal")
        return redirect(_next_url("network"))

    state = _wizard_state().get("network", {})
    # Pre-fill: previous wizard answer wins; otherwise show the box's current
    # config so an operator hitting "Continue" without edits keeps the same
    # network. Helpful for re-runs.
    detected = _detect_current_network()
    return _render("network", "setup_network.html",
                   suggested_ip=state.get("NET_IP_CIDR") or detected.get("ip_cidr", "192.168.254.254/24"),
                   suggested_gateway=state.get("NET_GATEWAY") or detected.get("gateway", ""),
                   suggested_dns=state.get("NET_DNS") or detected.get("dns", "1.1.1.1 1.0.0.1"),
                   suggested_hostname=state.get("NET_HOSTNAME") or detected.get("hostname", "portal"))


def _detect_current_network() -> dict:
    """Best-effort: read the current IP/gateway/DNS so the wizard can pre-fill.
    Returns an empty dict if anything goes wrong (e.g. Windows dev)."""
    import socket
    out: dict[str, str] = {}
    try:
        out["hostname"] = socket.gethostname()
    except Exception:
        pass
    # Primary IP via the "connect to a remote, read local socket" trick. No
    # packets are actually sent because we use a UDP socket with no sendto.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("1.1.1.1", 1))
        ip = s.getsockname()[0]
        s.close()
        out["ip_cidr"] = f"{ip}/24"
    except Exception:
        pass
    return out


@bp.route("/review", methods=["GET", "POST"])
def review():
    state = _wizard_state()
    flat = _flatten_state(state)
    if request.method == "POST":
        return _finalize(flat)
    return _render("review", "setup_review.html", flat=flat)


def _flatten_state(state: dict) -> dict[str, str]:
    """Collapse {step_key: {ENV: val, ...}, ...} into a flat {ENV: val} dict.
    Strips out keys that don't belong in .env: TLS-step credentials (consumed
    by _issue_tls_cert), and NET_ values (consumed by _apply_network)."""
    flat: dict[str, str] = {}
    transient = {
        "CLOUDFLARE_API_TOKEN", "TLS_HOSTNAME", "TLS_EMAIL",
        "NET_IP_CIDR", "NET_GATEWAY", "NET_DNS", "NET_HOSTNAME",
    }
    for step_data in state.values():
        for k, v in step_data.items():
            if v is None or k in transient:
                continue
            flat[k] = str(v)
    return flat


def _apply_network(state: dict) -> tuple[bool, str]:
    """Write netplan YAML + apply it + set hostname.

    Returns (ok, message). Failure is non-fatal — the wizard still saves .env
    and restarts, but the message lands on the finished page so the operator
    can see what happened.

    The captive-portal user has scoped sudo NOPASSWD rules for `netplan
    apply`, `hostnamectl set-hostname`, and `systemctl restart
    systemd-networkd` — see deploy/install.sh.
    """
    import shutil
    import subprocess

    net = state.get("network", {})
    ip_cidr = net.get("NET_IP_CIDR")
    gateway = net.get("NET_GATEWAY")
    dns = net.get("NET_DNS") or ""
    hostname = net.get("NET_HOSTNAME") or "portal"
    if not (ip_cidr and gateway):
        return False, "Network values missing — skipping network change."

    netplan = shutil.which("netplan")
    if not netplan:
        return False, "netplan not installed — network change skipped (Windows dev?)."

    # We rewrite a single, dedicated netplan file so we don't fight with
    # whatever else might be in /etc/netplan. The interface name is detected
    # automatically (`eth0` on most Debian VMs, `ens18` on Proxmox, etc.).
    iface = _detect_primary_iface() or "eth0"
    dns_list = [d for d in dns.split() if d]
    yaml = (
        "# Managed by the captive portal setup wizard.\n"
        "network:\n"
        "  version: 2\n"
        "  renderer: networkd\n"
        "  ethernets:\n"
        f"    {iface}:\n"
        f"      addresses: [{ip_cidr}]\n"
        "      routes:\n"
        f"        - to: default\n"
        f"          via: {gateway}\n"
    )
    if dns_list:
        yaml += "      nameservers:\n        addresses: [" + ", ".join(dns_list) + "]\n"

    cfg_path = "/etc/netplan/01-captive-portal.yaml"
    try:
        # 0600 — netplan requires this since 0.106+ (warning otherwise).
        fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(yaml)
    except Exception as e:
        return False, f"Couldn't write {cfg_path}: {e}"

    def _run(cmd: list[str]) -> tuple[int, str]:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return p.returncode, (p.stdout + p.stderr).strip()
        except Exception as e:
            return -1, f"{type(e).__name__}: {e}"

    rc, out = _run(["sudo", "-n", "/usr/sbin/netplan", "apply"])
    if rc != 0:
        return False, f"netplan apply failed: {out[-300:]}"

    rc, out = _run(["sudo", "-n", "/usr/bin/hostnamectl", "set-hostname", hostname])
    if rc != 0:
        # Hostname is cosmetic — log but don't fail the whole network change.
        current_app.logger.warning("hostnamectl set-hostname failed: %s", out)

    return True, f"Network set to {ip_cidr} (gateway {gateway}); hostname {hostname}."


def _detect_primary_iface() -> str | None:
    """Read /sys/class/net to find the first non-loopback interface."""
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name == "lo":
                continue
            # Skip virtual/down interfaces if possible.
            try:
                with open(f"/sys/class/net/{name}/operstate") as f:
                    state = f.read().strip()
                if state in ("up", "unknown"):  # 'unknown' is normal for some
                    return name
            except OSError:
                continue
    except OSError:
        return None
    return None


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
    """Save everything and trigger a restart at the new IP.

    Order matters:
      1. Issue TLS cert (still on the setup IP, but only if internet works
         from it — best-effort).
      2. Write .env.
      3. Render the finished page so the browser receives it BEFORE we change
         the network and lose the connection.
      4. After the response goes out: apply netplan (browser dies), exit so
         systemd restarts the portal in normal mode at the new IP.
    """
    flat.setdefault("FLASK_SECRET_KEY", secrets.token_urlsafe(48))
    flat["SETUP_COMPLETE"] = "true"

    cert_ok, cert_msg, cert_env = _issue_tls_cert(_wizard_state())
    flat.update(cert_env)

    try:
        path = write_env(flat)
    except Exception as e:
        return _render("review", "setup_review.html", flat=flat,
                       error=f"Failed to write .env: {e}"), 500

    state_snapshot = dict(_wizard_state())  # for the background thread
    session.pop("wizard", None)

    new_ip = state_snapshot.get("network", {}).get("NET_IP_CIDR", "").split("/")[0]
    new_hostname = state_snapshot.get("network", {}).get("NET_HOSTNAME", "portal")
    base_url = flat.get("PORTAL_BASE_URL", "")

    def _after_response():
        # Tiny delay so the HTTP response definitely makes it out the door.
        time.sleep(1.5)
        try:
            _apply_network(state_snapshot)
        except Exception:
            current_app.logger.exception("network apply crashed")
        # systemd Restart=always brings us back in normal mode.
        os._exit(0)

    threading.Thread(target=_after_response, name="finalize", daemon=True).start()

    return render_template("setup_finished.html",
                           env_path=str(path),
                           cert_ok=cert_ok,
                           cert_msg=cert_msg,
                           new_ip=new_ip,
                           new_hostname=new_hostname,
                           base_url=base_url)


