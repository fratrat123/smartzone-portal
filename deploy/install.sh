#!/usr/bin/env bash
# Captive portal installer for Debian 12 (Bookworm).
#
# Idempotent: re-running upgrades the venv and refreshes the systemd unit
# without touching the operator's .env. Run as root.
#
# Usage:
#   curl -fsSL https://your-host/install.sh | sudo bash
#   # or
#   sudo bash deploy/install.sh
set -euo pipefail

APP_USER="captive-portal"
APP_DIR="/opt/captive-portal"
LOG_DIR="/var/log/captive-portal"
SERVICE_FILE="/etc/systemd/system/captive-portal.service"
PYTHON_BIN="/usr/bin/python3"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m!! %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run as root (sudo)."

log "Installing system packages"
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    certbot python3-certbot-dns-cloudflare \
    libcap2-bin \
    netplan.io \
    git ca-certificates curl

# Some Debian package mirrors have shipped 0-byte python3.13 binaries in the
# past; verify the interpreter actually works before continuing. Re-install
# the *minimal* package (which actually owns /usr/bin/python3.13) if needed.
if ! python3 -c 'print("ok")' >/dev/null 2>&1; then
    warn "python3 produced no output — reinstalling python3.13-minimal"
    apt-get install --reinstall -y python3.13-minimal \
        || apt-get install --reinstall -y python3-minimal
    python3 -c 'print("ok")' >/dev/null 2>&1 || fail "python3 still broken after reinstall — check disk space and package mirrors"
fi

log "Creating service user '${APP_USER}'"
if ! id "${APP_USER}" &>/dev/null; then
    useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin "${APP_USER}"
fi

log "Preparing directories"
install -d -o "${APP_USER}" -g "${APP_USER}" -m 0750 "${APP_DIR}"
install -d -o "${APP_USER}" -g "${APP_USER}" -m 0750 "${LOG_DIR}"

# The repo content is assumed to already be at ${APP_DIR}. Either you cloned
# it there before running this script, or the bash one-liner did. If not,
# bail with a clear message.
if [[ ! -f "${APP_DIR}/app.py" ]]; then
    fail "Couldn't find the portal source at ${APP_DIR}. Clone the repo there first:
  sudo git clone <repo-url> ${APP_DIR}
  sudo chown -R ${APP_USER}:${APP_USER} ${APP_DIR}"
fi

log "Creating / refreshing Python venv"
sudo -u "${APP_USER}" "${PYTHON_BIN}" -m venv "${APP_DIR}/.venv"
# Invoke pip via `python -m pip` instead of the pip wrapper script: the wrapper
# uses a shebang line, and if anything goes wrong with the python3 symlink
# chain inside the venv, the kernel silently falls back to /bin/sh and parses
# Python as shell. `python -m pip` skips all of that.
sudo -u "${APP_USER}" "${APP_DIR}/.venv/bin/python3" -m pip install --quiet --upgrade pip
sudo -u "${APP_USER}" "${APP_DIR}/.venv/bin/python3" -m pip install --quiet -r "${APP_DIR}/requirements.txt"

log "Granting low-port bind capability to the venv's Python"
# Lets the gunicorn workers bind 443 and the RADIUS server bind 1812 without
# running as root. Best-effort: on Debian, venv python is typically a symlink
# to /usr/bin/python3 and setcap refuses symlinks. That's fine — the systemd
# unit also sets AmbientCapabilities=CAP_NET_BIND_SERVICE, which provides the
# same permission at service start. setcap is just belt-and-suspenders for
# direct invocations (testing, dev).
setcap 'cap_net_bind_service=+ep' "${APP_DIR}/.venv/bin/python3" 2>/dev/null \
    || warn "setcap skipped (venv python is a symlink); relying on systemd AmbientCapabilities"

log "Seeding .env if missing"
if [[ ! -f "${APP_DIR}/.env" ]]; then
    install -m 0640 -o "${APP_USER}" -g "${APP_USER}" "${APP_DIR}/.env.example" "${APP_DIR}/.env"
fi

log "Installing sudoers rule for wizard-driven network changes"
# The wizard's network step applies a new IP/hostname/gateway/DNS at the end
# of the flow. Scoped sudo only — no general root, just these three commands.
install -d -m 0750 /etc/sudoers.d
cat > /etc/sudoers.d/captive-portal <<EOF
# Scoped sudo for the captive-portal setup wizard's network step.
${APP_USER} ALL=(root) NOPASSWD: /usr/sbin/netplan apply
${APP_USER} ALL=(root) NOPASSWD: /usr/bin/hostnamectl set-hostname *
${APP_USER} ALL=(root) NOPASSWD: /bin/systemctl restart systemd-networkd
EOF
chmod 0440 /etc/sudoers.d/captive-portal
visudo -cf /etc/sudoers.d/captive-portal >/dev/null

log "Installing systemd units"
install -m 0644 "${APP_DIR}/deploy/captive-portal.service" "${SERVICE_FILE}"
install -m 0644 "${APP_DIR}/deploy/captive-portal-firstboot.service" \
    /etc/systemd/system/captive-portal-firstboot.service
install -m 0755 "${APP_DIR}/deploy/captive-portal-firstboot" \
    /usr/local/sbin/captive-portal-firstboot
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
install -m 0755 "${APP_DIR}/deploy/certbot-reload-portal" \
    /etc/letsencrypt/renewal-hooks/deploy/00-reload-captive-portal || true
systemctl daemon-reload
systemctl enable --now captive-portal.service
# firstboot is *enabled* but won't run until prep-for-export.sh wipes the
# machine-id (its ConditionFirstBoot triggers only on a clean machine-id).
systemctl enable captive-portal-firstboot.service || true

log "Done."
echo
echo "Next steps:"
echo "  1. Open https://<this-host>/ — you'll land on the setup wizard."
echo "  2. Walk through each step. The wizard issues the TLS cert via Cloudflare DNS-01."
echo "  3. The portal restarts itself when you click 'Save and restart' at the end."
echo
echo "Logs:    journalctl -u captive-portal -f"
echo "Status:  systemctl status captive-portal"
