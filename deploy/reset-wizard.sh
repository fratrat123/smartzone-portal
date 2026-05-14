#!/usr/bin/env bash
# Reset the captive portal to wizard-default state — for dev iteration
# when you want to re-walk the wizard from scratch without snapshot-reverting.
#
# What this DOES:
#   - Stop the service
#   - Reset .env back to .env.example (drops SETUP_COMPLETE, all user input)
#   - Delete portal.db (clears device list, audit log, admins, etc.)
#   - Delete .bootstrap-secret (regenerated on next start)
#   - Delete any leftover wizard resume tokens
#   - Restart the service — comes back in bootstrap mode at the SAME IP
#
# What this does NOT do:
#   - Change /etc/netplan/01-captive-portal.yaml (current network stays)
#   - Change the system hostname
#   - Touch /etc/letsencrypt (cert files survive — wizard reuses them if the
#     hostname matches; otherwise issues fresh)
#   - Touch sudoers, systemd units, apt packages
#
# Use this for: testing the wizard repeatedly during development.
# Use prep-for-export.sh instead for: producing a shippable OVA.
set -euo pipefail

APP_DIR="/opt/captive-portal"
APP_USER="captive-portal"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m!! %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run as root (sudo)."

cat <<'EOF'
This will:
  - Stop the captive-portal service
  - Wipe portal.db, .env, .bootstrap-secret, .wizard-state/
  - Restart in bootstrap mode (wizard at /setup)

The network IP, hostname, OS, packages, and SSH access all stay intact.
EOF

read -rp "Continue? (yes/no) " confirm
[[ "$confirm" == "yes" ]] || { echo "aborted."; exit 0; }

log "Stopping service"
systemctl stop captive-portal.service 2>/dev/null || true

log "Wiping portal data"
rm -f  "${APP_DIR}/portal.db" \
       "${APP_DIR}/portal.db-journal" \
       "${APP_DIR}/portal.db-wal" \
       "${APP_DIR}/portal.db-shm" \
       "${APP_DIR}/.bootstrap-secret"
rm -rf "${APP_DIR}/.wizard-state"

log "Resetting .env to .env.example"
if [[ -f "${APP_DIR}/.env.example" ]]; then
    install -m 0640 -o "${APP_USER}" -g "${APP_USER}" \
        "${APP_DIR}/.env.example" "${APP_DIR}/.env"
else
    fail ".env.example missing — repo state is bad"
fi

log "Starting service"
systemctl start captive-portal.service
sleep 2
systemctl status captive-portal.service --no-pager | head -3

CURRENT_IP=$(hostname -I | awk '{print $1}')
cat <<EOF

Done. Service is back up in bootstrap mode.

  Open in a browser:  http://${CURRENT_IP}/setup

EOF
