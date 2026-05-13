#!/usr/bin/env bash
# Reset a configured captive-portal VM back to "fresh appliance" state, ready
# to shut down and export as an OVA.
#
# Idempotent: re-run if you tweak something and want a clean slate again.
# Run as root, ON THE GOLDEN VM ONLY. Don't run on a deployed instance — it
# will wipe its identity, its database, and its configuration.
set -euo pipefail

APP_DIR="/opt/captive-portal"
APP_USER="captive-portal"
SHIP_IP_CIDR="192.168.254.254/24"
SHIP_GATEWAY="192.168.254.1"
SHIP_HOSTNAME="captive-portal"

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[1;31m!! %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run as root (sudo)."

read -rp "This will WIPE configuration, database, certificates, SSH host keys, machine-id, logs, and bash history. Continue? (yes/no) " confirm
[[ "$confirm" == "yes" ]] || { echo "aborted."; exit 1; }

log "Stopping the portal service"
systemctl stop captive-portal.service 2>/dev/null || true

log "Resetting portal data"
# Wipe the SQLite DB if present — recipient starts with no devices on file.
rm -f "${APP_DIR}/portal.db" "${APP_DIR}/portal.db-journal" "${APP_DIR}/portal.db-wal" "${APP_DIR}/portal.db-shm"
# Reset .env back to .env.example so the portal boots into bootstrap mode.
if [[ -f "${APP_DIR}/.env.example" ]]; then
    install -m 0640 -o "${APP_USER}" -g "${APP_USER}" "${APP_DIR}/.env.example" "${APP_DIR}/.env"
fi

log "Removing any issued Let's Encrypt certs"
rm -rf /etc/letsencrypt
# Recreate the empty top-level dir + hook subdir so the install layout is intact.
install -d -m 0755 /etc/letsencrypt
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
if [[ -x "${APP_DIR}/deploy/certbot-reload-portal" ]]; then
    install -m 0755 "${APP_DIR}/deploy/certbot-reload-portal" /etc/letsencrypt/renewal-hooks/deploy/00-reload-captive-portal
fi

log "Pinning netplan to ship IP ${SHIP_IP_CIDR}"
# Remove any other netplan files so there's no conflict at first boot.
rm -f /etc/netplan/*.yaml /etc/netplan/*.yml
cat > /etc/netplan/01-captive-portal.yaml <<EOF
# Captive portal appliance — ship state.
# The setup wizard rewrites this file when the operator picks a permanent IP.
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses: [${SHIP_IP_CIDR}]
      routes:
        - to: default
          via: ${SHIP_GATEWAY}
      nameservers:
        addresses: [1.1.1.1, 1.0.0.1]
EOF
chmod 0600 /etc/netplan/01-captive-portal.yaml

log "Setting ship hostname"
hostnamectl set-hostname "${SHIP_HOSTNAME}"

log "Installing first-boot console banner (/etc/issue)"
install -m 0644 "${APP_DIR}/deploy/issue.appliance" /etc/issue
# Also overwrite issue.net (shown to telnet/ssh pre-auth on some configs)
install -m 0644 "${APP_DIR}/deploy/issue.appliance" /etc/issue.net 2>/dev/null || true

log "Resetting OS-level account password"
echo 'portal:portal' | chpasswd
# Clear lastlog timestamp so the new password isn't immediately stale.
# (we're intentionally NOT forcing first-login password change — the
# recipient is expected to use the web wizard, not the shell.)

log "Wiping machine identity"
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id

log "Wiping SSH host keys (first-boot service regenerates)"
rm -f /etc/ssh/ssh_host_*

log "Enabling first-boot regen service"
install -m 0644 "${APP_DIR}/deploy/captive-portal-firstboot.service" \
    /etc/systemd/system/captive-portal-firstboot.service
install -m 0755 "${APP_DIR}/deploy/captive-portal-firstboot" \
    /usr/local/sbin/captive-portal-firstboot
systemctl daemon-reload
systemctl enable captive-portal-firstboot.service

log "Clearing DHCP leases"
rm -f /var/lib/dhcp/*.leases /var/lib/dhcpcd/*.lease 2>/dev/null || true
rm -rf /var/lib/NetworkManager/*.lease 2>/dev/null || true

log "Clearing logs"
journalctl --rotate >/dev/null 2>&1 || true
journalctl --vacuum-time=1s >/dev/null 2>&1 || true
find /var/log -type f \( -name '*.log' -o -name '*.gz' -o -name '*.1' \) -delete 2>/dev/null || true
truncate -s 0 /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null || true

log "Clearing bash history"
for h in /root/.bash_history /home/*/.bash_history; do
    [[ -f "$h" ]] && truncate -s 0 "$h"
done
history -c 2>/dev/null || true

log "Cleaning apt caches"
apt-get clean
rm -rf /var/lib/apt/lists/*

log "Zeroing free space for better OVA compression"
# Optional but recommended — typical disk goes from ~6 GB to ~2 GB compressed.
# Skip with PREP_NO_ZEROFREE=1 if you're in a hurry.
if [[ "${PREP_NO_ZEROFREE:-0}" != "1" ]]; then
    if command -v dd >/dev/null; then
        dd if=/dev/zero of=/zerofile bs=1M status=progress 2>/dev/null || true
        rm -f /zerofile
        sync
    fi
fi

cat <<'EOF'

================================================================
  Appliance is ready to export.
  Next steps:
    1. shutdown -h now
    2. In ESXi: VM -> Export -> OVF Template (or Export OVA)
    3. Ship the .ova to the recipient.

  Recipient experience:
    - Import OVA in ESXi
    - Power on; console shows http://192.168.254.254:8080/setup
    - Open browser at that URL, walk the wizard
    - Wizard reboots the box at the recipient's chosen IP
================================================================

EOF
