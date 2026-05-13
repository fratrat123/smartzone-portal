# SmartZone Captive Portal

A self-service MAC-registration captive portal for **Ruckus SmartZone**
controllers (tested on SZ 6.1.1 / SZ 144). Replaces a passphrase SSID with a
sponsor-approved MAC allowlist — users register a device once via a web
portal, an admin approves, and the device joins silently from then on.

Designed to drop onto a small Debian VM and configure itself via a first-run
setup wizard. No external reverse proxy, no separate auth daemon — one Python
process, one systemd unit.

## What it does

- Client associates to an open SSID → SmartZone does RADIUS MAC auth against
  the portal.
- Unknown MAC → portal returns Reject → SmartZone redirects to the captive
  portal page.
- User authenticates by **email magic link / 6-digit code** (works inside iOS
  CNA mini-browser, unlike Google OAuth) or by Google OAuth on real browsers.
- User picks a device type + friendly name → request lands in the admin queue.
- Each configured admin gets an email with one-click **Approve / Deny** links
  (no portal login needed; the link itself is the auth).
- Approve → SmartZone API kicks the client → it reassociates and passes MAC
  auth silently. Approvals can be time-limited; a background sweeper flips
  expired approvals back to rejected and kicks the client.

## Architecture

```
                          ┌────────────────────────────────┐
                          │  Debian VM (one systemd unit)  │
                          │                                │
client ──Wi-Fi──┐    ┌────│  Flask + pyrad + sweeper       │
                │    │    │    ├ TLS on :443               │
                ▼    ▼    │    ├ RADIUS on UDP :1812       │
        SmartZone ───RADIUS─→  └ SQLite (or MariaDB)       │
        controller   ←──CoA──                              │
                ▲    ▲    │  outbound: SmartZone API,      │
                │    │    │            SMTP, OAuth         │
                └────┘    │                                │
                          └────────────────────────────────┘
```

| Component | Role |
| --- | --- |
| `app.py` | Flask entry; starts RADIUS + expiry threads |
| `radius_server.py` | pyrad-based MAC auth server (plain UDP socket) |
| `coa.py` | RFC 5176 CoA-Disconnect fallback for SZ API failures |
| `smartzone.py` | SmartZone Public API client |
| `arp.py` | ARP + reverse-DNS hostname lookup (LAN-adjacent only) |
| `email_sender.py` | SMTP delivery for sign-in codes |
| `expiry.py` | Background sweeper for expired approvals |
| `oauth.py` | Google OAuth with optional Workspace domain restriction |
| `action_tokens.py` | Signed tokens for magic-link approve/deny emails |
| `notifications.py` | New-pending Slack + per-admin email with magic links |
| `routes/portal.py` | End-user portal (email magic link + Google OAuth) |
| `routes/admin.py` | Approve / Deny / Ignore queue + admin management |
| `device_types.py` | OS device type list + UA-based inference |
| `db.py` | SQLAlchemy models + lightweight migrations |
| `dictionary` | Minimal RADIUS attribute dictionary for pyrad |

## Quick start (Debian 12)

> *The full automated installer + setup wizard live in the upcoming
> `redeploy/wizard` branch. The steps below are the manual path.*

```sh
sudo apt-get install -y python3 python3-venv python3-pip
git clone <this repo> /opt/captive-portal
cd /opt/captive-portal
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env       # leave SETUP_COMPLETE=false on first boot
```

Start the app — it boots into setup mode and serves the wizard at
`https://your-host/setup`:

```sh
.venv/bin/python app.py
```

Walk through the wizard (branding, OAuth, SmartZone, admins, RADIUS). It
writes back to `.env`, sets `SETUP_COMPLETE=true`, and restarts. The portal
is now live.

## SmartZone configuration

The setup wizard generates a checklist with values pre-filled for your install
(walled-garden domains, AP MAC option, etc.). The short version:

### AAA Auth Profile

Services & Profiles → AAA Servers → Authentication → Create:
- Type: RADIUS
- Primary Server IP: portal host LAN IP
- Port: 1812
- Shared Secret: matches `RADIUS_SHARED_SECRET` in `.env`

### Hotspot (WISPr) profile

Services & Profiles → Hotspots & Portals → Hotspot (WISPr) → Create:
- Smart Client Support: None
- Logon URL: External
- Primary URL: `<PORTAL_BASE_URL>/portal`
- Redirected MAC Format: `AA:BB:CC:DD:EE:FF`
- HTTPS Redirect: ON
- Walled Garden:
  ```
  <your portal hostname>
  *.google.com
  *.googleapis.com
  *.gstatic.com
  *.googleusercontent.com
  accounts.youtube.com
  gmail.com
  mail.google.com
  ```

### WLAN

Wireless LANs → your zone → Create:
- Authentication Type: **Hotspot (WISPr)**
- Method: **MAC Address**
- MAC Authentication: OFF (uses MAC as password)
- MAC Address Format: must match `RADIUS_MAC_FORMAT` in `.env`
- Encryption: None
- Hotspot (WISPr) Portal: the profile above
- Authentication Server: the AAA profile above
- **RADIUS Options → Called Station ID: AP MAC** *(not WLAN BSSID — important for CoA)*
- Advanced → Client Fingerprinting: ON (so hostname populates)
- Advanced → Inactivity Timeout: bump from 120s default

## Day-to-day

- Admin queue: `<PORTAL_BASE_URL>/admin/`
- Add/remove admins, browse audit log: links from the admin header
- Magic-link approvals arrive in admins' inboxes as new requests come in

## Known limitations

- iOS CNA mini-browser blocks Google OAuth (Google won't render OAuth in
  embedded webviews). Use the email magic link path instead — it works in CNA.
- ARP-based client MAC enrichment requires the portal host to share a
  broadcast domain with wireless clients. Without it the portal falls back to
  SmartZone's API for hostname lookup.
- SmartZone wildcard walled-garden matching can be finicky. If a Google
  resource fails with SSL errors, add the specific hostname explicitly.
- SQLite is fine for school-scale (hundreds of devices). For larger
  deployments, switch `DATABASE_URL` to MariaDB or Postgres.

## License

Internal tool. Not packaged for general release.
