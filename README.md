# SmartZone MAC-Registration Portal

A self-service captive portal for **Ruckus SmartZone 144 (6.1.1)**. Replaces a
passphrase SSID with a sponsor-approved MAC allowlist — users register their
device via the portal, an admin approves, the device joins silently from then on.

Built for a school running Google Workspace, but generalizes to any small org.

## What it does

- Client associates to an open SSID → RADIUS MAC auth
- Unknown MAC → SmartZone redirects to the portal
- User authenticates by **email magic link / 6-digit code** (works inside iOS
  CNA mini-browser, unlike Google OAuth) or Google OAuth on real browsers
- User submits device-type + friendly name → request goes into the admin queue
- Admin clicks Approve → SmartZone API kicks the client → it reassociates and
  passes MAC auth silently
- Approvals expire after a configurable duration (default 1 day). A background
  sweeper flips expired approvals and kicks the client.

## Architecture

```
                      ┌──────────────────────────────┐
                      │      portal host (Win/Linux) │
                      │                              │
 client ──Wi-Fi──┐    │  Caddy :443 ──┐              │
                 │    │   (TLS,       │              │
                 ▼    │    Let's      ▼              │
   SmartZone ───RADIUS─→ Flask :8080  ──→  SQLite    │
   controller   ←──CoA── + pyrad :1812                │
                 ▲    │                              │
                 │    │  RADIUS / API to SmartZone   │
                 └────│                              │
                      └──────────────────────────────┘
```

| Component | Role |
| --- | --- |
| `app.py` | Flask entry, starts RADIUS + expiry threads |
| `radius_server.py` | pyrad-based MAC auth server, plain-socket (Windows-friendly) |
| `coa.py` | RFC 5176 CoA-Disconnect fallback |
| `smartzone.py` | SmartZone Public API (client lookup, disconnect_client) |
| `arp.py` | ARP-based client MAC + reverse DNS hostname resolution |
| `email_sender.py` | SMTP delivery for verification codes/links |
| `expiry.py` | Background sweeper for expired approvals |
| `oauth.py` | Google OAuth (Authlib), with Workspace domain restriction |
| `routes/portal.py` | User-facing portal (email magic link + Google OAuth) |
| `routes/admin.py` | Approve / Deny / Ignore / Reset queue, admin management |
| `device_types.py` | Per-OS device type list + UA-based inference |
| `db.py` | SQLAlchemy models (Device, EmailVerification, Admin, AuditLog) |
| `dictionary` | Minimal RADIUS attribute dictionary for pyrad |
| `Caddyfile` | Reverse proxy with auto TLS via Cloudflare DNS-01 |

## Setup

### 1. Python + deps

```sh
python -m venv .venv
.venv\Scripts\activate          # or .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```sh
cp .env.example .env
# Edit .env with your values
```

Required:

- **Flask**: `FLASK_SECRET_KEY`, `PORTAL_BASE_URL`
- **Google OAuth** (for admin login + portal fallback): `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_HOSTED_DOMAIN`
- **Admin emails**: `ADMIN_EMAILS` (comma-separated bootstrap admins)
- **RADIUS**: `RADIUS_SHARED_SECRET` (must match the AAA profile in SmartZone)
- **CoA**: `COA_HOST` (controller IP), `COA_SECRET` (= `RADIUS_SHARED_SECRET` on Ruckus)
- **SmartZone API**: `SZ_HOST`, `SZ_USERNAME`, `SZ_PASSWORD`, `SZ_API_VERSION` (v11_1 for SZ 6.1.1)
- **SMTP**: `SMTP_HOST`, `SMTP_FROM_EMAIL` (Google Workspace SMTP relay works out of the box)

### 3. TLS (Caddy)

```sh
# Download Caddy with the Cloudflare DNS plugin baked in
https://caddyserver.com/api/download?os=windows&arch=amd64&p=github.com/caddy-dns/cloudflare

# Run with your Cloudflare API token (Zone:Read + DNS:Edit on the zone)
$env:CF_API_TOKEN = "your-token-here"
.\caddy.exe run
```

### 4. Run the app

```sh
python app.py
```

You'll see:
```
RADIUS server listening on 0.0.0.0:1812
expiry: sweeper started (interval=60s)
 * Serving Flask app 'app'
```

## SmartZone configuration

### AAA Auth Profile

Services & Profiles → AAA Servers → Authentication → Create:
- Type: RADIUS
- Primary Server IP: portal host LAN IP
- Port: 1812
- Shared Secret: same value as `RADIUS_SHARED_SECRET` in `.env`

### Hotspot (WISPr) profile

Services & Profiles → Hotspots & Portals → Hotspot (WISPr) → Create:
- Smart Client Support: None
- Logon URL: External
- Primary URL: `https://portal.your-domain.com/portal`
- Redirected MAC Format: `AA:BB:CC:DD:EE:FF`
- HTTPS Redirect: ON
- Walled Garden:
  ```
  portal.your-domain.com
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
- MAC Address Format: `aabbccddeeff`
- Encryption: None
- Hotspot (WISPr) Portal: the profile from above
- Authentication Server: the AAA profile above
- **RADIUS Options → Called Station ID: AP MAC** *(not WLAN BSSID — important for CoA)*
- Advanced → Client Fingerprinting: ON (for hostname populating)
- Advanced → Inactivity Timeout: bump from 120s default to something higher

## Day-to-day

- Admin queue: `https://portal.your-domain.com/admin/`
- Admin management: same page → "admins" link in header
- Audit log: query the `audit_log` table directly

## Known limitations

- iOS CNA mini-browser can't complete Google OAuth (Google blocks embedded
  webviews). Use the email magic link path instead — it works inside CNA.
- ARP-based client MAC discovery requires the portal host to be on the same
  broadcast domain as the wireless clients.
- SmartZone wildcard walled-garden matching can be finicky. If a Google service
  fails with SSL errors, add the specific hostname explicitly.
- SQLite is fine for school-scale (hundreds of devices, a few admins). For
  larger deployments, change `DATABASE_URL` to MariaDB / Postgres.

## License

Internal tool. Not packaged for general release.
