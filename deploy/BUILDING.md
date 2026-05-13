# Building the captive-portal appliance (for the OVA producer)

This is **the operator-side procedure** — how you turn a clean Debian 12
install into a shippable OVA that recipients can import and configure via the
web wizard.

Recipients never see this document. They get an OVA and three sentences of
instructions ("import, power on, open `http://192.168.254.254:8080/setup`").

---

## What you need

- ESXi (any modern version — vSphere Web Client or VMware Workstation also work)
- A Debian 12 (Bookworm) network installer ISO
- About 20 minutes for the first build, 5 minutes for re-builds

## Step 1 — Build the base VM

In ESXi, create a new VM:

- **Guest OS:** Linux → Debian GNU/Linux 12 (64-bit)
- **CPU:** 1 vCPU
- **RAM:** 2 GB
- **Disk:** 10 GB, thin-provisioned
- **Network:** one adapter, VMXNET3, on a network that *has internet access*
  (you need to apt-install packages and clone the repo)
- **CD-ROM:** mount the Debian netinst ISO

Power on, install Debian. Choose:

- **Hostname:** `captive-portal` (prep-for-export.sh sets this too — doesn't matter much)
- **Domain:** leave blank
- **Root password:** anything (will be wiped)
- **Create user:** username `portal`, password `portal`
- **Disk partitioning:** guided, entire disk, all files in one partition
- **Software selection:** SSH server + standard system utilities. **No desktop.**
- **GRUB:** install to MBR/EFI as the installer suggests
- Reboot, log in as `portal`.

## Step 2 — Clone the repo + run the installer

```sh
sudo apt-get install -y git
sudo git clone https://github.com/<your-org>/captive-portal.git /opt/captive-portal
sudo chown -R root:root /opt/captive-portal

sudo bash /opt/captive-portal/deploy/install.sh
```

The installer:
- installs Python, certbot, the Cloudflare DNS plugin, libcap2-bin, etc.
- creates the `captive-portal` service user
- makes the venv, installs Python requirements
- `setcap` on the venv's Python so it can bind ports 443/1812
- installs the systemd unit + scoped sudoers rule + first-boot service
- starts the service in bootstrap mode

When it returns, the box is serving the setup wizard. From your laptop on the
same network, open `http://<box-ip>:8080/setup`.

## Step 3 — (Recommended) Walk the wizard end-to-end once

Just to verify the build works against your real SmartZone / Google / SMTP /
Cloudflare. This is *test data* — it gets wiped by `prep-for-export.sh`.

Walk through every step. Watch for:
- Test buttons returning green on SMTP, SmartZone, Cloudflare token
- Cert issuance succeeding on the TLS step
- Final restart bringing you back at the new IP cleanly

If anything fails, fix the underlying issue *in the code or .env.example*,
re-pull, re-run, re-test. Don't ship an appliance you haven't seen work.

## Step 4 — Reset to ship state

```sh
sudo bash /opt/captive-portal/deploy/prep-for-export.sh
```

This:
- stops the portal
- wipes `portal.db`, resets `.env` to the example (so `SETUP_COMPLETE=false`)
- removes any issued Let's Encrypt certs
- pins netplan back to `192.168.254.254/24`
- resets the OS hostname to `captive-portal`
- resets the `portal` user's password to `portal`
- wipes `/etc/machine-id` and SSH host keys (first-boot service regenerates)
- enables `captive-portal-firstboot.service` (runs once on recipient's first boot)
- clears DHCP leases, journald, /var/log/*, bash history, apt caches
- (optional) zeroes free disk space for better OVA compression

When it's done, **shut down immediately**:

```sh
sudo shutdown -h now
```

> Do not power on after running `prep-for-export.sh` — that triggers the
> first-boot regen, undoing the wipe. If you do power on by mistake, just
> re-run prep before exporting.

## Step 5 — Export the OVA

In the ESXi web client:

1. Select the powered-off VM
2. Actions → **Export OVF Template** (or **Export** in older versions)
3. Choose OVA format (single file) rather than OVF (multiple files)
4. Save to your local machine

The OVA is ~1.5–2 GB depending on whether you ran zerofree.

## Step 6 — Ship it

Copy the OVA to a flash drive, send a download link, whatever. Include three
sentences for the recipient:

> 1. Import the OVA in ESXi.
> 2. Power on the VM.
> 3. Open `http://192.168.254.254:8080/setup` from a browser on the same
>    subnet (or use ESXi's console).

That's all they need.

---

## Iterating: shipping a new version

If you want to ship an updated OVA without rebuilding from scratch:

1. Power on the same golden VM.
2. `cd /opt/captive-portal && sudo git pull`
3. `sudo bash deploy/install.sh` (idempotent — re-installs deps, refreshes systemd unit)
4. (Optional) Re-walk the wizard if changes affect the flow.
5. `sudo bash deploy/prep-for-export.sh`
6. `sudo shutdown -h now`
7. Re-export.

You can keep the golden VM around between releases. Snapshot it before each
prep-for-export run if you want a quick revert point.

## Troubleshooting

**Wizard's network step doesn't apply the new IP at the recipient site.**
The `captive-portal` user's sudoers entry didn't get installed. Check
`/etc/sudoers.d/captive-portal` exists and contains the NOPASSWD lines.
`install.sh` writes it; `prep-for-export.sh` leaves it alone.

**Recipient boots the OVA and console shows old IP / no MOTD.**
`prep-for-export.sh` wasn't run, or was run after powering on again
(first-boot regen consumed the marker). Rebuild from the snapshot, re-prep,
re-export.

**Two recipients on the same network have the same SSH host keys.**
The first-boot service didn't run. Check it's `enabled`:
`systemctl is-enabled captive-portal-firstboot.service`. If not enabled on
the golden VM, prep won't enable it either. Fix in `install.sh` and rebuild.
