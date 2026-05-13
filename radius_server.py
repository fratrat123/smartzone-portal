"""Plain-socket RADIUS server for MAC auth.

Why not pyrad.server.Server? It uses select.poll() which doesn't exist on Windows.
We do the UDP loop ourselves and use pyrad only for packet parsing/formatting,
which is the cross-platform half.

Flow:
  Access-Request arrives with User-Name = MAC (format per config)
  -> normalize, look up in `devices`
  -> approved  : Access-Accept
  -> otherwise : create/refresh pending row, Access-Reject
"""
import logging
import socket
import threading
from datetime import datetime, timezone

from pyrad.dictionary import Dictionary
from pyrad import packet
from pyrad.packet import AuthPacket, AccessAccept, AccessReject, AccessRequest

from config import config
from db import Device, DeviceSsidSeen, SessionLocal, audit
from macfmt import canonical
from notifications import notify_new_pending
from smartzone import sz_client

log = logging.getLogger(__name__)


class MacAuthServer:
    def __init__(self):
        self._dict = Dictionary("dictionary")
        self._secret = config.RADIUS_SHARED_SECRET
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((config.RADIUS_LISTEN_HOST, config.RADIUS_LISTEN_PORT))

    def serve_forever(self):
        log.info("RADIUS server listening on %s:%d",
                 config.RADIUS_LISTEN_HOST, config.RADIUS_LISTEN_PORT)
        while True:
            try:
                data, addr = self._sock.recvfrom(4096)
            except OSError as e:
                log.warning("recvfrom error: %s", e)
                continue
            try:
                pkt = AuthPacket(secret=self._secret, dict=self._dict, packet=data)
            except Exception:
                log.exception("malformed RADIUS packet from %s", addr)
                continue
            if pkt.code != AccessRequest:
                log.info("ignoring non-auth packet code=%s from %s", pkt.code, addr)
                continue
            try:
                self._handle(pkt, addr)
            except Exception:
                log.exception("auth handler crashed for %s", addr)

    def _handle(self, pkt: AuthPacket, addr):
        try:
            user_name = pkt["User-Name"][0]
        except (KeyError, IndexError):
            log.warning("Access-Request without User-Name from %s", addr)
            return self._reply(pkt, addr, AccessReject)

        try:
            mac = canonical(user_name)
        except ValueError:
            log.info("Access-Request with non-MAC User-Name=%r from %s", user_name, addr)
            return self._reply(pkt, addr, AccessReject)

        ssid_raw = _first(pkt, "Called-Station-Id")  # "<AP-MAC>:<SSID>" on SmartZone
        ap_mac, ssid_name = _split_called(ssid_raw)

        with SessionLocal() as s:
            dev = s.get(Device, mac)
            now = datetime.now(timezone.utc)
            if dev and dev.status == "approved":
                # Expired approval -> reject. The background sweeper will flip
                # status to 'expired' on its next pass and CoA-kick if needed.
                # tz re-attach because SQLite strips it on read.
                approved_until = dev.approved_until
                if approved_until and approved_until.tzinfo is None:
                    approved_until = approved_until.replace(tzinfo=timezone.utc)
                if approved_until and approved_until < now:
                    _touch_seen(s, mac, ssid_name, ap_mac, dev, now)
                    audit(s, "radius_reject", mac=mac,
                          details=f"approval expired at {dev.approved_until.isoformat()}; ssid={ssid_name}")
                    s.commit()
                    log.info("REJECT %s (expired) (ssid=%s)", mac, ssid_name)
                    return self._reply(pkt, addr, AccessReject)
                _touch_seen(s, mac, ssid_name, ap_mac, dev, now)
                audit(s, "radius_accept", mac=mac, details=f"ssid={ssid_name}")
                s.commit()
                log.info("ACCEPT %s (ssid=%s)", mac, ssid_name)
                return self._reply(pkt, addr, AccessAccept)

            if not dev:
                dev = Device(
                    mac=mac,
                    status="pending",
                    first_seen_ssid=ssid_name,
                    first_seen_ap_mac=ap_mac,
                    last_seen_ssid=ssid_name,
                    last_seen_ap_mac=ap_mac,
                    last_seen_at=now,
                )
                s.add(dev)
                # Best-effort hostname enrichment, only on first sighting.
                try:
                    hostname = sz_client.get_hostname(mac)
                except Exception:
                    log.exception("smartzone hostname lookup failed for %s", mac)
                    hostname = None
                if hostname:
                    dev.hostname = hostname
                _touch_seen(s, mac, ssid_name, ap_mac, dev, now)
                audit(s, "radius_reject", mac=mac, details=f"new pending; ssid={ssid_name}")
                _notify_args = (mac, hostname, ssid_name)
                _is_new_pending = True
            else:
                _touch_seen(s, mac, ssid_name, ap_mac, dev, now)
                audit(s, "radius_reject", mac=mac, details=f"status={dev.status}; ssid={ssid_name}")
                _is_new_pending = False
            s.commit()

        log.info("REJECT %s (ssid=%s)", mac, ssid_name)
        if _is_new_pending:
            # First time we've seen this MAC — admins get pinged. Fire-and-forget.
            notify_new_pending(
                mac=mac,
                mac_display=":".join(mac[i:i + 2] for i in range(0, 12, 2)).upper(),
                requested_by_email=None,
                friendly_name=None,
                hostname=_notify_args[1],
                device_type=None,
                ssid=_notify_args[2],
            )
        return self._reply(pkt, addr, AccessReject)

    def _reply(self, pkt: AuthPacket, addr, code: int):
        reply = pkt.CreateReply()
        reply.code = code
        self._sock.sendto(reply.ReplyPacket(), addr)


def _touch_seen(s, mac: str, ssid: str | None, ap_mac: str | None,
                dev: "Device", now: datetime) -> None:
    """Refresh per-device + per-(device,SSID) last-seen tracking. No commit."""
    dev.last_seen_at = now
    if ssid:
        dev.last_seen_ssid = ssid
    if ap_mac:
        dev.last_seen_ap_mac = ap_mac
        if not dev.first_seen_ap_mac:
            dev.first_seen_ap_mac = ap_mac
    if not ssid:
        return
    row = s.get(DeviceSsidSeen, (mac, ssid))
    if row is None:
        s.add(DeviceSsidSeen(mac=mac, ssid=ssid,
                             first_seen_at=now, last_seen_at=now, hit_count=1))
    else:
        row.last_seen_at = now
        row.hit_count = (row.hit_count or 0) + 1


def _first(pkt, key: str) -> str | None:
    try:
        return pkt[key][0]
    except (KeyError, IndexError):
        return None


def _split_called(called: str | None) -> tuple[str | None, str | None]:
    """SmartZone Called-Station-Id is '<AP-MAC>:<SSID>'."""
    if not called:
        return None, None
    if ":" in called:
        ap, ssid = called.rsplit(":", 1)
        return ap, ssid
    return called, None


def start_radius_thread():
    srv = MacAuthServer()
    t = threading.Thread(target=srv.serve_forever, name="radius-server", daemon=True)
    t.start()
    return t
