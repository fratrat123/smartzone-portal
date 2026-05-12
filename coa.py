"""CoA-Disconnect sender.

Same Windows compatibility issue as the RADIUS server: pyrad.client.Client uses
select.poll() which doesn't exist on Windows. We send the packet with a plain
UDP socket and use pyrad just for packet build/parse.

Triggered after admin approval so the client immediately reassociates and gets
an Access-Accept on the retry, rather than waiting for the client's own retry
timer.
"""
import logging
import os
import socket

from pyrad.dictionary import Dictionary
from pyrad import packet
from pyrad.packet import CoAPacket

from config import config
from macfmt import to_radius_format

log = logging.getLogger(__name__)

_dict = Dictionary("dictionary")


def disconnect(mac: str) -> bool:
    """Send a Disconnect-Request for the given MAC. Returns True on ACK."""
    user_name = to_radius_format(mac, config.RADIUS_MAC_FORMAT)

    pkt = CoAPacket(
        code=packet.DisconnectRequest,
        secret=config.COA_SECRET,
        dict=_dict,
        authenticator=os.urandom(16),
    )
    # Calling-Station-Id is the primary session identifier on Ruckus.
    # We use upper-colon format (AA:BB:CC:DD:EE:FF) which matches what the
    # controller exports in its client list.
    pkt["Calling-Station-Id"] = to_radius_format(mac, "upper_colon")
    # User-Name in the same format the WLAN's MAC-auth uses, so SmartZone can
    # match it against the session it tracks internally.
    pkt["User-Name"] = user_name
    # NAS-IP-Address tells SmartZone which controller this CoA targets — required
    # when the controller serves multiple zones/clusters.
    pkt["NAS-IP-Address"] = config.COA_HOST

    raw = pkt.RequestPacket()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(raw, (config.COA_HOST, config.COA_PORT))
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        log.warning("CoA Disconnect timeout for %s (no reply from %s:%d)",
                    mac, config.COA_HOST, config.COA_PORT)
        return False
    except Exception:
        log.exception("CoA Disconnect send failed for %s", mac)
        return False
    finally:
        sock.close()

    try:
        reply = CoAPacket(secret=config.COA_SECRET, dict=_dict, packet=data)
    except Exception:
        log.exception("malformed CoA reply for %s", mac)
        return False

    ok = reply.code == packet.DisconnectACK

    # Log Error-Cause if NAK, so we can see *why* SmartZone refused.
    error_cause = None
    try:
        ec_vals = reply["Error-Cause"]
        if ec_vals:
            error_cause = ec_vals[0]
    except (KeyError, IndexError):
        pass

    log.info("CoA Disconnect %s -> code=%s (%s)%s",
             mac, reply.code, "ACK" if ok else "NAK",
             f" error_cause={error_cause}" if error_cause is not None else "")
    return ok
