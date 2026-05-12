"""Resolve a client MAC address via the OS ARP table, and hostname via reverse DNS.

ARP is used when SmartZone's portal redirect encrypts client_mac and the only
plaintext MAC in the URL params is the AP's MAC. Since the captive client's TCP
connection reaches our portal host directly (or through a same-subnet path), its
MAC is in our ARP cache as soon as the connection lands.

Reverse DNS works when the local DNS server (AD DNS in this deployment) has PTR
records for the client. Windows clients typically register themselves via dynamic
DNS, so the lookup succeeds for managed laptops.

Caveat: ARP only works when the portal host is on the same broadcast domain as
the wireless clients. If they're separated by a router, ARP only sees the router.
"""
from __future__ import annotations

import logging
import re
import socket
import subprocess

log = logging.getLogger(__name__)

_MAC_RE = re.compile(r"\b([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")


def hostname_for_ip(ip: str) -> str | None:
    """Reverse-DNS lookup, stripping the domain suffix for a clean short name."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError) as e:
        log.debug("reverse DNS failed for %s: %s", ip, e)
        return None
    # 'desktop-ctoquvu.hillmanschools.local' -> 'desktop-ctoquvu'
    short = name.split(".", 1)[0]
    return short or None


def mac_for_ip(ip: str) -> str | None:
    """Return MAC for the given IPv4 address as seen in the local ARP table, or None."""
    try:
        out = subprocess.check_output(
            ["arp", "-a"],
            text=True,
            timeout=3,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        log.warning("arp lookup failed: %s", e)
        return None

    for line in out.splitlines():
        # Windows: "  10.30.21.21           f0-20-ff-e8-0f-ad     dynamic"
        # Linux:   "? (10.30.21.21) at f0:20:ff:e8:0f:ad [ether] on eth0"
        if ip in line:
            m = _MAC_RE.search(line)
            if m:
                return m.group(0)
    return None
