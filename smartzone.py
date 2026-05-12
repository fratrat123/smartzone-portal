"""SmartZone 144 (SZ 7.x) Public API client.

Currently only implements 'lookup client by MAC' for hostname enrichment.
Auth uses serviceTicket (token in query string).
"""
import logging
import threading
import time
from typing import Any

import requests
import urllib3

from config import config
from macfmt import display_upper_colon

log = logging.getLogger(__name__)

# SmartZone controllers ship with self-signed certs by default.
if not config.SZ_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SmartZoneClient:
    def __init__(self):
        self._lock = threading.Lock()
        self._ticket: str | None = None
        self._ticket_obtained_at: float = 0.0
        self._ticket_ttl = 25 * 60  # serviceTicket idle timeout default ~30 min; refresh early
        self._base = f"https://{config.SZ_HOST}:{config.SZ_PORT}/wsg/api/public/{config.SZ_API_VERSION}"
        self._session = requests.Session()
        self._session.verify = config.SZ_VERIFY_TLS

    def _login(self) -> str:
        r = self._session.post(
            f"{self._base}/serviceTicket",
            json={"username": config.SZ_USERNAME, "password": config.SZ_PASSWORD},
            timeout=10,
        )
        r.raise_for_status()
        ticket = r.json()["serviceTicket"]
        self._ticket = ticket
        self._ticket_obtained_at = time.monotonic()
        return ticket

    def _ticket_param(self) -> dict:
        with self._lock:
            if not self._ticket or (time.monotonic() - self._ticket_obtained_at) > self._ticket_ttl:
                self._login()
        return {"serviceTicket": self._ticket}

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        params = kwargs.pop("params", {}) or {}
        params.update(self._ticket_param())
        r = self._session.request(method, f"{self._base}{path}", params=params, timeout=10, **kwargs)
        if r.status_code == 401:
            with self._lock:
                self._ticket = None
            params.update(self._ticket_param())
            r = self._session.request(method, f"{self._base}{path}", params=params, timeout=10, **kwargs)
        return r

    def lookup_client(self, mac: str) -> dict[str, Any] | None:
        """Look up an active client by MAC. Returns the first matching record or None.

        On SZ 6.1.1 / v11_1, the CLIENT filter type belongs in `extraFilters` —
        the top-level `filters` array is reserved for scope filters (zone, AP, etc.).
        """
        body = {
            "extraFilters": [
                {"type": "CLIENT", "value": display_upper_colon(mac), "operator": "eq"}
            ],
            "limit": 1,
        }
        try:
            r = self._request("POST", "/query/client", json=body)
            r.raise_for_status()
            data = r.json()
            items = data.get("list") or data.get("data") or []
            return items[0] if items else None
        except Exception:
            log.exception("SmartZone lookup_client failed for %s", mac)
            return None

    def get_hostname(self, mac: str) -> str | None:
        rec = self.lookup_client(mac)
        if not rec:
            return None
        return rec.get("hostname") or None

    def disconnect_client(self, mac: str, ap_mac: str | None) -> bool:
        """Force a client to disconnect via SmartZone Public API.

        Returns True on success (200 or 204 from the controller).
        Requires both the client MAC and the AP MAC. We learn the AP MAC from
        each Access-Request (Called-Station-Id) and persist it on the device row.
        """
        if not ap_mac:
            log.warning("disconnect_client: no AP MAC known for %s", mac)
            return False

        body = {
            "mac": display_upper_colon(mac),
            "apMac": display_upper_colon(ap_mac),
        }
        try:
            r = self._request("POST", "/clients/disconnect", json=body)
        except Exception:
            log.exception("smartzone disconnect_client crashed for %s", mac)
            return False

        if r.status_code in (200, 204):
            log.info("smartzone: disconnect_client OK for %s on AP %s",
                     body["mac"], body["apMac"])
            return True
        log.warning("smartzone: disconnect_client failed %s on AP %s -> %s %s",
                    body["mac"], body["apMac"], r.status_code, r.text[:200])
        return False


sz_client = SmartZoneClient()
