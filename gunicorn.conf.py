"""Gunicorn config — run RADIUS + sweeper in master so only one listener exists,
and serve TLS directly from the certbot-issued cert files.
"""
import os

# Tell app.py we're under gunicorn so it doesn't try to start RADIUS again
# inside a worker (the on_starting hook below already does it once).
os.environ["RUN_RADIUS"] = "1"

# TLS: read from env at gunicorn-config load time. When the wizard hasn't
# issued a cert yet, we listen plain on 8080 so the wizard remains reachable;
# in normal mode the cert files exist so we bind 443 with TLS.
_cert = os.environ.get("TLS_CERT_FILE") or ""
_key = os.environ.get("TLS_KEY_FILE") or ""

if _cert and _key and os.path.exists(_cert) and os.path.exists(_key):
    bind = "0.0.0.0:443"
    certfile = _cert
    keyfile = _key
else:
    bind = "0.0.0.0:8080"

workers = 2
threads = 4
worker_class = "gthread"
timeout = 60
graceful_timeout = 30

# Import the app once in the master and fork workers from there. Critical so
# all workers share the same FLASK_SECRET_KEY (in bootstrap mode the key is
# ephemeral random; without preload, each worker generates its own and signed
# session cookies break across workers — the wizard session would silently
# disappear partway through).
preload_app = True


def on_starting(server):
    """Master-process startup. Only runs in normal mode (bootstrap mode has
    no .env to satisfy the required keys, so SETUP_COMPLETE isn't true)."""
    from config import is_setup_complete
    if not is_setup_complete():
        server.log.info("bootstrap mode — skipping RADIUS + sweeper startup")
        return
    from radius_server import start_radius_thread
    from expiry import start_sweeper_thread
    start_radius_thread()
    start_sweeper_thread()
