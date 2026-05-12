"""Flask app entry. Starts the RADIUS server in a background thread."""
import logging

from flask import Flask, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from config import config
from db import init_db
from expiry import start_sweeper_thread
from oauth import init_oauth
from radius_server import start_radius_thread
from routes.admin import bp as admin_bp
from routes.portal import bp as portal_bp


def create_app() -> Flask:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    app = Flask(__name__)
    # Caddy in front: trust X-Forwarded-{Proto,Host,For} so Flask knows it's behind HTTPS.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)

    app.config["SECRET_KEY"] = config.SECRET_KEY
    # Secure cookies only over HTTPS. Auto-relax for local http://localhost dev.
    app.config["SESSION_COOKIE_SECURE"] = config.PORTAL_BASE_URL.startswith("https://")
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    init_db()
    init_oauth(app)
    app.register_blueprint(portal_bp)
    app.register_blueprint(admin_bp)

    @app.route("/")
    def index():
        return redirect(url_for("portal.landing"))

    @app.route("/healthz")
    def healthz():
        return {"ok": True}

    return app


app = create_app()
# Start RADIUS server only in the main process (not in Werkzeug's reloader child).
# When running under gunicorn we let the master start it once via on_starting hook in
# gunicorn.conf.py — see README.
import os
if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or os.environ.get("RUN_RADIUS") == "1":
    start_radius_thread()


if __name__ == "__main__":
    # Dev only. Use gunicorn (Linux) or waitress (Windows) for production.
    start_radius_thread()
    start_sweeper_thread()
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
