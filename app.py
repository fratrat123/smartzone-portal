"""Flask app entry. Starts the RADIUS server in a background thread."""
import logging

from flask import Flask, redirect, render_template, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from config import config
from db import init_db
from expiry import start_sweeper_thread
from oauth import current_user, init_oauth
from radius_server import start_radius_thread
from routes.admin import bp as admin_bp
from routes.portal import bp as portal_bp


def create_app() -> Flask:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    app = Flask(__name__)
    # If a reverse proxy / TLS terminator is in front, trust the forwarded
    # headers so url_for() generates https:// URLs and request.remote_addr is
    # the real client. Harmless when no proxy is in front.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)

    app.config["SECRET_KEY"] = config.SECRET_KEY
    # Secure cookies only over HTTPS. Auto-relax for local http://localhost dev.
    app.config["SESSION_COOKIE_SECURE"] = config.PORTAL_BASE_URL.startswith("https://")
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    init_db()
    init_oauth(app)
    app.register_blueprint(portal_bp)
    app.register_blueprint(admin_bp)

    # Make user and branding available in every template without explicit passing.
    @app.context_processor
    def inject_context():
        return {
            "user": current_user(),
            "brand_name": config.PORTAL_BRAND_NAME,
            "brand_mark": (config.PORTAL_BRAND_NAME or "?")[:1].upper(),
            "support_email": config.PORTAL_SUPPORT_EMAIL,
            "logo_url": config.PORTAL_LOGO_URL,
            "email_placeholder": (
                config.PORTAL_EMAIL_PLACEHOLDER
                or (f"you@{config.GOOGLE_HOSTED_DOMAIN}" if config.GOOGLE_HOSTED_DOMAIN
                    else "you@example.com")
            ),
        }

    @app.route("/")
    def index():
        return redirect(url_for("portal.landing"))

    @app.route("/healthz")
    def healthz():
        from sqlalchemy import text
        from db import SessionLocal
        from smartzone import sz_client

        checks: dict = {"flask": True}
        ok = True

        # DB check — a trivial SELECT proves the engine + file are reachable.
        try:
            with SessionLocal() as s:
                s.execute(text("SELECT 1"))
            checks["db"] = True
        except Exception as e:
            checks["db"] = f"error: {e!s}"
            ok = False

        # SmartZone API — try a service-ticket auth round trip.
        # This is a soft check: if SZ is unreachable but RADIUS still works,
        # the portal is degraded but not down. We report it, don't fail.
        try:
            sz_client._ticket_param()  # forces auth if no cached ticket
            checks["smartzone_api"] = True
        except Exception as e:
            checks["smartzone_api"] = f"error: {e!s}"

        return ({"ok": ok, "checks": checks}, 200 if ok else 503)

    # ---- Friendly error pages ----
    @app.errorhandler(404)
    def _not_found(e):
        return render_template("error.html",
            status="404", icon="?", title="Page not found",
            message="That page doesn't exist or has moved."), 404

    @app.errorhandler(403)
    def _forbidden(e):
        return render_template("error.html",
            status="403", icon="🚫", title="Access denied",
            message="You don't have permission to view this page. "
                    "If you should — ask an existing admin to add your email."), 403

    @app.errorhandler(500)
    def _server_error(e):
        return render_template("error.html",
            status="500", icon="!", title="Something went wrong",
            message="The server hit an unexpected error. The log has the details — "
                    "ping your administrator if this keeps happening."), 500

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
