"""Flask app entry. Picks bootstrap mode (setup wizard) or normal mode at
startup based on config.is_setup_complete()."""
import logging
import os
import sys

from flask import Flask, redirect, render_template, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from config import config, is_setup_complete, missing_required_keys

log = logging.getLogger(__name__)


def _common_app() -> Flask:
    """Build a Flask app shell that's identical between bootstrap and normal
    modes — branding context, proxy headers, error pages."""
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)

    app.config["SECRET_KEY"] = config.SECRET_KEY
    # SESSION_COOKIE_SECURE: only when we *actually* have a TLS cert installed.
    # PORTAL_BASE_URL being https isn't enough — that's just *intent*. The
    # operator may still be browsing via plain http:port-8080 while waiting
    # for cert issuance, in which case marking cookies Secure would break
    # OAuth (browser refuses to send Secure cookies over HTTP, so the OAuth
    # CSRF state token never gets back to the callback → MismatchingStateError).
    # Tie Secure strictly to "real HTTPS is available."
    _have_tls = bool(config.TLS_CERT_FILE and config.TLS_KEY_FILE
                     and os.path.exists(config.TLS_CERT_FILE)
                     and os.path.exists(config.TLS_KEY_FILE))
    app.config["SESSION_COOKIE_SECURE"] = (
        is_setup_complete()
        and _have_tls
        and config.PORTAL_BASE_URL.startswith("https://")
    )
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    @app.context_processor
    def inject_branding():
        from oauth import current_user
        # current_user() only resolves in normal mode where OAuth is wired up;
        # in bootstrap mode it returns None harmlessly because session is empty.
        try:
            user = current_user()
        except Exception:
            user = None
        return {
            "user": user,
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

    @app.errorhandler(404)
    def _not_found(e):
        return render_template("error.html",
            status="404", icon="?", title="Page not found",
            message="That page doesn't exist or has moved."), 404

    @app.errorhandler(403)
    def _forbidden(e):
        return render_template("error.html",
            status="403", icon="🚫", title="Access denied",
            message="You don't have permission to view this page."), 403

    @app.errorhandler(500)
    def _server_error(e):
        return render_template("error.html",
            status="500", icon="!", title="Something went wrong",
            message="The server hit an unexpected error. Check the logs."), 500

    return app


def create_bootstrap_app() -> Flask:
    """Minimal app for first-run setup: only the wizard is reachable. No DB,
    no OAuth, no RADIUS — those modules assume real config and would crash."""
    log.warning("starting in BOOTSTRAP mode — setup wizard is at /setup")
    app = _common_app()

    from routes.setup import bp as setup_bp
    app.register_blueprint(setup_bp)

    @app.route("/")
    def _bootstrap_index():
        return redirect(url_for("setup.welcome"))

    @app.route("/healthz")
    def _bootstrap_healthz():
        return {"ok": True, "mode": "bootstrap"}

    # Catch-all: anything else redirects to the wizard so an operator hitting
    # /admin/ on a half-configured box gets routed to setup instead of a 404.
    @app.route("/<path:_path>")
    def _bootstrap_catchall(_path):
        return redirect(url_for("setup.welcome"))

    return app


def create_normal_app() -> Flask:
    """Fully configured app: DB, OAuth, RADIUS, sweeper, all routes."""
    missing = missing_required_keys()
    if missing:
        log.error("SETUP_COMPLETE=true but required keys are unset: %s", ", ".join(missing))
        log.error("either fill those in .env or set SETUP_COMPLETE=false to re-run the wizard")
        sys.exit(2)

    log.info("starting in NORMAL mode")
    app = _common_app()

    # Heavy imports are deferred to here so bootstrap mode never touches them.
    from db import init_db
    from oauth import init_oauth
    from routes.admin import bp as admin_bp
    from routes.portal import bp as portal_bp
    from routes.setup import bp as setup_bp

    init_db()
    init_oauth(app)
    app.register_blueprint(portal_bp)
    app.register_blueprint(admin_bp)
    # Setup blueprint is also registered in normal mode so the admin
    # "Re-run setup wizard" button can flip back into bootstrap mode.
    app.register_blueprint(setup_bp)

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
        try:
            with SessionLocal() as s:
                s.execute(text("SELECT 1"))
            checks["db"] = True
        except Exception as e:
            checks["db"] = f"error: {e!s}"
            ok = False
        try:
            sz_client._ticket_param()
            checks["smartzone_api"] = True
        except Exception as e:
            checks["smartzone_api"] = f"error: {e!s}"
        return ({"ok": ok, "checks": checks}, 200 if ok else 503)

    return app


def create_app() -> Flask:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    if is_setup_complete():
        return create_normal_app()
    return create_bootstrap_app()


app = create_app()


def _maybe_start_background_threads():
    """Start RADIUS + sweeper, but only in normal mode and only once.

    Werkzeug's reloader spawns a child — we want the threads only in the
    actual server child (WERKZEUG_RUN_MAIN) or under gunicorn (RUN_RADIUS=1).
    """
    if not is_setup_complete():
        return
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true" and os.environ.get("RUN_RADIUS") != "1":
        return
    from radius_server import start_radius_thread
    from expiry import start_sweeper_thread
    start_radius_thread()
    start_sweeper_thread()


_maybe_start_background_threads()


if __name__ == "__main__":
    # Dev runner. Production = gunicorn with the threads started via the
    # on_starting hook in gunicorn.conf.py.
    if is_setup_complete():
        from radius_server import start_radius_thread
        from expiry import start_sweeper_thread
        start_radius_thread()
        start_sweeper_thread()
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)
