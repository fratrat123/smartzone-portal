"""First-run setup wizard.

Renders a linear, multi-step form that collects everything the portal needs
to run, validates each step against real services where possible (SMTP, SZ
API, Cloudflare), and finally writes back to .env, sets SETUP_COMPLETE=true,
and exits so systemd restarts the process in normal mode.

The wizard is also reachable in normal mode for re-configuration — see the
admin "Re-run setup wizard" button, which flips SETUP_COMPLETE=false and
forces a restart.
"""
from flask import Blueprint, render_template

bp = Blueprint("setup", __name__, url_prefix="/setup")


@bp.route("/")
@bp.route("/welcome")
def welcome():
    return render_template("setup_welcome.html")
