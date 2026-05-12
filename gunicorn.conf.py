"""Gunicorn config — run RADIUS in master so only one listener exists."""
bind = "0.0.0.0:8080"
workers = 2
threads = 4
worker_class = "gthread"
timeout = 60


def on_starting(server):
    # Master process — start RADIUS once here, before workers fork.
    from radius_server import start_radius_thread
    start_radius_thread()
