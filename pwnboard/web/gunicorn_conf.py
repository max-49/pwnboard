"""Gunicorn settings, loaded with `-c python:pwnboard.web.gunicorn_conf`."""
import os

from .startup import initialize

bind = f"0.0.0.0:{os.environ.get('FLASK_PORT', '5000')}"
workers = 3
threads = 4


def on_starting(server):
    # Runs once in the master process, before any worker is forked
    initialize()
