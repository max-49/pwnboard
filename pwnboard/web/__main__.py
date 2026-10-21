#!/usr/bin/env python3
"""Development server: `python3 -m pwnboard.web` (production uses gunicorn)."""
import os

from . import app
from .startup import initialize

if __name__ == '__main__':
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", 80))
    debug = os.environ.get("FLASK_DEBUG", "false")
    debug = debug.lower().strip() in ["true", "yes", "1", "t"]
    initialize()
    app.run(host=host, debug=debug, port=port)
