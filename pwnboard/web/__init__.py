#!/usr/bin/env python3
'''
Flask web app: dashboard, login, token and user management, and the beacon/creds endpoints
'''
from flask import Flask, g, session, redirect, url_for
import re
import os
from functools import wraps
from argon2 import PasswordHasher
from markupsafe import Markup, escape
from ..core.db import get_pool

access_token_choice = os.environ.get("USE_ACCESS_TOKENS", "True")
if (access_token_choice.lower() in ("true", "t")):
    USE_ACCESS_TOKENS = True
else:
    USE_ACCESS_TOKENS = False

# Create the Flask app
app = Flask(__name__)
# Basic secret key for session support (override in production)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')
ph = PasswordHasher()

# Simple linkify filter: convert http(s) URLs inside a string into clickable links
# Returns Markup so it's safe to render in templates
URL_RE = re.compile(r'(https?://[^\s]+)')

def linkify(text):
    if not text:
        return ''
    # Build the output by escaping non-URL parts and replacing URLs with anchors
    parts = []
    last_end = 0
    for m in URL_RE.finditer(text):
        start, end = m.start(), m.end()
        # escape text between matches
        parts.append(escape(text[last_end:start]))
        url = m.group(0)
        # escape url for safe insertion into href/text
        esc_url = escape(url)
        parts.append('<a href="{0}" target="_blank" rel="noopener noreferrer">{1}</a>'.format(esc_url, esc_url))
        last_end = end

    # append the remainder
    parts.append(escape(text[last_end:]))
    return Markup(''.join(parts))

# Register the filter with Jinja environment
app.jinja_env.filters['linkify'] = linkify

# Linked from the dashboard menu and the Manage Apps page
app.jinja_env.globals['USAGE_GUIDE_URL'] = "https://github.com/max-49/pwnboard/blob/main/doc/usage.md"

def get_db():
    """Return a per-request PostgreSQL connection stored on flask.g."""
    if getattr(g, "db", None) is None:
        g.db = get_pool().getconn()
    return g.db


def close_db(e=None):
    conn = getattr(g, "db", None)
    if conn is not None:
        try:
            try:
                conn.rollback()
            except Exception:
                pass
            get_pool().putconn(conn)
        finally:
            delattr(g, "db")

# Close DB when app is ended
app.teardown_appcontext(close_db)

# Decorator to check to see if session args are set
def login_required(f):
    """Simple decorator that requires session['user'] to be set."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    """Decorator to require an admin role for API endpoints."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return ("Forbidden", 403)
        return f(*args, **kwargs)
    return wrapper

# Import routes from routes file (imported for their route registrations)
from . import routes  # noqa: E402,F401
from . import endpoints  # noqa: E402,F401
