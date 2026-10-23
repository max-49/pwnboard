#!/usr/bin/env python3
'''
Flask web app: dashboard, login, token and user management, and the beacon/creds endpoints
'''
from flask import Flask, g, session, redirect, request, url_for
import re
import os
from datetime import timedelta
from functools import wraps
from argon2 import PasswordHasher
from markupsafe import Markup, escape
from werkzeug.exceptions import HTTPException, InternalServerError
from werkzeug.middleware.proxy_fix import ProxyFix
from ..core.db import get_pool
from ..core.logger import logger
from .api_errors import api_error

access_token_choice = os.environ.get("USE_ACCESS_TOKENS", "True")
if (access_token_choice.lower() in ("true", "t")):
    USE_ACCESS_TOKENS = True
else:
    USE_ACCESS_TOKENS = False

# Create the Flask app
app = Flask(__name__)
# Basic secret key for session support (override in production)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')
# Reject request bodies over 1 MB (beacon payloads are tiny; this also bounds CSV uploads)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
# Caddy is the only thing that talks to this app, so trust its X-Forwarded-For header for the client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

# Session cookies: HTTPS only (except in debug mode, for http://localhost), not sent on cross-site POSTs
app.config['SESSION_COOKIE_SECURE'] = os.environ.get("FLASK_DEBUG", "false").lower().strip() not in ("true", "yes", "1", "t")
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Logins expire after 12 hours without activity
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
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

# Roles that may not use a feature. The pages and the API both use these, so they cannot disagree.
TOKEN_BLOCKED_ROLES = frozenset({'guest', 'restricted'})
PASSWORD_BLOCKED_ROLES = frozenset({'restricted'})

def api_login_required(f):
    """Like login_required, for JSON endpoints: answers 401 instead of redirecting to the login page."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user'):
            return api_error(401, 'unauthenticated', 'You are not logged in.')
        return f(*args, **kwargs)
    return wrapper

def api_admin_required(f):
    """Like admin_required, for JSON endpoints. Also checks that the user is logged in."""
    @wraps(f)
    @api_login_required
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            return api_error(403, 'forbidden', 'This requires the admin role.')
        return f(*args, **kwargs)
    return wrapper

def api_forbid_roles(blocked_roles, message):
    """Decorator for JSON endpoints that answers 403 for users whose role is in blocked_roles."""
    def decorator(f):
        @wraps(f)
        @api_login_required
        def wrapper(*args, **kwargs):
            if session.get('role') in blocked_roles:
                return api_error(403, 'forbidden', message)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def _client_wants_html():
    """True for browsers, which list text/html explicitly. curl and scripts send */* or JSON."""
    return any(mimetype == 'text/html' for mimetype, _quality in request.accept_mimetypes)

@app.errorhandler(HTTPException)
def handle_http_error(error):
    """JSON errors for API clients (404, 405, 413, ...). Browsers still get the normal HTML page."""
    if error.code is None or error.code < 400 or _client_wants_html():
        return error
    return api_error(error.code, error.name.lower().replace(' ', '_'), error.description or error.name)

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if app.debug:
        raise error  # keep Flask's interactive debugger in development
    logger.exception('Unhandled error on %s %s', request.method, request.path)
    return handle_http_error(InternalServerError())

# Import routes from routes file (imported for their route registrations)
from . import routes  # noqa: E402,F401
from . import endpoints  # noqa: E402,F401
