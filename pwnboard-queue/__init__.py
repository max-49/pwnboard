#!/usr/bin/env python3
'''
Initialize all the data and the config info
'''
from flask import Flask, g, session, redirect, url_for
import re
import os
import json
import redis
import logging
from functools import wraps
from argon2 import PasswordHasher
from markupsafe import Markup, escape
from .logging_handler import DBHandler
from .logger import logger
from .board_config import BOARD, TEAM_MAP, IP_SET
from .db import init_pool, init_schema, get_db_connection, close_db_connection

BOARD = BOARD
TEAM_MAP = TEAM_MAP
IP_SET = IP_SET

access_token_choice = os.environ.get("USE_ACCESS_TOKENS", "True")
if (access_token_choice.lower() in ("true", "t")):
    USE_ACCESS_TOKENS = True
else:
    USE_ACCESS_TOKENS = False

# Create the Flask app
app = Flask(__name__)
app.config['STATIC_FOLDER'] = "lib/static"
# Basic secret key for session support (override in production)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')
r = redis.StrictRedis(host="redis", port=6379, decode_responses=True)
ph = PasswordHasher()

# Basic pool initialization (safe to call multiple times)
init_pool()

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

default_user = os.environ.get("DEFAULT_USER", "admin")
default_password = os.environ.get("DEFAULT_USER_PASSWORD", "password")
init_schema(default_user=default_user, default_password_hash=ph.hash(default_password), default_password=default_password)
logger.addHandler(DBHandler())

def get_db():
    """Return a per-request PostgreSQL connection stored on flask.g."""
    return get_db_connection()


def get_logs_db():
    """Return a PostgreSQL connection for logs queries."""
    return get_db_connection()


def close_db(e=None):
    close_db_connection()

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

# Import routes from routes file
from . import routes
from . import endpoints
