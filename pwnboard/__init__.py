#!/usr/bin/env python3
'''
Initialize all the data and the config info
'''
from flask import Flask, g
import re
import os
import json
import redis
import sqlite3
import logging
from os.path import isfile
from argon2 import PasswordHasher
from markupsafe import Markup, escape
from .logging_handler import DBHandler

BOARD = []
IP_SET = set()

# Load the board.json file
def loadBoard():
    global BOARD
    global IP_SET
    fil = os.environ.get("BOARD", "board.json")
    with open(fil) as fil:
        BOARD = json.load(fil)
    
    for row in BOARD.get("board", []):
        for host in row.get("hosts", []):
            ip = host.get("ip")
            if ip:
                IP_SET.add(ip)

# Create the Flask app
app = Flask(__name__)
app.config['STATIC_FOLDER'] = "lib/static"
# Basic secret key for session support (override in production)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')
logger = logging.getLogger('pwnboard')
loadBoard()

ph = PasswordHasher()

logfil = ""

# Get the pwnboard logger
# Create a log formatter
FMT = logging.Formatter(fmt="[%(asctime)s] %(levelname)s: %(message)s",
                        datefmt="%x %I:%M:%S")

# Create a file handler
if logfil != "":
    FH = logging.FileHandler(logfil)
    FH.setFormatter(FMT)
    logger.addHandler(FH)

# Create a console logging handler
SH = logging.StreamHandler()
SH.setFormatter(FMT)
logger.addHandler(SH)
logger.setLevel(logging.DEBUG)
logger.addHandler(DBHandler())

# Create the redis object. Make sure that we decode our responses
rserver = os.environ.get('REDIS_HOST', 'localhost')
rport = os.environ.get('REDIS_PORT', 6379)
r = redis.StrictRedis(host=rserver, port=int(rport), decode_responses=True)

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

# Initialize user database (use a short-lived connection for init)
USERS_DB = os.environ.get('USERS_DB', 'users.db')
with sqlite3.connect(USERS_DB) as _init_conn:
    _init_conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT
    )
    """)
    _init_conn.commit()

    default_user = os.environ.get("DEFAULT_USER", "admin")
    default_password = os.environ.get("DEFAULT_USER_PASSWORD", "password")

    cur = _init_conn.execute('SELECT username FROM users WHERE username = ?;', (default_user,))
    if cur.fetchone() is None:
        _init_conn.execute(
            'INSERT INTO users(username, password, role) VALUES (?, ?, "admin");',
            (default_user, ph.hash(default_password))
        )
        _init_conn.commit()


def get_db():
    """Return a per-request sqlite3 connection stored on flask.g."""
    if getattr(g, 'db', None) is None:
        g.db = sqlite3.connect(USERS_DB, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        try:
            g.db.execute("PRAGMA foreign_keys = ON")
            g.db.execute("PRAGMA busy_timeout = 5000")
        except Exception:
            pass
    return g.db


def close_db(e=None):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()
        delattr(g, 'db')

# Close DB when app is ended
app.teardown_appcontext(close_db)

# Import routes from routes file
from . import routes
