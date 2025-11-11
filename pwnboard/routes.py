#!/usr/bin/env python3
import os
import logging
from flask import (request, render_template, make_response, Response, url_for,
                   redirect, abort, jsonify)
from flask import session
import sqlite3
import pandas as pd
from functools import wraps
from .data import getBoardDict, getEpoch, getAlert, saveData, saveCredData
from . import app, logger, r, BOARD, IP_SET, ph, get_db

# The cache of the main board page
try:
    BOARDCACHE_TIMEOUT = int(os.environ.get('CACHE_TIME', -1))  # -1 means disabled
except (TypeError, ValueError):
    BOARDCACHE_TIMEOUT = -1
BOARDCACHE = ""
BOARDCACHE_TIME = 0
BOARDCACHE_UPDATED = True

# Decorator to check to see if session args are set
def login_required(f):
    """Simple decorator that requires session['user'] to be set."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

@app.route("/", methods=['GET'])
def login():
    return render_template("login.html")

@app.route("/", methods=['POST'])
def login_post():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if not username or not password:
        return render_template('login.html', error='Username and password required')

    db = get_db()
    cur = db.execute('SELECT password, role FROM users WHERE username = ?;', (username,))
    row = cur.fetchone()
    if row is None:
        return render_template('login.html', error='Invalid username or password')

    stored = row['password']
    try:
        if ph.verify(stored, password):
            # Successful login: set session and redirect to index
            session['user'] = username
            session['role'] = row['role']
            return redirect(url_for('index'))
    except Exception:
        # verification failed (bad password or invalid hash)
        pass

    return render_template('login.html', error='Invalid username or password')

@app.route('/pwnboard', methods=['GET'])
@login_required
def index():
    '''
    Return the board with the most recent data (cached for 10 seconds)
    '''
    html = ""
    log = logging.getLogger('werkzeug')

    # Find the time since the last cache
    # The server will return the cache in two situations
    #  1. It has been less than 'cache_time' since the last cache
    #  2. There has been no new data since the last cache AND the cache is
    #     younger than 30 seconds
    if BOARDCACHE_TIMEOUT == -1:
        global BOARDCACHE
        global BOARDCACHE_TIME
        global BOARDCACHE_UPDATED
        ctime = getEpoch() - BOARDCACHE_TIME
        if (ctime < BOARDCACHE_TIMEOUT or
                (not BOARDCACHE_UPDATED and ctime < 30)):
            log.info("Pulling board html from cache")
            # return the cached dictionary
            return make_response(BOARDCACHE)
    # Get the board data and render the template
    error = getAlert()
    board = getBoardDict()
    theme = os.environ.get('PWN_THEME', "blue")
    html = render_template('index.html', error=error, theme=theme,
                           board=board, teams=BOARD['teams'])
    # Update the cache and the cache time
    if BOARDCACHE_TIMEOUT == -1:
        BOARDCACHE_TIME = getEpoch()
        BOARDCACHE = html
        BOARDCACHE_UPDATED = False
    return make_response(html)


@app.route('/checkin', methods=['POST'])
@app.route('/generic', methods=['POST'])
@app.route('/pwn', methods=['POST'])
def callback():
    """Handle when a server registers an callback"""
    data = request.get_json(force=True) or {}

    if 'challenge' in data:
        return data['challenge']
    data['last_seen'] = getEpoch()

    # Make sure 'application' is in the data
    if 'application' not in data and 'type' not in data:
        return "Invalid: Missing 'application' or 'type' in the request"

    if 'type' in data: data['application'] = data['type']

    if 'ips' in data and isinstance(data['ips'], list):
        for ip in data['ips']:
            d = dict(data)
            d['ip'] = ip
            if ip in IP_SET:
                saveData(d)
            else:
                return 'invalid IP\n'
    elif 'ip' in data:
        if data['ip'] in IP_SET:
            saveData(data)
        else:
            return 'invalid IP\n'
    else:
        return 'invalid POST\n'
    # Tell us that new data has come
    global BOARDCACHE_UPDATED
    BOARDCACHE_UPDATED = True
    return "valid\n"

@app.route('/creds', methods=['POST'])
def creds_callback():
    """Handle when a server registers a credential update"""
    data = request.get_json(force=True) or {}
    # data = {"ip": <ip>, "username": <username>, "password": <password>, "admin": 0/1} --> callback
    data['last_seen'] = getEpoch()
    # Make sure username and password are in the data
    if 'username' not in data and 'password' not in data:
        return "Invalid: Missing 'username' or 'password' in the request"
    
    if 'admin' in data:
        if data['admin'] not in [0,1]:
            return "Invalid: admin must be set to either 0 (not admin) or 1 (admin)"
    else:
        # -1 = unknown
        data['admin'] = -1

    if 'ips' in data and isinstance(data['ips'], list):
        for ip in data['ips']:
            d = dict(data)
            d['ip'] = ip
            if ip in IP_SET:
                saveCredData(d)
            else:
                return 'invalid IP\n'
    elif 'ip' in data:
        if data['ip'] in IP_SET:
            saveCredData(data)
        else:
            return 'invalid IP\n'
    else:
        return 'invalid POST\n'
    # Tell us that new data has come
    global BOARDCACHE_UPDATED
    BOARDCACHE_UPDATED = True
    return "valid\n"

@app.route('/install/<tool>/', methods=['GET'])
@app.route('/install/<tool>', methods=['GET'])
def installTools(tool):
    '''
    Returns a script that can be used as an installer for the specific tool.
    E.g. If you request '/install/empire' you will get a script to run that
    will update your empire with the needed functions
    '''
    host = os.environ.get("PWNBOARD_URL", "PWNBOARD_URL")
    # Try to render a template for the tool
    try:
        text = render_template('clients/{}.j2'.format(tool), server=host)
        logger.info("{} requested {} install script".format(
                                                request.remote_addr, tool))
        return Response(text+"\n", mimetype='text/plain')
    except Exception as E:
        print(E)
        abort(404)

@app.route("/graphs")
def callbacks():
    conn = sqlite3.connect("logs.db")
    df = pd.read_sql_query("SELECT * FROM logs", conn, parse_dates=["timestamp"])
    conn.close()

    # Optional: aggregate by minute and application
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    counts = df.groupby(["app", pd.Grouper(key="timestamp", freq="1min")]).size().unstack(0).fillna(0)

    # Convert to JSON for the frontend (so JS can plot it)
    graph_data = {
        "timestamps": counts.index.strftime("%Y-%m-%d %H:%M:%S").tolist(),
        "series": [
            {"name": app, "values": counts[app].tolist()} for app in counts.columns
        ],
    }

    return render_template("graphs.html", graph_data=graph_data)


@app.route('/manage_apps')
@login_required
def manage_apps():
    """Placeholder Manage Apps view."""
    return render_template('manage_apps.html')


@app.route('/account_settings')
@login_required
def account_settings():
    """Placeholder Account Settings view."""
    return render_template('account_settings.html')


@app.route('/manage_user_accounts')
@login_required
def manage_user_accounts():
    """Admin-only Manage User Accounts page."""
    # Only allow users with admin role
    if session.get('role') != 'admin':
        abort(403)
    return render_template('manage_user_accounts.html')