#!/usr/bin/env python3
from flask import request, session, render_template, make_response, url_for, redirect, abort

import os
import logging
import pandas as pd

from .authentication import verifyUser
from .data import getBoardDict, getEpoch, getAlert
from . import app, BOARD, get_logs_db, login_required, admin_required

# The cache of the main board page
try:
    BOARDCACHE_TIMEOUT = int(os.environ.get('CACHE_TIME', -1))  # -1 means disabled
except (TypeError, ValueError):
    BOARDCACHE_TIMEOUT = -1
BOARDCACHE = ""
BOARDCACHE_TIME = 0
BOARDCACHE_UPDATED = True

@app.route("/", methods=['GET'])
def login():
    # If already authenticated, redirect to dashboard
    if session.get('user'):
        return redirect(url_for('index'))
    return render_template("login.html")

@app.route("/", methods=['POST'])
def login_post():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if not username or not password:
        return render_template('login.html', error='Username and password required')
    
    login_res = verifyUser(username, password)
    if login_res:
        session['user'] = login_res[0]
        session['role'] = login_res[1]
        return redirect(url_for('index'))
    else:
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

# @app.route('/install/<tool>/', methods=['GET'])
# @app.route('/install/<tool>', methods=['GET'])
# def installTools(tool):
#     '''
#     Returns a script that can be used as an installer for the specific tool.
#     E.g. If you request '/install/empire' you will get a script to run that
#     will update your empire with the needed functions
#     '''
#     host = os.environ.get("PWNBOARD_URL", "PWNBOARD_URL")
#     # Try to render a template for the tool
#     try:
#         text = render_template('clients/{}.j2'.format(tool), server=host)
#         logger.info("{} requested {} install script".format(
#                                                 request.remote_addr, tool))
#         return Response(text+"\n", mimetype='text/plain')
#     except Exception as E:
#         print(E)
#         abort(404)

@app.route("/graphs")
@login_required
def callbacks():
    # Read logs and build a time-series of callback counts per application.
    # We adapt the resampling frequency based on the total time span so the
    # chart remains readable for short and long time ranges.
    try:
        conn = get_logs_db()
        df = pd.read_sql_query("SELECT * FROM logs", conn, parse_dates=["timestamp"])
    except Exception:
        # If the DB is missing/corrupt, render an empty chart
        df = pd.DataFrame(columns=["timestamp", "app"])

    if df.empty:
        graph_data = {"timestamps": [], "series": []}
        return render_template("graphs.html", graph_data=graph_data)

    # Ensure timestamp is a datetime and sorted
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")

    start = df["timestamp"].min()
    end = df["timestamp"].max()
    span = end - start

    # Choose an appropriate resample frequency based on span
    if span <= pd.Timedelta(days=2):
        freq = '1min'
    elif span <= pd.Timedelta(days=14):
        freq = '15min'
    elif span <= pd.Timedelta(days=90):
        freq = '1H'
    else:
        freq = '1D'

    # Pivot into a time-indexed table of counts per application, resampled to the chosen freq
    try:
        counts = (df.set_index('timestamp')
                    .groupby([pd.Grouper(freq=freq), 'app'])
                    .size()
                    .unstack(fill_value=0)
                    .sort_index())
    except Exception:
        # Fallback to minute-level grouping if something goes wrong
        counts = df.groupby(['app', pd.Grouper(key='timestamp', freq='1min')]).size().unstack(0).fillna(0)

    # Ensure a deterministic ordering of apps (columns)
    apps = list(counts.columns)

    # Convert timestamps to ISO-like strings for the frontend
    timestamps = [ts.strftime("%Y-%m-%d %H:%M:%S") for ts in counts.index]

    series = []
    for app_name in apps:
        series.append({
            'name': app_name,
            'values': counts[app_name].tolist()
        })

    graph_data = {"timestamps": timestamps, "series": series}
    return render_template("graphs.html", graph_data=graph_data)


@app.route('/manage_apps')
@login_required
def manage_apps():
    # Guests are not allowed to manage apps or create tokens
    if session.get('role') == 'guest' or session.get('role') == 'restricted':
        abort(403)
    return render_template('manage_apps.html')


@app.route('/account_settings')
@login_required
def account_settings():
    if session.get('role') == 'restricted':
        abort(403)
    return render_template('account_settings.html')


@app.route('/manage_user_accounts')
@login_required
@admin_required
def manage_user_accounts():
    """Admin-only Manage User Accounts page."""
    # Only allow users with admin role
    if session.get('role') != 'admin':
        abort(403)
    return render_template('manage_user_accounts.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))