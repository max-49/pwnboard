#!/usr/bin/env python3
from flask import request, session, render_template, make_response, send_file, url_for, redirect, abort

import os
import logging
import json
from pathlib import Path

from .authentication import verifyUser
from ..core.board import BOARD
from ..core.data import getBoardDict
from ..core.logger import logger
from ..core.queues import BOARD_CACHE_KEY, redis_client
from . import (
    app, get_db, login_required, admin_required, login_throttle,
    PASSWORD_BLOCKED_ROLES, TOKEN_BLOCKED_ROLES, USE_ACCESS_TOKENS,
)

OPENAPI_SPEC = Path(__file__).parent / "openapi.yaml"

LOGIN_PAGE_MESSAGE = os.environ.get("LOGIN_PAGE_MESSAGE", "Contact an admin to make an account!")
REFRESH_SECONDS = os.environ.get("REFRESH_SECONDS", 10)

@app.route("/", methods=['GET'])
def login():
    # If already authenticated, redirect to dashboard
    if session.get('user'):
        return redirect(url_for('index'))
    return render_template("login.html", LOGIN_PAGE_MESSAGE=LOGIN_PAGE_MESSAGE)

@app.route("/", methods=['POST'])
def login_post():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    if not username or not password:
        return render_template('login.html', LOGIN_PAGE_MESSAGE=LOGIN_PAGE_MESSAGE, error='Username and password required')
    
    client_ip = request.remote_addr or 'unknown'
    if login_throttle.is_blocked(client_ip, username):
        logger.warning("Blocked login attempt for %r from %s: too many recent failures", username, client_ip)
        return render_template('login.html', LOGIN_PAGE_MESSAGE=LOGIN_PAGE_MESSAGE,
                               error='Too many failed login attempts. Try again in 15 minutes.'), 429

    login_res = verifyUser(username, password)
    if login_res:
        login_throttle.clear_username_failures(username)
        session.permanent = True
        session['user'] = login_res[0]
        session['role'] = login_res[1]
        return redirect(url_for('index'))
    else:
        login_throttle.record_failure(client_ip, username)
        return render_template('login.html', LOGIN_PAGE_MESSAGE=LOGIN_PAGE_MESSAGE, error='Invalid username or password')

@app.route('/pwnboard', methods=['GET'])
@login_required
def index():
    log = logging.getLogger('werkzeug')
    board = None
    error = None

    cached_board_str = redis_client.get(BOARD_CACHE_KEY)
    if cached_board_str:
        log.info("Pulling board data from Redis cache")
        board = json.loads(cached_board_str)
    else:
        log.info("Redis cache empty, generating board from database")
        board = getBoardDict(get_db())
    
    # Always render HTML per-request so session-specific navbar data stays accurate
    theme = os.environ.get('PWN_THEME', "blue")
    html = render_template('index.html', error=error, theme=theme,
                           board=board, teams=BOARD['teams'], refresh_seconds=REFRESH_SECONDS)
    return make_response(html)

@app.route('/openapi.yaml', methods=['GET'])
def openapi_spec():
    """The OpenAPI description of the API. Public, like the usage guide."""
    return send_file(OPENAPI_SPEC, mimetype='application/yaml')

@app.route('/manage_apps')
@login_required
def manage_apps():
    # The same rule the token API endpoints enforce
    if session.get('role') in TOKEN_BLOCKED_ROLES:
        abort(403)
    return render_template('manage_apps.html', USE_ACCESS_TOKENS=str(USE_ACCESS_TOKENS).upper())


@app.route('/account_settings')
@login_required
def account_settings():
    # The same rule the change-password API endpoint enforces
    if session.get('role') in PASSWORD_BLOCKED_ROLES:
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