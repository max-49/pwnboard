#!/usr/bin/env python3
from flask import request, session, render_template, make_response, url_for, redirect, abort

import os
import logging
import copy
import json

from .authentication import verifyUser
from .data import getBoardDict, getEpoch
from . import app, BOARD, r, login_required, admin_required, USE_ACCESS_TOKENS

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
    
    login_res = verifyUser(username, password)
    if login_res:
        session['user'] = login_res[0]
        session['role'] = login_res[1]
        return redirect(url_for('index'))
    else:
        return render_template('login.html', LOGIN_PAGE_MESSAGE=LOGIN_PAGE_MESSAGE, error='Invalid username or password')

@app.route('/pwnboard', methods=['GET'])
@login_required
def index():
    log = logging.getLogger('werkzeug')
    board = None
    error = None

    cached_board_str = r.get('board_cache')
    if cached_board_str:
        log.info("Pulling board data from Redis cache")
        board = json.loads(cached_board_str)
    else:
        log.info("Redis cache empty, generating board from database")
        board = getBoardDict()
    
    # Always render HTML per-request so session-specific navbar data stays accurate
    theme = os.environ.get('PWN_THEME', "blue")
    html = render_template('index.html', error=error, theme=theme,
                           board=board, teams=BOARD['teams'], refresh_seconds=REFRESH_SECONDS)
    return make_response(html)

@app.route('/manage_apps')
@login_required
def manage_apps():
    # Guests are not allowed to manage apps or create tokens
    if session.get('role') == 'guest' or session.get('role') == 'restricted':
        abort(403)
    return render_template('manage_apps.html', USE_ACCESS_TOKENS=str(USE_ACCESS_TOKENS).upper())


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