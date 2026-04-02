
from flask import request, session, jsonify, Response

import re
import csv
import io
from .authentication import *
from .data import getEpoch, saveData, saveCredData
from .routes import mark_board_cache_dirty

from . import app, logger, r, IP_SET, get_db, login_required, admin_required, USE_ACCESS_TOKENS

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
        return "Invalid: Missing 'application' or 'type' in the request", 400

    if 'type' in data: data['application'] = data['type']

    if USE_ACCESS_TOKENS:
        auth_header = request.headers.get('Authorization')

        if not auth_header:
            return "Not authorized\n", 401

        
        auth_header_split = auth_header.split(' ')
        if auth_header_split[0].strip().lower() != "bearer":
            return "Please use Bearer Token\n", 401
        
        token = auth_header_split[1].strip()

        verification = verifyAccessToken(token, data['application'])

        if (verification == False):
            return "Not authorized\n", 401

    if 'ips' in data and isinstance(data['ips'], list):
        for ip in data['ips']:
            d = dict(data)
            d['ip'] = ip
            if ip in IP_SET:
                saveData(d)
            else:
                return 'invalid IP\n', 400
    elif 'ip' in data:
        if data['ip'] in IP_SET:
            saveData(data)
        else:
            return 'invalid IP\n', 400
    else:
        return 'invalid POST\n', 400
    # Tell routes cache that new data has come in
    mark_board_cache_dirty()
    return "valid\n"

@app.route('/creds', methods=['POST'])
def creds_callback():
    """Handle when a server registers a credential update"""
    data = request.get_json(force=True) or {}
    # data = {"ip": <ip>, "username": <username>, "password": <password>, "admin": 0/1} --> callback
    data['last_seen'] = getEpoch()
    # Make sure username and password are in the data
    if 'username' not in data or 'password' not in data or 'application' not in data:
        return "Invalid: Missing 'username', 'password', or 'application' in the request\n", 400
    
    if 'admin' in data:
        if data['admin'] not in [0,1]:
            return "Invalid: admin must be set to either 0 (not admin) or 1 (admin)\n", 400
    else:
        # -1 = unknown
        data['admin'] = -1

        auth_header = request.headers.get('Authorization')

    if not auth_header:
        return "Not authorized\n", 401

    token = auth_header.split(' ')[1]

    verification = verifyAccessToken(token, data['application'])

    if (verification == False):
        return "Not authorized\n", 401

    if 'ips' in data and isinstance(data['ips'], list):
        for ip in data['ips']:
            d = dict(data)
            d['ip'] = ip
            if ip in IP_SET:
                saveCredData(d)
            else:
                return 'invalid IP\n', 400
    elif 'ip' in data:
        if data['ip'] in IP_SET:
            saveCredData(data)
        else:
            return 'invalid IP\n', 400
    else:
        return 'invalid POST\n', 400
    # Tell routes cache that new data has come in
    mark_board_cache_dirty()
    return "valid\n"

@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def admin_list_users():
    """Return JSON list of users for admin UI."""
    db = get_db()
    cur = db.execute('SELECT username, role FROM users ORDER BY username COLLATE NOCASE;')
    rows = cur.fetchall()
    out = []
    for r in rows:
        out.append({
            'username': r['username'],
            'role': r['role']
        })
    return jsonify(out)


@app.route('/admin/users', methods=['POST'])
@login_required
@admin_required
def admin_create_user():
    """Create a new user. Expects form data: username, password, role."""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')
    if not username or not password:
        return ("Missing fields", 400)
    # reuse authentication.createUser
    res = createUser(username, password, role)
    if res is True:
        return ("", 201)
    else:
        # createUser returns an error string on failure
        return (res or 'Create failed', 400)


@app.route('/admin/users/<username>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_user(username):
    """Delete a user from the sqlite users DB. Admin-only. Prevent deleting self."""
    username = username or ''
    username = username.strip()
    if not username:
        return ("Missing username", 400)
    # prevent deleting yourself
    if session.get('user') == username:
        return ("Cannot delete current user", 400)
    db = get_db()
    cur = db.execute('SELECT 1 FROM users WHERE username = ?;', (username,))
    if cur.fetchone() is None:
        return ("Not found", 404)
    try:
        db.execute('DELETE FROM users WHERE username = ?;', (username,))
        db.commit()
        return ("", 204)
    except Exception as e:
        logger.exception('Failed to delete user %s', username)
        return ("Error", 500)


@app.route('/admin/users/<username>/tokens', methods=['GET'])
@login_required
@admin_required
def admin_list_user_tokens(username):
    """Return token metadata for a specific user. Admin-only."""
    username = username or ''
    username = username.strip()
    if not username:
        return ("Missing username", 400)
    tokens = list_user_tokens(username)
    return jsonify(tokens)

@app.route('/tokens/create', methods=['POST'])
@login_required
def create_token():
    token_name = request.form.get('token_name', '').strip()
    username = session.get('user')
    # Guests may not create access tokens
    if session.get('role') == 'guest':
        return ("Forbidden", 403)
    application = request.form.get('application', '').strip()
    description = request.form.get('description', '')
    expiry = request.form.get('expiry', '7d')
    # parse expiry like '30m', '5d', '1h', '6mo' into seconds; default 7 days
    seconds_map = {'m': 60, 'h': 3600, 'd': 86400, 'w': 604800, 'mo': 2592000, 'y': 31536000}
    expire_after = None
    try:
        m = re.match(r'^(\d+)\s*([a-zA-Z]+)?$', (expiry or '').strip())
        if m:
            num = int(m.group(1))
            unit = (m.group(2) or '').lower()
            if unit == '':
                expire_after = num
            elif unit in seconds_map:
                expire_after = num * seconds_map[unit]
            else:
                # fallback default
                expire_after = 7 * 86400
        else:
            expire_after = 7 * 86400
    except Exception:
        expire_after = 7 * 86400

    token = createAccessToken(token_name, username, application, description, expires_after=expire_after)
    if token:
        return jsonify({'token': token})
    else:
        return ("", 500)


@app.route('/tokens', methods=['GET'])
@login_required
def list_tokens():
    username = session.get('user')
    tokens = list_user_tokens(username)
    return jsonify(tokens)


@app.route('/tokens/<token_hash>', methods=['DELETE'])
@login_required
def delete_token_route(token_hash):
    # owner or admin may delete
    username = session.get('user')
    data = r.get(f"token:{token_hash}")
    if not data:
        return ("Not found", 404)
    try:
        meta = json.loads(str(data))
    except Exception:
        return ("Invalid token", 500)
    owner = meta.get('username')
    if owner != username and session.get('role') != 'admin':
        return ("Forbidden", 403)
    ok = removeAccessToken(token_hash)
    if ok:
        return ("", 204)
    return ("Error", 500)


@app.route('/admin/users/bulk_csv_template', methods=['GET'])
@login_required
@admin_required
def admin_bulk_csv_template():
    """Return a CSV template file for bulk user creation."""
    template = "username,password,role\nexample_user,securepassword,user\n"
    return Response(
        template,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=users_template.csv'}
    )


@app.route('/admin/users/bulk', methods=['POST'])
@login_required
@admin_required
def admin_bulk_create_users():
    """Bulk create users from comma-separated usernames with a shared password and role."""
    usernames_raw = request.form.get('usernames', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')

    if not usernames_raw or not password:
        return ("Missing fields", 400)

    valid_roles = {'user', 'admin', 'guest', 'restricted'}
    if role not in valid_roles:
        return ("Invalid role", 400)

    USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.\-]+$')
    usernames = [u.strip() for u in usernames_raw.split(',')]
    usernames = [u for u in usernames if u]

    if not usernames:
        return ("No valid usernames provided", 400)

    errors = []
    for uname in usernames:
        if not USERNAME_RE.match(uname):
            errors.append(f"Invalid username {uname!r}: only letters, digits, _, ., - are allowed")

    if errors:
        return ("\n".join(errors), 400)

    results = {'created': [], 'failed': []}
    for uname in usernames:
        res = createUser(uname, password, role)
        if res is True:
            results['created'].append(uname)
        else:
            results['failed'].append({'username': uname, 'error': res or 'Create failed'})

    return jsonify(results), 200


@app.route('/admin/users/bulk_csv', methods=['POST'])
@login_required
@admin_required
def admin_bulk_create_users_csv():
    """Bulk create users from a CSV file upload. Validates entire file before creating any users."""
    if 'file' not in request.files:
        return ("No file uploaded", 400)

    f = request.files['file']
    if not f.filename:
        return ("No file selected", 400)

    try:
        content = f.read().decode('utf-8')
    except Exception:
        return ("Could not decode file as UTF-8", 400)

    USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.\-]+$')
    PASSWORD_RE = re.compile(r'^.{1,128}$')
    VALID_ROLES = {'user', 'admin', 'guest', 'restricted'}

    try:
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
    except Exception as e:
        return (f"Failed to parse CSV: {e}", 400)

    if not rows:
        return ("CSV file is empty", 400)

    header = [h.strip().lower() for h in rows[0]]
    if header != ['username', 'password', 'role']:
        return ("Invalid header. The CSV must have exactly these columns in order: username,password,role", 400)

    if len(rows) < 2:
        return ("CSV contains no data rows", 400)

    errors = []
    for i, row in enumerate(rows[1:], start=2):
        if len(row) != 3:
            errors.append(f"Row {i}: expected 3 columns, got {len(row)}")
            continue
        uname, passwd, role = [v.strip() for v in row]
        if not uname:
            errors.append(f"Row {i}: username is empty")
        elif not USERNAME_RE.match(uname):
            errors.append(f"Row {i}: invalid username {uname!r} (only letters, digits, _, ., - allowed)")
        if not passwd:
            errors.append(f"Row {i}: password is empty")
        elif not PASSWORD_RE.match(passwd):
            errors.append(f"Row {i}: password must be between 1 and 128 characters")
        if role not in VALID_ROLES:
            errors.append(f"Row {i}: invalid role {role!r} (must be one of: {', '.join(sorted(VALID_ROLES))})")

    if errors:
        return jsonify({'errors': errors}), 400

    results = {'created': [], 'failed': []}
    for row in rows[1:]:
        uname, passwd, role = [v.strip() for v in row]
        res = createUser(uname, passwd, role)
        if res is True:
            results['created'].append(uname)
        else:
            results['failed'].append({'username': uname, 'error': res or 'Create failed'})

    return jsonify(results), 200


@app.route('/account/change_password', methods=['POST'])
@login_required
def account_change_password():
    username = session.get('user')
    old_pass = request.form.get('old_pass', '')
    new_pass = request.form.get('new_pass', '')
    if not old_pass or not new_pass:
        return ("Missing fields", 400)
    ok = changeUserPassword(username, old_pass, new_pass)
    if ok:
        # invalidate the session so the user must re-authenticate after password change
        try:
            session.clear()
        except Exception:
            pass
        return ("Password changed", 200)
    return ("Password change failed", 400)

