
from flask import request, session, jsonify, Response

from functools import wraps
import re
import csv
import io
import json
from .authentication import (
    changeUserPassword,
    createAccessToken,
    MAX_PASSWORD_LENGTH,
    USER_EXISTS,
    USER_SERVER_ERRORS,
    USERNAME_RE,
    VALID_ROLES,
    createUser,
    list_user_tokens,
    removeAccessToken,
    verifyAccessToken,
)
from ..core.board import IP_SET
from ..core.data import getEpoch, list_host_callbacks, list_host_creds
from ..core.db import dict_cursor
from ..core.info import MAX_KEY_LENGTH, MAX_VALUE_LENGTH, get_host_info
from ..core.logger import logger
from ..core.queues import CALLBACK_QUEUE, CREDS_QUEUE, INFO_QUEUE, redis_client

from .api_errors import api_error
from . import (
    app, get_db, api_admin_required, api_forbid_roles, api_login_required,
    PASSWORD_BLOCKED_ROLES, TOKEN_BLOCKED_ROLES, USE_ACCESS_TOKENS,
)

MAX_TOKEN_NAME_LENGTH = 64
MAX_APPLICATION_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 256

# Longest accepted value for each string field in beacon and credential payloads
PAYLOAD_STRING_LIMITS = {
    'ip': 45,
    'application': MAX_APPLICATION_LENGTH,
    'access_info': 2000,
    'username': 256,
    'password': 256,
}
# Extra limits for POST /info. They are not part of PAYLOAD_STRING_LIMITS because the other
# ingest endpoints accept (and ignore) fields with these names.
INFO_STRING_LIMITS = {'key': MAX_KEY_LENGTH, 'value': MAX_VALUE_LENGTH}
MAX_IPS_PER_REQUEST = 1000


def _read_payload():
    """Parse the request body as a JSON object. Returns (data, error_response)."""
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return None, ("Invalid: the request body must be a JSON object\n", 400)
    return data, None


def _check_payload_types(data, extra_limits=None):
    """Return an error response if a field has the wrong type or is too long, else None."""
    for field, limit in {**PAYLOAD_STRING_LIMITS, **(extra_limits or {})}.items():
        if field in data and (not isinstance(data[field], str) or len(data[field]) > limit):
            return f"Invalid: '{field}' must be a string of at most {limit} characters\n", 400
    ips = data.get('ips')
    if isinstance(ips, list):
        if len(ips) > MAX_IPS_PER_REQUEST:
            return f"Invalid: 'ips' can contain at most {MAX_IPS_PER_REQUEST} addresses\n", 400
        if not all(isinstance(ip, str) and len(ip) <= PAYLOAD_STRING_LIMITS['ip'] for ip in ips):
            return "Invalid: 'ips' must be a list of strings\n", 400
    return None


def _authorize():
    """Check the access token when tokens are enabled. Returns an error response, or None if allowed."""
    if not USE_ACCESS_TOKENS:
        return None

    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return "Not authorized. This server uses Access Tokens to authenticate requests!\n", 401

    parts = auth_header.split(' ')
    if parts[0].strip().lower() != "bearer" or len(parts) < 2 or not parts[1].strip():
        return "Please use Bearer Token (and Bearer keyword)\n", 401

    if not verifyAccessToken(parts[1].strip()):
        return "Not authorized! The access token is not valid or has expired.\n", 401
    return None


def _enqueue(queue, data):
    """Push the payload onto a Redis queue once per IP. Returns an error response, or None on success."""
    if 'ips' in data and isinstance(data['ips'], list):
        for ip in data['ips']:
            if ip not in IP_SET:
                return 'invalid IP\n', 400
            # Queue a copy for this IP without the full list of addresses
            item = {k: v for k, v in data.items() if k != 'ips'}
            item['ip'] = ip
            redis_client.lpush(queue, json.dumps(item))
    elif 'ip' in data:
        if data['ip'] not in IP_SET:
            return 'invalid IP\n', 400
        redis_client.lpush(queue, json.dumps(data))
    else:
        return 'invalid POST\n', 400
    return None


@app.route('/checkin', methods=['POST'])
@app.route('/pwn', methods=['POST'])
def callback():
    """Handle when a server registers an callback"""
    data, error = _read_payload()
    if error:
        return error

    if 'challenge' in data:
        # Plain text, so the echoed value is never rendered as HTML
        return Response(str(data['challenge']), mimetype='text/plain')
    data['last_seen'] = getEpoch()

    # Make sure 'application' is in the data
    if 'application' not in data:
        return "Invalid: Missing 'application' field in the request", 400

    error = _check_payload_types(data) or _authorize() or _enqueue(CALLBACK_QUEUE, data)
    if error:
        return error
    return "valid\n", 200


@app.route('/creds', methods=['POST'])
def creds_callback():
    """Handle when a server registers a credential update"""
    data, error = _read_payload()
    if error:
        return error
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

    error = _check_payload_types(data) or _authorize() or _enqueue(CREDS_QUEUE, data)
    if error:
        return error
    return "valid\n", 200


def _user_error(message):
    """Turn a message from createUser into the matching error response."""
    if message == USER_EXISTS:
        return api_error(409, 'user_exists', message)
    if message in USER_SERVER_ERRORS:
        return api_error(500, 'internal_error', message)
    return api_error(400, 'invalid_request', message)


@app.route('/info', methods=['POST'])
def info_callback():
    """Handle a tool attaching a key/value note to a host. An empty value deletes the note."""
    data, error = _read_payload()
    if error:
        return error

    if 'application' not in data or 'key' not in data or 'value' not in data:
        return "Invalid: Missing 'application', 'key' or 'value' in the request\n", 400

    error = _check_payload_types(data, INFO_STRING_LIMITS)
    if error:
        return error
    data['key'], data['value'] = data['key'].strip(), data['value'].strip()
    if not data['key']:
        return "Invalid: 'key' must not be empty\n", 400

    error = _authorize() or _enqueue(INFO_QUEUE, data)
    if error:
        return error
    return "valid\n", 200


@app.route('/hosts/<ip>/info', methods=['GET'])
@api_login_required
def host_info(ip):
    """The notes tools have attached to a host, for the dashboard's host popup."""
    if ip not in IP_SET:
        return api_error(404, 'not_found', 'Not found')
    return jsonify(get_host_info(get_db(), ip))


def _unauthenticated(message):
    response = api_error(401, 'unauthenticated', message)
    if USE_ACCESS_TOKENS:
        response.headers['WWW-Authenticate'] = 'Bearer'
    return response


def api_token_or_login_required(f):
    """For JSON endpoints that tools call: accept a bearer access token, or a login session.

    A request with an Authorization header is judged by its token alone, so a bad token is
    refused even if the caller is also logged in. Without the header, the session is used.
    When tokens are disabled (USE_ACCESS_TOKENS=false) the header is ignored and only a
    session works, because these endpoints return passwords and must never be open.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if USE_ACCESS_TOKENS and auth_header:
            scheme, _, token = auth_header.partition(' ')
            if scheme.strip().lower() != 'bearer' or not token.strip():
                return _unauthenticated('Use the header "Authorization: Bearer <access token>".')
            if not verifyAccessToken(token.strip()):
                return _unauthenticated('The access token is not valid or has expired.')
        elif not session.get('user'):
            if USE_ACCESS_TOKENS:
                return _unauthenticated('Send an access token as "Authorization: Bearer <access token>", or log in.')
            return _unauthenticated('You are not logged in.')
        return f(*args, **kwargs)
    return wrapper


def _active_only():
    """The ?active= filter: (True/False, None), or (None, error response) for a bad value."""
    value = request.args.get('active')
    if value is None:
        return False, None
    if value.lower() in ('true', 'false'):
        return value.lower() == 'true', None
    return None, api_error(400, 'invalid_request', "'active' must be true or false")


def _host_listing(ip, listing):
    """Answer with listing(db, ip, active_only) for a host on the board. Never cached."""
    active_only, error = _active_only()
    if error:
        return error
    if ip not in IP_SET:
        return api_error(404, 'not_found', 'Not found')
    response = jsonify(listing(get_db(), ip, active_only))
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/hosts/<ip>/callbacks', methods=['GET'])
@api_token_or_login_required
def host_callbacks(ip):
    """The callbacks recorded for a host, newest active first. ?active=true keeps only active ones."""
    return _host_listing(ip, list_host_callbacks)


@app.route('/hosts/<ip>/creds', methods=['GET'])
@api_token_or_login_required
def host_creds(ip):
    """The credentials recorded for a host, newest active first. ?active=true keeps only active ones."""
    return _host_listing(ip, list_host_creds)


@app.route('/admin/users', methods=['GET'])
@api_admin_required
def admin_list_users():
    """Return JSON list of users for admin UI."""
    db = get_db()
    with dict_cursor(db) as cur:
        cur.execute('SELECT username, role, extract(epoch from created_at)::bigint AS created '
                    'FROM users ORDER BY lower(username);')
        rows = cur.fetchall()
    return jsonify([{'username': r['username'], 'role': r['role'], 'created': r['created']} for r in rows])


@app.route('/admin/users', methods=['POST'])
@api_admin_required
def admin_create_user():
    """Create a new user. Expects form data: username, password, role."""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')
    if not username or not password:
        return api_error(400, 'invalid_request', 'Missing fields')
    # reuse authentication.createUser
    res = createUser(username, password, role)
    if res is True:
        return jsonify({'username': username, 'role': role}), 201
    # createUser returns an error string on failure
    return _user_error(res or 'Create failed')


@app.route('/admin/users/<username>', methods=['DELETE'])
@api_admin_required
def admin_delete_user(username):
    """Delete a user from PostgreSQL. Admin-only. Prevent deleting self."""
    username = username or ''
    username = username.strip()
    if not username:
        return api_error(400, 'invalid_request', 'Missing username')
    # prevent deleting yourself
    if session.get('user') == username:
        return api_error(400, 'invalid_request', 'Cannot delete current user')
    db = get_db()
    with db.cursor() as cur:
        cur.execute('SELECT 1 FROM users WHERE username = %s;', (username,))
        row = cur.fetchone()
    if row is None:
        return api_error(404, 'not_found', 'Not found')
    try:
        with db.cursor() as cur:
            cur.execute('DELETE FROM users WHERE username = %s;', (username,))
        db.commit()
        return ("", 204)
    except Exception:
        db.rollback()
        logger.exception('Failed to delete user %s', username)
        return api_error(500, 'internal_error', 'Error')


@app.route('/admin/users/<username>/tokens', methods=['GET'])
@api_admin_required
def admin_list_user_tokens(username):
    """Return token metadata for a specific user. Admin-only."""
    username = username or ''
    username = username.strip()
    if not username:
        return api_error(400, 'invalid_request', 'Missing username')
    with get_db().cursor() as cur:
        cur.execute('SELECT 1 FROM users WHERE username = %s;', (username,))
        if cur.fetchone() is None:
            return api_error(404, 'not_found', 'Not found')
    tokens = list_user_tokens(username)
    return jsonify(tokens)

@app.route('/tokens/create', methods=['POST'])
@api_forbid_roles(TOKEN_BLOCKED_ROLES, 'Your account cannot create access tokens.')
def create_token():
    token_name = request.form.get('token_name', '').strip()
    username = session.get('user')
    application = request.form.get('application', '').strip()
    description = request.form.get('description', '')
    if not token_name or len(token_name) > MAX_TOKEN_NAME_LENGTH:
        return api_error(400, 'invalid_request', f"Token name is required (max {MAX_TOKEN_NAME_LENGTH} characters)")
    if not application or len(application) > MAX_APPLICATION_LENGTH:
        return api_error(400, 'invalid_request', f"Application is required (max {MAX_APPLICATION_LENGTH} characters)")
    if len(description) > MAX_DESCRIPTION_LENGTH:
        return api_error(400, 'invalid_request', f"Description must be at most {MAX_DESCRIPTION_LENGTH} characters")
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
        return jsonify({'token': token}), 201
    return api_error(500, 'internal_error', 'Could not create the token')


@app.route('/tokens', methods=['GET'])
@api_forbid_roles(TOKEN_BLOCKED_ROLES, 'Your account cannot use access tokens.')
def list_tokens():
    username = session.get('user')
    tokens = list_user_tokens(username)
    return jsonify(tokens)


@app.route('/tokens/<token_hash>', methods=['DELETE'])
@api_forbid_roles(TOKEN_BLOCKED_ROLES, 'Your account cannot use access tokens.')
def delete_token_route(token_hash):
    # owner or admin may delete
    username = session.get('user')
    db = get_db()
    with dict_cursor(db) as cur:
        cur.execute('SELECT username FROM access_tokens WHERE token_hash = %s;', (token_hash,))
        meta = cur.fetchone()
    if not meta:
        return api_error(404, 'not_found', 'Not found')

    owner = meta.get('username')
    if owner != username and session.get('role') != 'admin':
        return api_error(403, 'forbidden', 'You can only delete your own tokens.')
    ok = removeAccessToken(token_hash)
    if ok:
        return ("", 204)
    return api_error(500, 'internal_error', 'Error')


@app.route('/admin/users/bulk_csv_template', methods=['GET'])
@api_admin_required
def admin_bulk_csv_template():
    """Return a CSV template file for bulk user creation."""
    template = "username,password,role\nexample_user,securepassword,user\n"
    return Response(
        template,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=users_template.csv'}
    )


@app.route('/admin/users/bulk', methods=['POST'])
@api_admin_required
def admin_bulk_create_users():
    """Bulk create users from comma-separated usernames with a shared password and role."""
    usernames_raw = request.form.get('usernames', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')

    if not usernames_raw or not password:
        return api_error(400, 'invalid_request', 'Missing fields')

    if role not in VALID_ROLES:
        return api_error(400, 'invalid_request', 'Invalid role')

    usernames = [u.strip() for u in usernames_raw.split(',')]
    usernames = [u for u in usernames if u]

    if not usernames:
        return api_error(400, 'invalid_request', 'No valid usernames provided')

    errors = []
    for uname in usernames:
        if not USERNAME_RE.match(uname):
            errors.append(f"Invalid username {uname!r}: only letters, digits, _, ., - are allowed (max 64 characters)")

    if errors:
        return api_error(400, 'validation_failed', 'Some usernames are invalid. No users were created.', errors)

    results = {'created': [], 'failed': []}
    for uname in usernames:
        res = createUser(uname, password, role)
        if res is True:
            results['created'].append(uname)
        else:
            results['failed'].append({'username': uname, 'error': res or 'Create failed'})

    return jsonify(results), 200


@app.route('/admin/users/bulk_csv', methods=['POST'])
@api_admin_required
def admin_bulk_create_users_csv():
    """Bulk create users from a CSV file upload. Validates entire file before creating any users."""
    if 'file' not in request.files:
        return api_error(400, 'invalid_request', 'No file uploaded')

    f = request.files['file']
    if not f.filename:
        return api_error(400, 'invalid_request', 'No file selected')

    try:
        content = f.read().decode('utf-8')
    except Exception:
        return api_error(400, 'invalid_request', 'Could not decode file as UTF-8')

    try:
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
    except Exception as e:
        return api_error(400, 'invalid_request', f"Failed to parse CSV: {e}")

    if not rows:
        return api_error(400, 'invalid_request', 'CSV file is empty')

    header = [h.strip().lower() for h in rows[0]]
    if header != ['username', 'password', 'role']:
        return api_error(400, 'invalid_request',
                         'Invalid header. The CSV must have exactly these columns in order: username,password,role')

    if len(rows) < 2:
        return api_error(400, 'invalid_request', 'CSV contains no data rows')

    errors = []
    for i, row in enumerate(rows[1:], start=2):
        if len(row) != 3:
            errors.append(f"Row {i}: expected 3 columns, got {len(row)}")
            continue
        uname, passwd, role = [v.strip() for v in row]
        if not uname:
            errors.append(f"Row {i}: username is empty")
        elif not USERNAME_RE.match(uname):
            errors.append(f"Row {i}: invalid username {uname!r} (only letters, digits, _, ., - allowed, max 64 characters)")
        if not passwd:
            errors.append(f"Row {i}: password is empty")
        elif len(passwd) > MAX_PASSWORD_LENGTH:
            errors.append(f"Row {i}: password must be between 1 and {MAX_PASSWORD_LENGTH} characters")
        if role not in VALID_ROLES:
            errors.append(f"Row {i}: invalid role {role!r} (must be one of: {', '.join(sorted(VALID_ROLES))})")

    if errors:
        return api_error(400, 'validation_failed', 'The CSV file has errors. No users were created.', errors)

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
@api_forbid_roles(PASSWORD_BLOCKED_ROLES, 'Your account cannot change its password.')
def account_change_password():
    username = session.get('user')
    old_pass = request.form.get('old_pass', '')
    new_pass = request.form.get('new_pass', '')
    if not old_pass or not new_pass:
        return api_error(400, 'invalid_request', 'Missing fields')
    if len(new_pass) > MAX_PASSWORD_LENGTH:
        return api_error(400, 'invalid_request', f"Password must be at most {MAX_PASSWORD_LENGTH} characters")
    ok = changeUserPassword(username, old_pass, new_pass)
    if ok:
        # invalidate the session so the user must re-authenticate after password change
        try:
            session.clear()
        except Exception:
            pass
        return jsonify({'message': 'Password changed'})
    return api_error(400, 'invalid_request', 'Password change failed')
