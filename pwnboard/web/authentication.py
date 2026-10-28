#!/usr/bin/env python3
import re
import secrets
import hashlib
import time

from . import ph, get_db
from ..core.db import dict_cursor
from ..core.logger import logger

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_.\-]{1,64}$')
VALID_ROLES = {'user', 'admin', 'guest', 'restricted'}
MAX_PASSWORD_LENGTH = 128
# Longer than any password we accept; anything beyond it is rejected without hashing
MAX_LOGIN_PASSWORD_LENGTH = 1024

# Messages createUser returns, which the endpoints turn into status codes
USER_EXISTS = "User already exists"
USER_SERVER_ERRORS = ("Password hashing failed", "Create failed")

# Verified against when a username does not exist, so a failed login does the same
# amount of hashing work whether or not the account is real
_DUMMY_HASH = ph.hash("pwnboard-dummy-password")

def _hash_token(raw_token):
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()

def createUser(username, password, role):
    if not USERNAME_RE.match(username):
        return "Invalid username: only letters, digits, _, ., - are allowed (max 64 characters)"
    if role not in VALID_ROLES:
        return "Invalid role"
    if not 1 <= len(password) <= MAX_PASSWORD_LENGTH:
        return f"Password must be between 1 and {MAX_PASSWORD_LENGTH} characters"

    db = get_db()

    # Check if the user already exists
    with db.cursor() as cur:
        cur.execute('SELECT 1 FROM users WHERE username = %s;', (username,))
        row = cur.fetchone()
    if row is not None:
        return USER_EXISTS

    # Hash the password before storing
    try:
        hashed = ph.hash(password)
    except Exception:
        # If hashing fails for any reason, return an error string
        return "Password hashing failed"

    # Insert the new user and commit so the change persists
    try:
        with db.cursor() as cur:
            cur.execute('INSERT INTO users(username, password, role) VALUES (%s, %s, %s);', (username, hashed, role))
        db.commit()
    except Exception:
        db.rollback()
        return "Create failed"

    return True

def verifyUser(username, password):
    if len(password) > MAX_LOGIN_PASSWORD_LENGTH:
        return None
    db = get_db()
    with dict_cursor(db) as cur:
        cur.execute('SELECT password, role FROM users WHERE username = %s;', (username,))
        row = cur.fetchone()
    if row is None:
        # User doesn't exist
        try:
            ph.verify(_DUMMY_HASH, password)
        except Exception:
            pass
        return None

    stored = row['password']

    try:
        if ph.verify(stored, password):
            # Correct Password
            return (username, row['role']) 
    except Exception:
        # Wrong Password
        return False

def changeUserPassword(username, old_pass, new_pass, override=False):
    if (new_pass == old_pass):
        return False

    db = get_db()

    # Verify old pass
    verify = verifyUser(username, old_pass)
    if (verify or (override == True and verify == False)):
        try:
            with db.cursor() as cur:
                cur.execute('UPDATE users SET password = %s WHERE username = %s;',
                    (ph.hash(new_pass), username))
            db.commit()
            return True
        except Exception:
            db.rollback()
            return False
    else:
        return False
    
# This function should only be run by an admin, no need for authentication
def changeUserRole(username, new_role):
    db = get_db()

    with dict_cursor(db) as cur:
        cur.execute('SELECT role FROM users WHERE username = %s;', (username,))
        row = cur.fetchone()
    if row is None:
        # User doesn't exist
        return None

    if row['role'] == new_role:
        return False
    else:
        try:
            with db.cursor() as cur:
                cur.execute('UPDATE users SET role = %s WHERE username = %s;', (new_role, username))
            db.commit()
            return True
        except Exception:
            db.rollback()
            return False

def createAccessToken(token_name, username, application, description, expires_after=604800):
    # expires_after must be in seconds
    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    expires_at = None
    if expires_after and int(expires_after) > 0:
        expires_at = int(time.time()) + int(expires_after)

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO access_tokens(token_hash, token_name, application, description, username, prefix, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, to_timestamp(%s), to_timestamp(%s))
                ON CONFLICT (token_hash) DO NOTHING
                """,
                (
                    token_hash,
                    token_name,
                    application,
                    description,
                    username,
                    token[:3],
                    int(time.time()),
                    expires_at,
                ),
            )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception('Failed to store token in PostgreSQL')
        return None

    return token

def verifyAccessToken(token):
    if not token:
        return False

    token_hash = _hash_token(token)
    db = get_db()
    with dict_cursor(db) as cur:
        cur.execute(
            """
            SELECT token_name, application, description, username,
                   extract(epoch from created_at)::bigint AS created,
                   CASE WHEN expires_at IS NULL THEN NULL ELSE extract(epoch from expires_at)::bigint END AS expires,
                   prefix
            FROM access_tokens
            WHERE token_hash = %s
            """,
            (token_hash,),
        )
        info = cur.fetchone()
    if not info:
        return False

    expires = info.get('expires')
    if expires and int(expires) < int(time.time()):
        return False

    return info

def removeAccessToken(token_hash):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute('DELETE FROM access_tokens WHERE token_hash = %s;', (token_hash,))
            deleted = cur.rowcount
        db.commit()
        return deleted > 0
    except Exception:
        db.rollback()
        return False


def list_user_tokens(username):
    """Return metadata list for tokens belonging to username."""
    db = get_db()
    try:
        with dict_cursor(db) as cur:
            cur.execute(
                """
                SELECT token_hash AS hash,
                       token_name,
                       application,
                       description,
                       username,
                       extract(epoch from created_at)::bigint AS created,
                       CASE WHEN expires_at IS NULL THEN NULL ELSE extract(epoch from expires_at)::bigint END AS expires,
                       prefix
                FROM access_tokens
                WHERE username = %s
                ORDER BY created_at DESC
                """,
                (username,),
            )
            return list(cur.fetchall())
    except Exception:
        logger.exception('Failed to query user tokens')
        return []