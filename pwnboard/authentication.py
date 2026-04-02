#!/usr/bin/env python3
import secrets
import hashlib
import time
from . import logger, ph, get_db
from .db import dict_cursor

def _hash_token(raw_token):
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()

def createUser(username, password, role):
    db = get_db()

    # Check if the user already exists
    with db.cursor() as cur:
        cur.execute('SELECT 1 FROM users WHERE username = %s;', (username,))
        row = cur.fetchone()
    if row is not None:
        return "User already exists"

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
    db = get_db()
    with dict_cursor(db) as cur:
        cur.execute('SELECT password, role FROM users WHERE username = %s;', (username,))
        row = cur.fetchone()
    if row is None:
        # User doesn't exist
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

def verifyAccessToken(token, application):
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

    if application and info.get('application').lower() != application.lower() and info.get('application') != 'global':
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