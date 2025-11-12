#!/usr/bin/env python3
import json
import secrets
import hashlib
import time
import inspect
from . import r, logger, ph, get_db

def _hash_token(raw_token):
    return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()

def createUser(username, password, role):
    db = get_db()

    # Check if the user already exists
    cur = db.execute('SELECT 1 FROM users WHERE username = ?;', (username,))
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
    db.execute('INSERT INTO users(username, password, role) VALUES (?, ?, ?);', (username, hashed, role))
    db.commit()

    return True

def verifyUser(username, password):
    db = get_db()
    cur = db.execute('SELECT password, role FROM users WHERE username = ?;', (username,))
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
            db.execute('UPDATE users SET password = ? WHERE username = ?;',
                (ph.hash(new_pass), username))
            db.commit()
            return True
        except Exception:
            return False
    else:
        return False
    
# This function should only be run by an admin, no need for authentication
def changeUserRole(username, new_role):
    db = get_db()

    cur = db.execute('SELECT 1 FROM users WHERE username = ?;', (username,))
    row = cur.fetchone()
    if row is None:
        # User doesn't exist
        return None

    if row['role'] == new_role:
        return False
    else:
        db.execute('UPDATE users SET role = ? WHERE username = ?;', (new_role, username))
        db.commit()
        return True

def createAccessToken(token_name, username, application, description, expires_after=604800):
    # expires_after must be in seconds
    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    token_key = f"token:{token_hash}"

    token_info = {
        "token_name": token_name,
        "application": application,
        "description": description,
        "username": username,
        "created": int(time.time()),
        "expires": (int(time.time()) + int(expires_after)) if expires_after else None,
        # small prefix to help users identify tokens without exposing the secret
        "prefix": token[:3]
    }
    try:
        if expires_after and int(expires_after) > 0:
            r.set(token_key, json.dumps(token_info), nx=True, ex=int(expires_after))
        else:
            r.set(token_key, json.dumps(token_info), nx=True)
    except Exception:
        logger.exception('Failed to store token in Redis')
        return None

    # maintain index sets so users can list their tokens and admins can see all
    try:
        r.sadd(f"user_tokens:{username}", token_hash)
        r.sadd("tokens:all", token_hash)
    except Exception:
        logger.exception('Failed to update token indexes in Redis')

    return token

def verifyAccessToken(token, application):
    if not token:
        return False

    token_hash = _hash_token(token)
    data = r.get(f"token:{token_hash}")
    if not data:
        return False

    info = json.loads(str(data))

    expires = info.get('expires')
    if expires and int(expires) < int(time.time()):
        return False

    if application and info.get('application') != application and info.get('application') != 'global':
        return False

    return info

def removeAccessToken(token_hash):
    data = r.get(f"token:{token_hash}")
    if not data:
        return False
    info = json.loads(str(data))
    username = info.get('username')
    r.delete(f"token:{token_hash}")
    r.srem(f"user_tokens:{username}", token_hash)
    r.srem("tokens:all", token_hash)
    return True


def list_user_tokens(username):
    """Return metadata list for tokens belonging to username."""
    try:
        raw = r.smembers(f"user_tokens:{username}") or []
    except Exception:
        logger.exception('Failed to read user token set')
        return []

    out = []
    if raw is None:
        return out
    hashes = []
    try:
        for h in raw:
            hashes.append(h)
    except Exception:
        hashes = []

    for h in hashes:
        d = r.get(f"token:{h}")
        if not d:
            continue
        try:
            meta = json.loads(str(d))
        except Exception:
            continue
        # don't include any encrypted token value here; only metadata and prefix
        meta.pop('enc', None)
        meta['hash'] = h
        out.append(meta)
    return out