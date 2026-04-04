#!/usr/bin/env python3
import datetime
import time
import os
import copy
import socket
import requests
from . import logger, BOARD, get_db

DISCORD_WEBHOOK=os.environ.get("DISCORD_WEBHOOK", None)

def send_discord(string):
    if DISCORD_WEBHOOK is None:
        return

    hook_data = {
        'content': string,
        'username': 'PWNboard Bot',
        'avatar_url': 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRGtJooqzY8OA0YNFuArgmbax3cOuSzXbdBnA&s',
    }

    try:
        requests.post(DISCORD_WEBHOOK, json=hook_data, timeout=5)
    except Exception as e:
        print(f"Discord webhook error: {e}")


def getEpoch():
    '''
    Return the current Epoch time
    '''
    return time.mktime(datetime.datetime.now().timetuple())


def getBoardDict():
    '''
    Generate a game board based on the config file
    Get all the DB info for each host
    '''
    # Get the teams and the basehost list from the config
    board = copy.deepcopy(BOARD['board'])
    for row in board:
        for _host in row['hosts']:
            _host.update(getHostData(_host['ip']))
    return board

def getActiveCreds(ip):
    db = get_db()
    try:
        total_creds = 0
        all_valid_creds = []
        creds_timeout = int(os.environ.get("CREDS_TIMEOUT", 30))
        stale_usernames = []

        with db.cursor() as cur:
            cur.execute(
                """
                SELECT username, password, last_seen, creds_online
                FROM credentials_by_user
                WHERE ip = %s
                """,
                (ip,),
            )
            rows = cur.fetchall()

        for username, password, last_seen, creds_online in rows:
            time_delta = getTimeDelta(last_seen)
            creds = f"{username}:{password}"

            if time_delta is None:
                continue

            if time_delta < creds_timeout:
                all_valid_creds.append((creds, "{}m".format(time_delta)))
                total_creds += 1
            elif time_delta >= creds_timeout and creds_online:
                stale_usernames.append(username)

        if stale_usernames:
            with db.cursor() as cur:
                cur.execute(
                    """
                    UPDATE credentials_by_user
                    SET creds_online = FALSE, updated_at = NOW()
                    WHERE ip = %s AND username = ANY(%s)
                    """,
                    (ip, stale_usernames),
                )
            db.commit()

    except Exception:
        db.rollback()
        total_creds = 0
        all_valid_creds = []

    return total_creds, all_valid_creds

def getActiveCallbacks(ip):
    db = get_db()
    try:
        num_valid_callbacks = 0
        active_callbacks = []
        host_timeout = int(os.environ.get("HOST_TIMEOUT", 5))
        stale_apps = []

        with db.cursor() as cur:
            cur.execute(
                """
                SELECT application, access_info, last_seen, online
                FROM callbacks
                WHERE ip = %s
                """,
                (ip,),
            )
            rows = cur.fetchall()
        
        for app_name, access_info, last_seen, online in rows:
            time_delta = getTimeDelta(last_seen)
            
            # Skip if time_delta is None (invalid timestamp)
            if time_delta is None:
                continue
            
            # Check if callback is valid (within timeout)
            if time_delta < host_timeout:
                num_valid_callbacks += 1
                active_callbacks.append((app_name, "{}m".format(time_delta), access_info))

            # Check if callback exceeded timeout but is still marked as online
            elif time_delta >= host_timeout and online:
                stale_apps.append(app_name)
                # send_discord(f"LOST BEACON ON {ip}: {app_name}")

        if stale_apps:
            with db.cursor() as cur:
                cur.execute(
                    """
                    UPDATE callbacks
                    SET online = FALSE, updated_at = NOW()
                    WHERE ip = %s AND application = ANY(%s)
                    """,
                    (ip, stale_apps),
                )
            db.commit()
    except Exception:
        db.rollback()
        num_valid_callbacks = 0
        active_callbacks = []

    return num_valid_callbacks, active_callbacks

def getHostData(ip):
    '''
    Get the host data for a single host.
    Returns and array with the following information:
    last_seen - The last known callback time
    type - The last service the host called back through
    '''
    db = get_db()
    server = app = last = message = online = access_type = None
    creds_last = creds = creds_online = None

    # Request the data from PostgreSQL
    with db.cursor() as cur:
        cur.execute(
            """
            SELECT server, application, last_seen, message, online, access_type
            FROM hosts
            WHERE ip = %s
            """,
            (ip,),
        )
        host_row = cur.fetchone()

        if host_row:
            server, app, last, message, online, access_type = host_row

        cur.execute(
            """
            SELECT last_seen, creds, creds_online
            FROM credentials_latest
            WHERE ip = %s
            """,
            (ip,),
        )
        creds_row = cur.fetchone()
        if creds_row:
            creds_last, creds, creds_online = creds_row

    # Add the data to a dictionary
    status = {}
    status['ip'] = ip
    # If all the data is None from the DB, just return the blank status
    # stop unneeded calcs. and prevent data from being written to db
    creds_last = getTimeDelta(creds_last)
    if all([x is None for x in (server, app, last, message, online)]):
        if all([x is None for x in (creds_last, creds, creds_online)]):
            return status

        # Handle creds but no callbacks
        status['Last Creds'] = creds
        status['Last Creds Received'] = "{}m".format(creds_last)
        if creds_last and creds_last > int(os.environ.get("CREDS_TIMEOUT", 30)):
            status['creds_online'] = ""
        else:
            status['creds_online'] = "True"
        
        try:
            with db.cursor() as cur:
                cur.execute(
                    """
                    UPDATE credentials_latest
                    SET creds_online = %s, updated_at = NOW()
                    WHERE ip = %s
                    """,
                    (status['creds_online'] == "True", ip),
                )
            db.commit()
        except Exception:
            db.rollback()

        total_creds, all_valid_creds = getActiveCreds(ip)
        status['Active Creds'] = total_creds
        status['all_valid_creds'] = all_valid_creds

        return status

    # Set the last seen time based on time calculations
    last = getTimeDelta(last)
    if last and last > int(os.environ.get("HOST_TIMEOUT", 2)):
        if online:
            logger.warning("{} offline".format(ip))
        status['online'] = ''
    else:
        status['online'] = "True"

    if creds_last and creds_last > int(os.environ.get("CREDS_TIMEOUT", 30)):
        status['creds_online'] = ''
    elif creds:
        status['creds_online'] = "True"
    else:
        status['creds_online'] = ''

    # get num valid callbacks
    num_valid_callbacks, active_callbacks = getActiveCallbacks(ip)
    total_creds, all_valid_creds = getActiveCreds(ip)
    
    # Write status booleans to the database
    try:
        with db.cursor() as cur:
            cur.execute(
                """
                UPDATE hosts
                SET online = %s, updated_at = NOW()
                WHERE ip = %s
                """,
                (status['online'] == "True", ip),
            )
            cur.execute(
                """
                UPDATE credentials_latest
                SET creds_online = %s, updated_at = NOW()
                WHERE ip = %s
                """,
                (status['creds_online'] == "True", ip),
            )
        db.commit()
    except Exception:
        db.rollback()

    status['Last Seen'] = "{}m".format(last)
    status['Type'] = app
    status['Access Type'] = access_type
    status['Active Callbacks'] = num_valid_callbacks

    status['all_valid_creds'] = all_valid_creds
    status['all_valid_callbacks'] = active_callbacks
    
    if (creds is not None):
        status['Last Creds'] = creds
        status['Last Creds Received'] = "{}m".format(creds_last)
        status['Active Creds'] = total_creds

    return status


def getAlert():
    '''
    Pull the alert message from PostgreSQL if it is recent.
    Return nothing if it is not recent
    '''
    db = get_db()
    with db.cursor() as cur:
        cur.execute('SELECT event_time, message FROM alerts WHERE id = 1;')
        row = cur.fetchone()

    if not row:
        return ""

    event_time, msg = row
    time = getTimeDelta(event_time)
    if time is None or msg is None:
        return ""
    # If the time is within X minutes, display the message
    if time < int(os.environ.get('ALERT_TIMEOUT', 2)):
        return msg
    return ""


def getTimeDelta(ts):
    '''
    Print the number of minutes between now and the last timestamp
    '''
    try:
        checkin = datetime.datetime.fromtimestamp(float(ts))
        diff = datetime.datetime.now() - checkin
        minutes = int(diff.total_seconds()/60)
        return minutes
    except Exception as E:
        return None


def saveData(data):
    '''
    Parse updates that come in via POST to the server.

    'ip' and 'application' are required in the data
    '''

    # Don't accept callback from no IP or loopback
    if str(data.get('ip', '127.0.0.1')).lower() in ["127.0.0.1", "none", None, "null"]:
        return

    logger.debug("updated beacon for {} from {}".format(data['ip'], data['application']))

    data['server'] = data['server'] if 'server' in data else "pwnboard"
    data['message'] = data['message'] if 'message' in data else "Callback received to {}".format(data['server'])
    data['access_type'] = data['access_type'] if 'access_type' in data else "generic"
    data['access_info'] = data['access_info'] if 'access_info' in data else ""

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO callbacks(ip, application, access_info, last_seen, online, updated_at)
                VALUES (%s, %s, %s, %s, TRUE, NOW())
                ON CONFLICT (ip, application)
                DO UPDATE SET
                    access_info = EXCLUDED.access_info,
                    last_seen = EXCLUDED.last_seen,
                    online = TRUE,
                    updated_at = NOW()
                """,
                (data['ip'], data['application'], data['access_info'], data['last_seen']),
            )

            cur.execute(
                """
                INSERT INTO hosts(ip, application, access_type, message, server, last_seen, online, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, TRUE, NOW())
                ON CONFLICT (ip)
                DO UPDATE SET
                    application = EXCLUDED.application,
                    access_type = EXCLUDED.access_type,
                    message = EXCLUDED.message,
                    server = EXCLUDED.server,
                    last_seen = EXCLUDED.last_seen,
                    online = TRUE,
                    updated_at = NOW()
                """,
                (
                    data['ip'],
                    data['application'],
                    data['access_type'],
                    data['message'],
                    data['server'],
                    data['last_seen'],
                ),
            )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("failed to save callback data")

def saveCredData(data):
    '''
    Parse credential updates that come in via POST to the server.

    'username' and 'password' are required in the data
    '''
    # Don't accept callback from no IP or loopback
    if str(data.get('ip', '127.0.0.1')).lower() in ["127.0.0.1", "none", None, "null"]:
        return

    # if no password, don't accept
    if (len(data['password']) <= 1):
        return

    logger.debug("updated credentials for {}".format(data['ip']))

    data['server'] = data['server'] if 'server' in data else "pwnboard"
    data['message'] = data['message'] if 'message' in data else "Credentials received to {}".format(data['server'])

    db = get_db()
    credstring = f"{'* ' if data['admin'] == 1 else ''}{data['username']}:{data['password']}"
    try:
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO credentials_latest(ip, creds, server, last_seen, creds_online, updated_at)
                VALUES (%s, %s, %s, %s, TRUE, NOW())
                ON CONFLICT (ip)
                DO UPDATE SET
                    creds = EXCLUDED.creds,
                    server = EXCLUDED.server,
                    last_seen = EXCLUDED.last_seen,
                    creds_online = TRUE,
                    updated_at = NOW()
                """,
                (data['ip'], credstring, data['server'], data['last_seen']),
            )

            cur.execute(
                """
                INSERT INTO credentials_by_user(ip, username, password, server, last_seen, creds_online, updated_at)
                VALUES (%s, %s, %s, %s, %s, TRUE, NOW())
                ON CONFLICT (ip, username)
                DO UPDATE SET
                    creds = EXCLUDED.creds,
                    server = EXCLUDED.server,
                    last_seen = EXCLUDED.last_seen,
                    creds_online = TRUE,
                    updated_at = NOW()
                """,
                (data['ip'], data['username'], data['password'], data['server'], data['last_seen']),
            )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("failed to save credential data")


