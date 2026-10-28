#!/usr/bin/env python3
import datetime
import time
import os
import copy

from .logger import logger
from .board import BOARD
from .info import get_info_counts

# How long after the last callback a host counts as online, and how long credentials count
# as current, in minutes. Set HOST_TIMEOUT / CREDS_TIMEOUT to change them. The web app and
# the worker must use the same values, because the worker builds the board the web app shows.
DEFAULT_HOST_TIMEOUT = 5
DEFAULT_CREDS_TIMEOUT = 30

def getHostTimeout():
    return int(os.environ.get("HOST_TIMEOUT", DEFAULT_HOST_TIMEOUT))

def getCredsTimeout():
    return int(os.environ.get("CREDS_TIMEOUT", DEFAULT_CREDS_TIMEOUT))

def getEpoch():
    '''
    Return the current Epoch time
    '''
    return time.mktime(datetime.datetime.now().timetuple())


def getBoardDict(db):
    '''
    Generate a game board based on the config file
    Get all the DB info for each host
    '''
    # Get the teams and the basehost list from the config
    board = copy.deepcopy(BOARD['board'])
    info_counts = get_info_counts(db)
    for row in board:
        for _host in row['hosts']:
            _host.update(getHostData(_host['ip'], db))
            if info_counts.get(_host['ip']):
                _host['Info'] = "Yes"
    return board

def getActiveCreds(ip, db):
    """Return (number of active credentials, every credential for the host).

    Each credential is (creds, age, is_stale). Credentials not seen for CREDS_TIMEOUT minutes
    are stale: they stay in the list, because the password may well still work, but they are
    not counted as active. Active credentials come first, newest first.
    """
    try:
        total_creds = 0
        entries = []
        creds_timeout = getCredsTimeout()
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

            is_stale = time_delta >= creds_timeout
            entries.append((is_stale, time_delta, creds))
            if not is_stale:
                total_creds += 1
            elif creds_online:
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

        entries.sort(key=lambda entry: (entry[0], entry[1]))
        all_creds = [(creds, "{}m".format(age), is_stale) for is_stale, age, creds in entries]

    except Exception:
        db.rollback()
        total_creds = 0
        all_creds = []

    return total_creds, all_creds

def getActiveCallbacks(ip, db):
    try:
        num_valid_callbacks = 0
        active_callbacks = []
        host_timeout = getHostTimeout()
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

def getHostData(ip, db):
    '''
    Get the host data for a single host.
    Returns and array with the following information:
    last_seen - The last known callback time
    type - The last service the host called back through
    '''
    server = app = last = message = online = None
    creds_last = creds = creds_online = None

    # Request the data from PostgreSQL
    with db.cursor() as cur:
        cur.execute(
            """
            SELECT server, application, last_seen, message, online
            FROM hosts
            WHERE ip = %s
            """,
            (ip,),
        )
        host_row = cur.fetchone()

        if host_row:
            server, app, last, message, online = host_row

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
        # status['Last Creds Received'] = "{}m".format(creds_last)
        if creds_last and creds_last > getCredsTimeout():
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

        total_creds, all_creds = getActiveCreds(ip, db)
        status['Valid Creds'] = "Yes" if total_creds else "Stale"
        status['Active Creds'] = total_creds
        # Despite the name, this holds stale credentials too (flagged in each entry). The key is
        # kept so that the cached board stays readable by pages from before stale credentials
        # were shown.
        status['all_valid_creds'] = all_creds

        return status

    # Set the last seen time based on time calculations
    last = getTimeDelta(last)
    if last and last > getHostTimeout():
        if online:
            logger.warning("{} offline".format(ip))
        status['online'] = ''
    else:
        status['online'] = "True"

    if creds_last and creds_last > getCredsTimeout():
        status['creds_online'] = ''
    elif creds:
        status['creds_online'] = "True"
    else:
        status['creds_online'] = ''

    # get num valid callbacks
    num_valid_callbacks, active_callbacks = getActiveCallbacks(ip, db)
    total_creds, all_creds = getActiveCreds(ip, db)
    
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
    status['Active Callbacks'] = num_valid_callbacks

    # See the note on 'all_valid_creds' above: it includes stale credentials
    status['all_valid_creds'] = all_creds
    status['all_valid_callbacks'] = active_callbacks
    
    if (creds is not None):
        status['Valid Creds'] = "Yes" if total_creds else "Stale"
        # status['Last Creds Received'] = "{}m".format(creds_last)
        status['Active Creds'] = total_creds

    return status


def getTimeDelta(ts):
    '''
    Print the number of minutes between now and the last timestamp
    '''
    try:
        checkin = datetime.datetime.fromtimestamp(float(ts))
        diff = datetime.datetime.now() - checkin
        minutes = int(diff.total_seconds()/60)
        return minutes
    except Exception:
        return None
