#!/usr/bin/env python3
import datetime
import time
import os
import copy
import json
import socket
from . import r, logger, BOARD

SYSLOGSOCK = None
HOST=os.environ.get("SYSLOG_HOST", None)
PORT=int(os.environ.get("SYSLOG_PORT", -1))

def send_syslog(string):
    """Send a syslog to the server. Make sure the port is open though
    """
    # TODO: If someone wants to thread this then pwnbaord wont fail if logstash is down
    if not HOST or PORT == -1:
        return
    global SYSLOGSOCK
    string = string.rstrip() +"\n"
    try:
        if not SYSLOGSOCK:
            print("Creating socket to", HOST, PORT)
            SYSLOGSOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            SYSLOGSOCK.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            SYSLOGSOCK.connect((HOST, PORT))
        SYSLOGSOCK.sendall(string.encode())
    except:
        SYSLOGSOCK = None

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


def getHostData(ip):
    '''
    Get the host data for a single host.
    Returns and array with the following information:
    last_seen - The last known callback time
    type - The last service the host called back through
    '''
    # Request the data from the database
    server, app, last, message, online, access_type = r.hmget(ip, ('server', 'application',
                                      'last_seen', 'message', 'online', 'access_type'))
    creds_last, creds, creds_online = r.hmget(f"{ip}:creds", ('last_seen', 'creds', 'creds_online'))

    # callbacks_raw = r.hgetall(f"{ip}:callbacks")
    # callbacks = {app.decode(): json.loads(data) for app, data in callbacks_raw.items()}

    # Add the data to a dictionary
    status = {}
    status['ip'] = ip
    # If all the data is None from the DB, just return the blank status
    # stop unneeded calcs. and prevent data from being written to db
    creds_last = getTimeDelta(creds_last)
    if all([x is None for x in (server, app, last, message, online)]):
        if all([x is None for x in (creds_last, creds, creds_online)]):
            return status
        
        status['Creds'] = creds
        status['Creds Last Seen'] = "{}m".format(creds_last)
        if creds_last and creds_last > int(os.environ.get("CREDS_TIMEOUT", 30)):
            status['creds_online'] = ""
        else:
            status['creds_online'] = "True"
        r.hmset(f"{ip}:creds", {'creds_online': status['creds_online']})
        
        return status

    # Set the last seen time based on time calculations
    last = getTimeDelta(last)
    if last and last > int(os.environ.get("HOST_TIMEOUT", 2)):
        if online and online.lower().strip() == "true":
            logger.warning("{} offline".format(ip))
            # Try to send a slack message
            send_syslog("pwnboard GENERIC {} went offline".format(ip))
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
    try:
        num_valid_callbacks = sum(getTimeDelta(json.loads(v)["last_seen"]) < int(os.environ.get("HOST_TIMEOUT", 2)) 
                                for v in r.hgetall(f"{ip}:callbacks").values())
    except Exception as e:
        num_valid_callbacks = 0
    
    # Write the status to the database
    r.hmset(ip, {'online': status['online']})
    r.hmset(f"{ip}:creds", {'creds_online': status['creds_online']})

    status['Last Seen'] = "{}m".format(last)
    status['Type'] = app
    status['Access Type'] = access_type
    status['Callbacks'] = num_valid_callbacks
    
    if (creds is not None):
        status['Creds'] = creds
        status['Creds Last Seen'] = "{}m".format(creds_last)

    return status


def getAlert():
    '''
    Pull the alert message from redis if is is recent.
    Return nothing if it is not recent
    '''
    time, msg = r.hmget("alert", ('time', 'message'))
    time = getTimeDelta(time)
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
    # data = {"ip": <ip>, "application": <type>, "last_seen": <time>}
    # data = {"ip": <ip>, "application": <type>, "server": <server>, "message": <log msg>, "last_seen": <time>}
    # Don't accept callback from no IP or loopback
    if str(data.get('ip', '127.0.0.1')).lower() in ["127.0.0.1", "none", None, "null"]:
        return
    
    """
    current (one callback per ip):
    "192.168.1.1": {
        'application': data['application'],
        'access_type': data['access_type'],
        'message': data['message'],
        'server': data['server'],
        'last_seen': data['last_seen']
    }

    proposed (multiple callbacks)
    - on callback (or on check?), callbacks list iterated through and delete any 'last_seen' > threshold (5 mins)
    - store in redis as f"{ip}:callbacks": json_string

    "192.168.1.1:callbacks": "[
        {'application': application, 'access_type': access_type, 'last_seen': last_seen},
        {'application': application, 'access_type': access_type, 'last_seen': last_seen},
        {'application': application, 'access_type': access_type, 'last_seen': last_seen}
    ]"

    Key: "192.168.1.10:callbacks"
    Fields:
        "application" → {"access_type": "", "last_seen": "2025-11-02T12:00:00Z"}
        "application" → {"access_type": "", "last_seen": "2025-11-02T12:10:00Z"}

    callbacks_json = json.dumps([{'application': application, 'access_type': access_type, 'last_seen': last_seen}, ...])
    r.set(f"{ip}:callbacks", callbacks_json)
    callbacks = json.loads(r.get(f"{ip}:callbacks"))
    """

    logger.debug("updated beacon for {} from {}".format(data['ip'], data['application']))
    # Fill in default values. Fastest way according to https://stackoverflow.com/a/17501506
    data['server'] = data['server'] if 'server' in data else "pwnboard"
    data['message'] = data['message'] if 'message' in data else "Callback received to {}".format(data['server'])
    data['access_type'] = data['access_type'] if 'access_type' in data else "generic"

    send_syslog("{application} BOXACCESS {ip} {message}".format(**data))

    super_callback_data = {
        "access_type": data['access_type'],
        "last_seen": data['last_seen']
    }

    r.hset(f"{data['ip']}:callbacks", data['application'], json.dumps(super_callback_data))

    # save this to the DB
    r.hmset(data['ip'], {
        'application': data['application'],
        'access_type': data['access_type'],
        'message': data['message'],
        'server': data['server'],
        'last_seen': data['last_seen']
    })

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
    # Fill in default values. Fastest way according to https://stackoverflow.com/a/17501506
    data['server'] = data['server'] if 'server' in data else "pwnboard"
    data['message'] = data['message'] if 'message' in data else "Credentials received to {}".format(data['server'])

    send_syslog("CREDENTIALS {ip} {message}".format(**data))

    # save this to the DB
    credstring = f"{'* ' if data['admin'] == 1 else ''}{data['username']}:{data['password']}"
    r.hmset(f"{data['ip']}:creds", {
        'creds': credstring,
        'server': data['server'],
        'last_seen': data['last_seen']
    })


