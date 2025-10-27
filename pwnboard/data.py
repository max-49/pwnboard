#!/usr/bin/env python3
import datetime
import time
import os
import copy
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
    server, app, last, message, online = r.hmget(ip, ('server', 'application',
                                      'last_seen', 'message', 'online'))
    # Add the data to a dictionary
    status = {}
    status['ip'] = ip
    # If all the data is None from the DB, just return the blank status
    # stop unneeded calcs. and prevent data from being written to db
    if all([x is None for x in (server, app, last, message, online)]):
        return status

    # Set the last seen time based on time calculations
    last = getTimeDelta(last)
    if last and last > int(os.environ.get("HOST_TIMEOUT", 2)):
        if online and online.lower().strip() == "true":
            logger.warning("{} offline".format(ip))
            # Try to send a slack message
            send_syslog("pwnboard GENERIC {} went offline".format(ip))
        status['online'] = ""
    else:
        status['online'] = "True"
    # Write the status to the database
    r.hmset(ip, {'online': status['online']})

    status['Last Seen'] = "{}m".format(last)
    status['Type'] = app
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

    logger.debug("updated beacon for {} from {}".format(data['ip'], data['application']))
    # Fill in default values. Fastest way according to https://stackoverflow.com/a/17501506
    data['server'] = data['server'] if 'server' in data else "pwnboard"
    data['message'] = data['message'] if 'message' in data else "Callback received to {}".format(data['server'])

    send_syslog("{application} BOXACCESS {ip} {message}".format(**data))

    # save this to the DB
    r.hmset(data['ip'], {
        'application': data['application'],
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

    logger.debug("updated credentials for {}".format(data['ip']))
    # Fill in default values. Fastest way according to https://stackoverflow.com/a/17501506
    data['server'] = data['server'] if 'server' in data else "pwnboard"
    data['message'] = data['message'] if 'message' in data else "Callback received to {}".format(data['server'])

    send_syslog("CREDENTIALS {ip} {message}".format(**data))

    #TODO: Make this work with credentials
    # save this to the DB
    r.hmset(data['ip'], {
        'username': data['username'],
        'password': data['password'],
        'server': data['server'],
        'last_seen': data['last_seen']
    })


