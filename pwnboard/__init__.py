#!/usr/bin/env python3
'''
Initialize all the data and the config info
'''
from flask import Flask
import os
import redis
import json
import logging
from os.path import isfile
from .logging_handler import DBHandler
import re
from markupsafe import Markup, escape

BOARD = []
IP_SET = set()

def loadBoard():
    global BOARD
    global IP_SET
    fil = os.environ.get("BOARD", "board.json")
    with open(fil) as fil:
        BOARD = json.load(fil)
    
    for row in BOARD.get("board", []):
        for host in row.get("hosts", []):
            ip = host.get("ip")
            if ip:
                IP_SET.add(ip)

# Create the Flask app
app = Flask(__name__)
app.config['STATIC_FOLDER'] = "lib/static"
logger = logging.getLogger('pwnboard')
loadBoard()

logfil = ""
# Get the pwnboard logger
# Create a log formatter
FMT = logging.Formatter(fmt="[%(asctime)s] %(levelname)s: %(message)s",
                        datefmt="%x %I:%M:%S")
# Create a file handler
if logfil != "":
    FH = logging.FileHandler(logfil)
    FH.setFormatter(FMT)
    logger.addHandler(FH)
# Create a console logging handler
SH = logging.StreamHandler()
SH.setFormatter(FMT)
logger.addHandler(SH)
logger.setLevel(logging.DEBUG)
logger.addHandler(DBHandler())
# Create the redis object. Make sure that we decode our responses
rserver = os.environ.get('REDIS_HOST', 'localhost')
rport = os.environ.get('REDIS_PORT', 6379)
r = redis.StrictRedis(host=rserver, port=rport, decode_responses=True)

# Simple linkify filter: convert http(s) URLs inside a string into clickable links
# Returns Markup so it's safe to render in templates
URL_RE = re.compile(r'(https?://[^\s]+)')

def linkify(text):
    if not text:
        return ''
    # escape the full text first to avoid injecting html
    esc = escape(text)

    def _repl(m):
        url = m.group(0)
        # url is escaped when inserted into the anchor text/href
        return '<a href="{0}" target="_blank" rel="noopener noreferrer">{0}</a>'.format(escape(url))

    result = URL_RE.sub(_repl, esc)
    return Markup(result)

# Register the filter with Jinja environment
app.jinja_env.filters['linkify'] = linkify

# Ignore a few errors here as routes arn't "used" and "not at top of file"
from . import routes  # noqa: E402, F401
