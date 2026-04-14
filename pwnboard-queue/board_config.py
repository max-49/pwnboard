#!/usr/bin/env python3
'''
Initialize the board
'''
import os
import json

BOARD = []
TEAM_MAP = {}
IP_SET = set()

# Load the board.json file
def loadBoard():
    global BOARD
    global IP_SET
    fil = os.environ.get("BOARD", "board.json")
    try:
        with open(fil) as fil:
            BOARD = json.load(fil)
    except FileNotFoundError:
        print("Please generate a board.json file first! See doc/config.md")
        exit(1)
    
    for row in BOARD.get("board", []):
        for host in row.get("hosts", []):
            ip = host.get("ip")
            if ip:
                IP_SET.add(ip)
                TEAM_MAP[ip] = f"Team {host.get('team')}"
                del host["team"]

loadBoard()
