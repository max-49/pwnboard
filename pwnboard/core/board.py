#!/usr/bin/env python3
'''
Initialize the board
'''
import os
import sys

from .board_format import BoardError, build_indexes, load_board_file

BOARD = {}
TEAM_MAP = {}
IP_SET = set()

# Load the board.json file
def loadBoard():
    global BOARD
    path = os.environ.get("BOARD", "board.json")
    try:
        BOARD = load_board_file(path)
    except FileNotFoundError:
        print("Please generate a board.json file first! See doc/config.md")
        sys.exit(1)
    except BoardError as e:
        print(f"Cannot use {path}: {e}. See doc/config.md")
        sys.exit(1)

    team_map, ip_set = build_indexes(BOARD)
    TEAM_MAP.update(team_map)
    IP_SET.update(ip_set)

loadBoard()
