"""The board.json format: reading, converting, validating.

This module has no side effects, so scripts and tests can import it. core/board.py is the
one that loads the file for the running app.

Format (version 2). Every host says which team and machine it belongs to:

    {
      "version": 2,
      "teams":    [{"id": 1}, {"id": 2}],
      "machines": ["DC01", "Web"],
      "hosts":    [{"ip": "10.1.1.10", "team": 1, "machine": "DC01"}, ...]
    }

`teams` and `machines` set the order of the dashboard columns and rows. A machine does not
need a host for every team: the missing cell is left blank.

The older format (rows of hosts, matched to the `teams` list by position) is still accepted
and converted when it is read.
"""
import json

VERSION = 2


class BoardError(ValueError):
    """The board file cannot be used. The message says what to fix."""


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _team_number(value, where):
    """Team numbers are whole numbers. The older format also wrote them as strings ("1")."""
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value)
    if not _is_int(value):
        raise BoardError(f"{where}: team must be a whole number, got {value!r}")
    return value


def _unique_name(name, taken):
    """name, or "name (2)", "name (3)", ... when it is already taken."""
    candidate, n = name, 1
    while candidate in taken:
        n += 1
        candidate = f"{name} ({n})"
    return candidate


def _convert_v1(raw):
    """Turn rows of hosts, matched to the teams by position, into the version 2 format."""
    if not isinstance(raw.get("teams"), list) or not isinstance(raw.get("board"), list):
        raise BoardError("expected a 'teams' list and a 'board' list")

    teams = [{"id": _team_number(team, "teams")} for team in raw["teams"]]
    machines, hosts = [], []
    for number, row in enumerate(raw["board"], start=1):
        if not isinstance(row, dict) or not isinstance(row.get("hosts", []), list):
            raise BoardError(f"board row {number}: expected an object with a 'hosts' list")
        name = row.get("name")
        name = name if isinstance(name, str) and name.strip() else f"Machine {number}"
        name = _unique_name(name, machines)
        machines.append(name)
        for host in row.get("hosts", []):
            if not isinstance(host, dict) or not host.get("ip"):
                continue
            where = f"host {host.get('ip')}"
            if "team" not in host:
                raise BoardError(f"{where}: missing 'team'")
            hosts.append({"ip": host["ip"], "team": _team_number(host["team"], where), "machine": name})
    return {"version": VERSION, "teams": teams, "machines": machines, "hosts": hosts}


def validate_board(board):
    """Check a version 2 board and return it. Raises BoardError for the first problem."""
    if not isinstance(board, dict):
        raise BoardError("the board must be a JSON object")
    if board.get("version") != VERSION:
        raise BoardError(f"unsupported board version {board.get('version')!r}, expected {VERSION}")

    teams = board.get("teams")
    if not isinstance(teams, list):
        raise BoardError("'teams' must be a list")
    team_ids = set()
    for team in teams:
        team_id = team.get("id") if isinstance(team, dict) else None
        if not _is_int(team_id):
            raise BoardError(f"every team needs a whole number 'id', got {team!r}")
        if team_id in team_ids:
            raise BoardError(f"team {team_id} is listed twice")
        team_ids.add(team_id)

    machines = board.get("machines")
    if not isinstance(machines, list):
        raise BoardError("'machines' must be a list")
    machine_names = set()
    for name in machines:
        if not isinstance(name, str) or not name.strip():
            raise BoardError(f"every machine needs a name, got {name!r}")
        if name in machine_names:
            raise BoardError(f"machine {name!r} is listed twice")
        machine_names.add(name)

    hosts = board.get("hosts")
    if not isinstance(hosts, list):
        raise BoardError("'hosts' must be a list")
    seen_ips, seen_cells = set(), set()
    for host in hosts:
        if not isinstance(host, dict):
            raise BoardError(f"every host must be an object, got {host!r}")
        ip, team, machine = host.get("ip"), host.get("team"), host.get("machine")
        if not isinstance(ip, str) or not ip.strip():
            raise BoardError(f"every host needs an 'ip', got {host!r}")
        if ip in seen_ips:
            raise BoardError(f"host {ip} is listed twice")
        seen_ips.add(ip)
        if team not in team_ids or not _is_int(team):
            raise BoardError(f"host {ip}: team {team!r} is not in 'teams'")
        if machine not in machine_names:
            raise BoardError(f"host {ip}: machine {machine!r} is not in 'machines'")
        if (team, machine) in seen_cells:
            raise BoardError(f"machine {machine!r} has two hosts for team {team}")
        seen_cells.add((team, machine))
    return board


def normalize_board(raw):
    """Return a validated version 2 board from either file format."""
    if not isinstance(raw, dict):
        raise BoardError("the board must be a JSON object")
    if "version" not in raw and "board" in raw:
        raw = _convert_v1(raw)
    return validate_board(raw)


def load_board_file(path):
    """Read, convert and validate a board file. A missing file raises FileNotFoundError."""
    with open(path) as fil:
        try:
            raw = json.load(fil)
        except ValueError as e:
            raise BoardError(f"not valid JSON: {e}")
    return normalize_board(raw)


def team_ids(board):
    """The team numbers, in dashboard order."""
    return [team["id"] for team in board["teams"]]


def build_indexes(board):
    """Return (ip -> "Team N", set of every ip) for looking hosts up."""
    team_map = {host["ip"]: f"Team {host['team']}" for host in board["hosts"]}
    return team_map, set(team_map)


def board_rows(board):
    """The dashboard grid: one row per machine, one cell per team in `teams` order.

    A cell is {"ip": ...}, or None where the machine has no host for that team.
    """
    cells = {(host["team"], host["machine"]): host["ip"] for host in board["hosts"]}
    ids = team_ids(board)
    rows = []
    for machine in board["machines"]:
        row = [{"ip": cells[(team, machine)]} if (team, machine) in cells else None for team in ids]
        rows.append({"name": machine, "hosts": row})
    return rows
