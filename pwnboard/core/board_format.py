"""The board.json format: reading, converting, validating.

This module has no side effects, so scripts and tests can import it. core/board.py is the
one that loads the file for the running app.

Format (version 2). Each machine is one row of the dashboard and has one host per team. Its
`ip` is a pattern: every `x` is replaced by the team number.

    {
      "version": 2,
      "teams": [1, 2, 5],
      "machines": [
        {"name": "DC01", "ip": "10.x.1.10", "os": "Windows Server 2019", "services": ["AD", "DNS"]},
        {"name": "Web",  "ip": "10.x.1.20", "skip": [5]},
        {"name": "Mail", "ip": "10.x.1.30", "ips": {"2": "10.2.9.30"}}
      ]
    }

`teams` and `machines` set the order of the dashboard columns and rows. An optional top-level
`"test_teams": [99]` marks teams that are not real competitors. They are labelled on the
dashboard and otherwise treated like any other team.

A machine can also have an `os` (text) and a list of critical `services`. They are shown
under the machine's name on the dashboard, and left out when not set.

Two more optional machine keys handle the exceptions: `skip` lists teams that have no host
for the machine (the cell is left blank), and `ips` gives a team's address when it does not
follow the pattern.

The older format (rows of hosts, matched to the `teams` list by position) is still accepted
and converted when it is read.
"""
import json
from collections import Counter

VERSION = 2
MACHINE_KEYS = ("name", "ip", "os", "services", "skip", "ips")
MAX_OS_LENGTH = 64
MAX_SERVICES = 20
MAX_SERVICE_LENGTH = 32


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


def _cells(machine, teams):
    """The machine's hosts as (team, ip, from_pattern), in team order. Assumes a valid machine."""
    skip = machine.get("skip", [])
    overrides = machine.get("ips", {})
    for team in teams:
        if team in skip:
            continue
        if str(team) in overrides:
            yield team, overrides[str(team)], False
        else:
            yield team, machine["ip"].replace("x", str(team)), True


def expand_hosts(board):
    """Every host on a valid board as {"ip", "team", "machine"}, machine by machine."""
    return [
        {"ip": ip, "team": team, "machine": machine["name"]}
        for machine in board["machines"]
        for team, ip, _ in _cells(machine, board["teams"])
    ]


# Converting the older format ---------------------------------------------------------------

def _following_octets(cells):
    """The positions in a machine's addresses that follow the team number.

    A position qualifies when it differs between teams and holds the team's own number for
    most of them, as the 1 does in 10.1.1.10 for team 1 and 10.2.1.10 for team 2.
    """
    parts = {team: ip.split(".") for team, ip in cells.items()}
    width = Counter(len(p) for p in parts.values()).most_common(1)[0][0]
    usable = {team: p for team, p in parts.items() if len(p) == width}
    positions = set()
    for i in range(width):
        matches = sum(p[i] == str(team) for team, p in usable.items())
        varies = len({p[i] for p in usable.values()}) > 1
        if varies and matches * 2 > len(usable):
            positions.add(i)
    return frozenset(positions)


def _team_octet_hint(all_cells):
    """The position that follows the team number on most machines, used where a machine has
    only one host and cannot show it by itself."""
    found = Counter(_following_octets(cells) for cells in all_cells if len(cells) > 1)
    found.pop(frozenset(), None)
    return found.most_common(1)[0][0] if found else frozenset()


def _compact_machine(name, cells, teams, hint):
    """One machine as {"name", "ip" pattern, "skip", "ips"} from its {team: ip} hosts."""
    if not cells:
        # No hosts at all: keep the row, with every team skipped
        return {"name": name, "ip": "x", "skip": list(teams)}

    if len(cells) > 1:
        positions = _following_octets(cells)
    else:
        (team, ip), = cells.items()
        parts = ip.split(".")
        positions = frozenset(i for i in hint if i < len(parts) and parts[i] == str(team))

    # Build the pattern from the first host that has the usual number of parts
    width = Counter(len(ip.split(".")) for ip in cells.values()).most_common(1)[0][0]
    rep = next(cells[team] for team in teams if team in cells and len(cells[team].split(".")) == width)
    pattern = ".".join("x" if i in positions else part for i, part in enumerate(rep.split(".")))

    machine = {"name": name, "ip": pattern}
    skip = [team for team in teams if team not in cells]
    if skip:
        machine["skip"] = skip
    irregular = {str(team): ip for team, ip in cells.items() if pattern.replace("x", str(team)) != ip}
    if irregular:
        machine["ips"] = irregular
    return machine


def _convert_v1(raw):
    """Turn rows of hosts, matched to the teams by position, into the version 2 format."""
    if not isinstance(raw.get("teams"), list) or not isinstance(raw.get("board"), list):
        raise BoardError("expected a 'teams' list and a 'board' list")

    teams = [_team_number(team, "teams") for team in raw["teams"]]
    names, rows = [], []
    for number, row in enumerate(raw["board"], start=1):
        if not isinstance(row, dict) or not isinstance(row.get("hosts", []), list):
            raise BoardError(f"board row {number}: expected an object with a 'hosts' list")
        name = row.get("name")
        name = name if isinstance(name, str) and name.strip() else f"Machine {number}"
        name = _unique_name(name, names)
        names.append(name)

        cells = {}
        for host in row.get("hosts", []):
            if not isinstance(host, dict) or not host.get("ip"):
                continue
            where = f"host {host['ip']}"
            if not isinstance(host["ip"], str):
                raise BoardError(f"{where}: the ip must be text")
            if "team" not in host:
                raise BoardError(f"{where}: missing 'team'")
            team = _team_number(host["team"], where)
            if team not in teams:
                raise BoardError(f"{where}: team {team} is not in 'teams'")
            if team in cells:
                raise BoardError(f"machine {name!r} has two hosts for team {team}")
            cells[team] = host["ip"]
        rows.append((name, cells))

    hint = _team_octet_hint([cells for _, cells in rows])
    machines = [_compact_machine(name, cells, teams, hint) for name, cells in rows]

    # The conversion must not change a single address
    for (name, cells), machine in zip(rows, machines):
        if {team: ip for team, ip, _ in _cells(machine, teams)} != cells:
            raise BoardError(f"machine {name!r} could not be converted")
    return {"version": VERSION, "teams": teams, "machines": machines}


# Validating --------------------------------------------------------------------------------

def _validate_machine(machine, teams):
    name = machine.get("name") if isinstance(machine, dict) else None
    if not isinstance(machine, dict):
        raise BoardError(f"every machine must be an object with a 'name' and an 'ip', got {machine!r}")
    if not isinstance(name, str) or not name.strip():
        raise BoardError(f"every machine needs a 'name', got {machine!r}")
    unknown = sorted(set(machine) - set(MACHINE_KEYS))
    if unknown:
        raise BoardError(f"machine {name!r}: unknown key {unknown[0]!r} (expected {', '.join(MACHINE_KEYS)})")
    if not isinstance(machine.get("ip"), str) or not machine["ip"].strip():
        raise BoardError(f"machine {name!r}: needs an 'ip' pattern such as '10.x.1.10'")

    if "os" in machine and (not isinstance(machine["os"], str) or not machine["os"].strip()
                            or len(machine["os"]) > MAX_OS_LENGTH):
        raise BoardError(f"machine {name!r}: 'os' must be text of at most {MAX_OS_LENGTH} characters")

    services = machine.get("services", [])
    if not isinstance(services, list) or len(services) > MAX_SERVICES:
        raise BoardError(f"machine {name!r}: 'services' must be a list of at most {MAX_SERVICES} names")
    for service in services:
        if not isinstance(service, str) or not service.strip() or len(service) > MAX_SERVICE_LENGTH:
            raise BoardError(
                f"machine {name!r}: each service must be text of at most {MAX_SERVICE_LENGTH} characters, got {service!r}"
            )

    skip = machine.get("skip", [])
    if not isinstance(skip, list):
        raise BoardError(f"machine {name!r}: 'skip' must be a list of team numbers")
    for team in skip:
        if team not in teams or not _is_int(team):
            raise BoardError(f"machine {name!r}: 'skip' names team {team!r}, which is not in 'teams'")

    ips = machine.get("ips", {})
    if not isinstance(ips, dict):
        raise BoardError(f"machine {name!r}: 'ips' must map team numbers to addresses")
    for key, ip in ips.items():
        if not key.isdigit() or int(key) not in teams:
            raise BoardError(f"machine {name!r}: 'ips' names team {key!r}, which is not in 'teams'")
        if int(key) in skip:
            raise BoardError(f"machine {name!r}: team {key} is both skipped and given an address")
        if not isinstance(ip, str) or not ip.strip():
            raise BoardError(f"machine {name!r}: the address for team {key} must be text")


def validate_board(board):
    """Check a version 2 board and return it. Raises BoardError for the first problem."""
    if not isinstance(board, dict):
        raise BoardError("the board must be a JSON object")
    if board.get("version") != VERSION:
        raise BoardError(f"unsupported board version {board.get('version')!r}, expected {VERSION}")

    teams = board.get("teams")
    if not isinstance(teams, list):
        raise BoardError("'teams' must be a list of team numbers")
    for team in teams:
        if not _is_int(team):
            raise BoardError(f"team numbers must be whole numbers, got {team!r}")
    if len(set(teams)) != len(teams):
        duplicate = next(team for team in teams if teams.count(team) > 1)
        raise BoardError(f"team {duplicate} is listed twice")

    test_teams = board.get("test_teams", [])
    if not isinstance(test_teams, list):
        raise BoardError("'test_teams' must be a list of team numbers")
    for team in test_teams:
        if not _is_int(team) or team not in teams:
            raise BoardError(f"'test_teams' names team {team!r}, which is not in 'teams'")
    if len(set(test_teams)) != len(test_teams):
        raise BoardError("'test_teams' lists a team twice")

    machines = board.get("machines")
    if not isinstance(machines, list):
        raise BoardError("'machines' must be a list")
    names = set()
    for machine in machines:
        _validate_machine(machine, teams)
        if machine["name"] in names:
            raise BoardError(f"machine {machine['name']!r} is listed twice")
        names.add(machine["name"])

    owners = {}
    for machine in machines:
        shared = [team for team, _, from_pattern in _cells(machine, teams) if from_pattern]
        if len(shared) > 1 and "x" not in machine["ip"]:
            raise BoardError(
                f"machine {machine['name']!r}: the ip {machine['ip']!r} has no 'x' for the team number, "
                f"so teams {shared[0]} and {shared[1]} would share it"
            )
        for team, ip, _ in _cells(machine, teams):
            if ip in owners:
                other_machine, other_team = owners[ip]
                raise BoardError(
                    f"host {ip} is used twice: {other_machine!r} team {other_team} "
                    f"and {machine['name']!r} team {team}"
                )
            owners[ip] = (machine["name"], team)
    return board


def normalize_board(raw):
    """Return a validated version 2 board from either file format."""
    if not isinstance(raw, dict):
        raise BoardError("the board must be a JSON object")
    if "version" not in raw:
        if "board" not in raw:
            raise BoardError("this is not a board file: it has neither 'version' nor the older 'board' key")
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


def format_board(board):
    """The board as JSON text with one line per machine, which is easy to read and edit."""
    machines = []
    for machine in board["machines"]:
        ordered = {key: machine[key] for key in MACHINE_KEYS if key in machine}
        machines.append("    " + json.dumps(ordered))
    test_teams = board.get("test_teams")
    return (
        "{\n"
        f'  "version": {VERSION},\n'
        f'  "teams": {json.dumps(board["teams"])},\n'
        + (f'  "test_teams": {json.dumps(test_teams)},\n' if test_teams else "")
        + '  "machines": [\n' + ",\n".join(machines) + "\n  ]\n"
        "}\n"
    )


# Using a valid board -----------------------------------------------------------------------

def team_ids(board):
    """The team numbers, in dashboard order."""
    return list(board["teams"])


def marked_test_teams(board):
    """The team numbers marked as test teams."""
    return list(board.get("test_teams", []))


def build_indexes(board):
    """Return (ip -> "Team N", set of every ip) for looking hosts up."""
    team_map = {host["ip"]: f"Team {host['team']}" for host in expand_hosts(board)}
    return team_map, set(team_map)


def board_rows(board):
    """The dashboard grid: one row per machine, one cell per team in `teams` order.

    A cell is {"ip": ...}, or None where the machine has no host for that team.
    """
    rows = []
    for machine in board["machines"]:
        cells = {team: ip for team, ip, _ in _cells(machine, board["teams"])}
        hosts = [{"ip": cells[team]} if team in cells else None for team in board["teams"]]
        row = {"name": machine["name"], "hosts": hosts}
        for key in ("os", "services"):
            if machine.get(key):
                row[key] = list(machine[key]) if key == "services" else machine[key]
        rows.append(row)
    return rows
