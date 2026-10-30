"""board.json: reading and checking the format, converting the older one, and building the dashboard grid."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

from pwnboard.core import board as board_module, data
from pwnboard.core.board_format import (
    BoardError, board_rows, build_indexes, expand_hosts, format_board, load_board_file,
    marked_test_teams, normalize_board, validate_board,
)
from pwnboard.web import routes
from tests.test_host_info import FakeBoardDb

V2 = {
    "version": 2,
    "teams": [1, 2, 5],
    "machines": [
        {"name": "DC01", "ip": "10.x.1.10", "os": "Windows Server 2019", "services": ["AD", "DNS"]},
        {"name": "Web", "ip": "10.x.1.20", "skip": [5]},
        {"name": "Mail", "ip": "10.x.1.30", "ips": {"2": "10.2.9.30"}},
    ],
}

V1 = {
    "teams": [1, 2],
    "board": [
        {"name": "DC01", "hosts": [{"ip": "10.1.1.10", "team": "1"}, {"ip": "10.2.1.10", "team": "2"}]},
        {"name": "Web", "hosts": [{"ip": "10.1.1.20", "team": "1"}, {"ip": "10.2.1.20", "team": "2"}]},
    ],
}
V1_AS_V2 = {
    "version": 2,
    "teams": [1, 2],
    "machines": [{"name": "DC01", "ip": "10.x.1.10"}, {"name": "Web", "ip": "10.x.1.20"}],
}


def broken(change):
    board = copy.deepcopy(V2)
    change(board)
    return board


def old_board(*rows, teams=(1, 2, 3)):
    """An older-format board. Each row is (name, {team: ip})."""
    return {
        "teams": list(teams),
        "board": [
            {"name": name, "hosts": [{"ip": ip, "team": str(team)} for team, ip in cells.items()]}
            for name, cells in rows
        ],
    }


def addresses(board):
    return {(h["machine"], h["team"]): h["ip"] for h in expand_hosts(board)}


class TestFormat:
    def test_a_valid_board_is_accepted_unchanged(self):
        assert normalize_board(copy.deepcopy(V2)) == V2

    def test_the_pattern_skip_and_ips_decide_every_address(self):
        hosts = addresses(V2)
        assert hosts[("DC01", 5)] == "10.5.1.10"            # x is the team number
        assert ("Web", 5) not in hosts and ("Web", 2) in hosts  # skipped
        assert hosts[("Mail", 2)] == "10.2.9.30"            # overridden
        assert hosts[("Mail", 1)] == "10.1.1.30"

    @pytest.mark.parametrize("change, message", [
        (lambda b: b.update(version=3), "unsupported board version"),
        (lambda b: b["teams"].append(1), "team 1 is listed twice"),
        (lambda b: b["machines"].append("Mail2"), "must be an object"),
        (lambda b: b["machines"].append({"name": "New", "ip": "10.x.2.1", "skp": [1]}), "unknown key 'skp'"),
        (lambda b: b["machines"][1].update(skip=[9]), "team 9, which is not in 'teams'"),
        (lambda b: b["machines"][0].update(ip="10.0.1.10"), "no 'x' for the team number"),
        (lambda b: b["machines"][0].update(os=5), "'os' must be text"),
        (lambda b: b["machines"][0].update(services="DNS"), "'services' must be a list"),
        (lambda b: b["machines"][0].update(services=["x" * 33]), "each service must be text"),
        (lambda b: b["machines"].append({"name": "Dup", "ip": "10.x.1.10"}),
         r"host 10.1.1.10 is used twice: 'DC01' team 1 and 'Dup' team 1"),
    ])
    def test_problems_are_reported_by_name(self, change, message):
        with pytest.raises(BoardError, match=message):
            validate_board(broken(change))

    def test_a_file_that_is_neither_format_is_refused(self):
        with pytest.raises(BoardError, match="not a board file"):
            normalize_board({"hello": "world"})

    def test_the_text_reads_back_to_the_same_board(self):
        assert normalize_board(json.loads(format_board(V2))) == V2

    def test_ip_lookups(self):
        team_map, ip_set = build_indexes(V2)
        assert team_map["10.5.1.10"] == "Team 5" and team_map["10.2.9.30"] == "Team 2"
        assert "10.5.1.20" not in ip_set and len(ip_set) == 8


class TestOlderFormat:
    """Existing boards must keep working: they are converted when PWNBoard starts."""

    def test_it_is_converted_to_patterns(self):
        assert normalize_board(copy.deepcopy(V1)) == V1_AS_V2

    def test_cells_follow_the_hosts_team_not_their_position(self):
        old = copy.deepcopy(V1)
        old["board"][0]["hosts"].reverse()
        assert normalize_board(old) == V1_AS_V2

    def test_a_team_without_a_host_is_skipped(self):
        board = normalize_board(old_board(("a", {1: "10.1.1.5", 3: "10.3.1.5"})))
        assert board["machines"] == [{"name": "a", "ip": "10.x.1.5", "skip": [2]}]

    def test_an_address_that_breaks_the_pattern_is_kept_as_an_override(self):
        board = normalize_board(old_board(("a", {1: "10.1.1.5", 2: "10.2.1.5", 3: "10.3.9.5"})))
        assert board["machines"] == [{"name": "a", "ip": "10.x.1.5", "ips": {"3": "10.3.9.5"}}]

    @pytest.mark.parametrize("cells", [
        {1: "10.1.1.5", 2: "10.2.1.5", 3: "10.3.1.5"},
        {1: "10.1.1.5", 2: "192.168.2.7", 3: "10.3.1.5"},
        {1: "web1.example.com", 2: "web2.example.com", 3: "mail"},
        {3: "fe80::3"},
    ])
    def test_no_address_is_ever_changed(self, cells):
        board = normalize_board(old_board(("a", cells)))
        assert {team: ip for (_, team), ip in addresses(board).items()} == cells

    def test_repeated_row_names_are_made_unique(self):
        old = copy.deepcopy(V1)
        old["board"][1]["name"] = "DC01"
        assert [m["name"] for m in normalize_board(old)["machines"]] == ["DC01", "DC01 (2)"]

    @pytest.mark.parametrize("change, message", [
        (lambda b: b["board"][0]["hosts"][0].pop("team"), "missing 'team'"),
        (lambda b: b["board"][0]["hosts"][0].update(team="9"), "team 9 is not in 'teams'"),
        (lambda b: b["board"][1]["hosts"][0].update(ip="10.1.1.10"), "host 10.1.1.10 is used twice"),
    ])
    def test_problems_are_reported(self, change, message):
        old = copy.deepcopy(V1)
        change(old)
        with pytest.raises(BoardError, match=message):
            normalize_board(old)


class TestTestTeams:
    def board(self, **extra):
        return {**copy.deepcopy(V2), **extra}

    def test_a_test_team_is_listed_and_keeps_its_hosts(self):
        board = validate_board(self.board(test_teams=[5, 1]))
        assert marked_test_teams(board) == [5, 1]
        assert build_indexes(board)[0]["10.5.1.10"] == "Team 5"

    def test_a_test_team_must_be_on_the_board(self):
        with pytest.raises(BoardError, match="team 9, which is not in 'teams'"):
            validate_board(self.board(test_teams=[9]))

    def test_they_are_written_and_read_back(self):
        board = self.board(test_teams=[5])
        assert normalize_board(json.loads(format_board(board))) == board


class TestGrid:
    def test_cells_line_up_under_their_team_and_a_skipped_team_is_blank(self):
        rows = board_rows(V2)
        assert rows[0]["hosts"] == [{"ip": "10.1.1.10"}, {"ip": "10.2.1.10"}, {"ip": "10.5.1.10"}]
        assert rows[1]["hosts"] == [{"ip": "10.1.1.20"}, {"ip": "10.2.1.20"}, None]

    def test_os_and_services_come_with_the_row_only_when_set(self):
        rows = board_rows(V2)
        assert (rows[0]["os"], rows[0]["services"]) == ("Windows Server 2019", ["AD", "DNS"])
        assert "os" not in rows[1] and "services" not in rows[1]

    def test_a_skipped_first_team_does_not_shift_the_rest(self):
        board = broken(lambda b: b["machines"][0].update(skip=[1]))
        assert board_rows(board)[0]["hosts"] == [None, {"ip": "10.2.1.10"}, {"ip": "10.5.1.10"}]

    def test_each_call_returns_fresh_cells(self):
        # the dashboard template removes keys from the cells it is given
        board_rows(V2)[0]["hosts"][0]["online"] = True
        assert board_rows(V2)[0]["hosts"][0] == {"ip": "10.1.1.10"}


class TestFiles:
    def write(self, tmp_path, content):
        path = tmp_path / "board.json"
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return path

    def test_both_formats_load_from_a_file(self, tmp_path):
        assert load_board_file(self.write(tmp_path, V2)) == V2
        assert load_board_file(self.write(tmp_path, V1)) == V1_AS_V2

    def test_broken_json_is_reported(self, tmp_path):
        with pytest.raises(BoardError, match="not valid JSON"):
            load_board_file(self.write(tmp_path, "{nope"))

    def test_the_app_loads_the_test_board(self):
        assert board_module.IP_SET == {"10.1.1.1", "10.2.1.1", "10.1.1.2", "10.2.1.2"}
        assert board_module.TEAM_MAP["10.2.1.1"] == "Team 2"


class TestDashboard:
    def test_the_board_dict_has_one_cell_per_team(self):
        rows = data.getBoardDict(FakeBoardDb({}))
        assert [[cell["ip"] for cell in row["hosts"]] for row in rows] == [
            ["10.1.1.1", "10.2.1.1"], ["10.1.1.2", "10.2.1.2"],
        ]

    def test_a_blank_cell_renders_as_an_empty_table_cell(self, client, redis, login):
        rows = [{"name": "box", "hosts": [{"ip": "10.1.1.1"}, None]}]
        redis.set("board_cache", json.dumps(rows))
        html = login("user").get("/pwnboard").get_data(as_text=True)
        assert "10.1.1.1" in html
        assert "<td></td>" in html

    def test_os_and_services_show_under_the_name_and_are_escaped(self, client, redis, login):
        rows = [{"name": "DC01", "os": "Windows <b>2019</b>", "services": ["AD", "DNS"], "hosts": [{"ip": "10.1.1.1"}]},
                {"name": "Plain", "hosts": [{"ip": "10.1.1.2"}]}]
        redis.set("board_cache", json.dumps(rows))
        html = login("user").get("/pwnboard").get_data(as_text=True)
        assert "Windows &lt;b&gt;2019&lt;/b&gt;" in html
        assert html.count('class="badge badge-secondary"') == 2

    def test_only_a_test_teams_header_is_styled(self, client, redis, login, monkeypatch):
        monkeypatch.setattr(routes, "BOARD", {"version": 2, "teams": [1, 5], "test_teams": [5], "machines": []})
        redis.set("board_cache", json.dumps([{"name": "box", "hosts": [{"ip": "10.1.1.1"}, {"ip": "10.5.1.1"}]}]))
        html = login("user").get("/pwnboard").get_data(as_text=True)
        assert html.count('class="team-test"') == 1
        assert "<td>Team 1</td>" in html


def load_script(name):
    path = Path(__file__).parent.parent / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestScripts:
    def test_the_generated_board_is_valid(self):
        config = {"teams": [1, 3], "networks": [
            {"ip": "10.x.1", "hosts": [{"ip": "10", "name": "DC", "os": "Ubuntu", "services": ["SSH"]},
                                       {"ip": "11", "name": "DC"}]},
        ]}
        board = load_script("gen_config").gen_board(config)
        assert validate_board(board) is board
        assert board["machines"][0] == {"name": "DC", "ip": "10.x.1.10", "os": "Ubuntu", "services": ["SSH"]}
        assert addresses(board)[("DC (2)", 3)] == "10.3.1.11"

    def test_the_converter_prints_the_new_format(self, tmp_path, capsys):
        old = tmp_path / "board.json"
        old.write_text(json.dumps(V1))
        assert load_script("convert_board").main([str(old)]) == 0
        assert capsys.readouterr().out == format_board(V1_AS_V2)

    def test_in_place_conversion_keeps_a_backup_and_the_same_file(self, tmp_path):
        old = tmp_path / "board.json"
        old.write_text(json.dumps(V1))
        inode = old.stat().st_ino
        assert load_script("convert_board").main([str(old), "--in-place"]) == 0
        assert old.read_text() == format_board(V1_AS_V2)
        assert json.loads(Path(str(old) + ".bak").read_text()) == V1
        assert old.stat().st_ino == inode  # a Docker bind mount keeps pointing at it

    def test_a_bad_board_is_reported_and_nothing_is_written(self, tmp_path, capsys):
        bad = copy.deepcopy(V1)
        del bad["board"][0]["hosts"][0]["team"]
        path = tmp_path / "board.json"
        path.write_text(json.dumps(bad))
        assert load_script("convert_board").main([str(path), "--in-place"]) == 1
        assert "missing 'team'" in capsys.readouterr().err
        assert not Path(str(path) + ".bak").exists()
