"""board.json: the version 2 format, the conversion of the older one, and how the grid is built."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

from pwnboard.core import board as board_module, data
from pwnboard.web import routes
from pwnboard.core.board_format import (
    BoardError, board_rows, build_indexes, expand_hosts, format_board, load_board_file,
    normalize_board, team_ids, marked_test_teams, validate_board,
)
from tests.test_host_info import FakeBoardDb

V2 = {
    "version": 2,
    "teams": [1, 2, 5],
    "machines": [
        {"name": "DC01", "ip": "10.x.1.10"},
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


class TestVersion2:
    def test_a_valid_board_is_accepted_unchanged(self):
        assert normalize_board(copy.deepcopy(V2)) == V2

    def test_the_team_number_is_put_in_place_of_every_x(self):
        assert addresses(V2)[("DC01", 5)] == "10.5.1.10"
        assert addresses({"version": 2, "teams": [3], "machines": [{"name": "m", "ip": "10.x.x.1"}]})[("m", 3)] == "10.3.3.1"

    def test_team_numbers_do_not_have_to_be_contiguous(self):
        assert team_ids(V2) == [1, 2, 5]

    def test_skip_leaves_out_a_team(self):
        hosts = addresses(V2)
        assert ("Web", 5) not in hosts and ("Web", 2) in hosts

    def test_ips_replaces_one_teams_address(self):
        hosts = addresses(V2)
        assert hosts[("Mail", 2)] == "10.2.9.30"
        assert hosts[("Mail", 1)] == "10.1.1.30" and hosts[("Mail", 5)] == "10.5.1.30"

    def test_a_machine_without_x_is_fine_when_only_one_team_uses_it(self):
        board = {"version": 2, "teams": [1, 2], "machines": [{"name": "m", "ip": "10.0.0.9", "skip": [2]}]}
        assert addresses(validate_board(board)) == {("m", 1): "10.0.0.9"}

    @pytest.mark.parametrize("change, message", [
        (lambda b: b.update(version=3), "unsupported board version"),
        (lambda b: b["teams"].append(1), "team 1 is listed twice"),
        (lambda b: b["teams"].append("7"), "whole numbers"),
        (lambda b: b["teams"].append(True), "whole numbers"),
        (lambda b: b.update(teams={"id": 1}), "'teams' must be a list"),
        (lambda b: b.update(machines="DC01"), "'machines' must be a list"),
        (lambda b: b["machines"].append("Mail2"), "must be an object"),
        (lambda b: b["machines"].append({"ip": "10.x.2.1"}), "needs a 'name'"),
        (lambda b: b["machines"].append({"name": " ", "ip": "10.x.2.1"}), "needs a 'name'"),
        (lambda b: b["machines"].append({"name": "DC01", "ip": "10.x.2.1"}), "'DC01' is listed twice"),
        (lambda b: b["machines"].append({"name": "New"}), "needs an 'ip' pattern"),
        (lambda b: b["machines"].append({"name": "New", "ip": "10.x.2.1", "skp": [1]}), "unknown key 'skp'"),
        (lambda b: b["machines"][1].update(skip=[9]), "team 9, which is not in 'teams'"),
        (lambda b: b["machines"][1].update(skip=5), "'skip' must be a list"),
        (lambda b: b["machines"][2]["ips"].update({"9": "10.9.9.9"}), "team '9', which is not in 'teams'"),
        (lambda b: b["machines"][2]["ips"].update({"two": "10.9.9.9"}), "team 'two'"),
        (lambda b: b["machines"][2].update(ips={"2": 5}), "must be text"),
        (lambda b: b["machines"][2].update(skip=[2]), "both skipped and given an address"),
        (lambda b: b["machines"][0].update(ip="10.0.1.10"), "no 'x' for the team number"),
        (lambda b: b["machines"].append({"name": "Dup", "ip": "10.x.1.10"}),
         r"host 10.1.1.10 is used twice: 'DC01' team 1 and 'Dup' team 1"),
        (lambda b: b["machines"][2]["ips"].update({"2": "10.2.1.10"}), "host 10.2.1.10 is used twice"),
    ])
    def test_problems_are_reported_by_name(self, change, message):
        with pytest.raises(BoardError, match=message):
            validate_board(broken(change))

    def test_a_file_that_is_neither_format_is_refused(self):
        with pytest.raises(BoardError, match="not a board file"):
            normalize_board({"hello": "world"})
        with pytest.raises(BoardError):
            normalize_board([])


class TestOlderFormat:
    def test_it_is_converted_to_patterns(self):
        assert normalize_board(copy.deepcopy(V1)) == V1_AS_V2

    def test_the_addresses_do_not_change(self):
        assert addresses(normalize_board(copy.deepcopy(V1))) == {
            ("DC01", 1): "10.1.1.10", ("DC01", 2): "10.2.1.10",
            ("Web", 1): "10.1.1.20", ("Web", 2): "10.2.1.20",
        }

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

    def test_a_machine_with_one_host_takes_the_pattern_of_the_others(self):
        board = normalize_board(old_board(
            ("a", {1: "10.1.1.5", 2: "10.2.1.5", 3: "10.3.1.5"}),
            ("b", {2: "10.2.1.30"}),
        ))
        assert board["machines"][1] == {"name": "b", "ip": "10.x.1.30", "skip": [1, 3]}

    def test_a_machine_with_one_host_and_nothing_to_go_on_keeps_its_address(self):
        board = normalize_board(old_board(("a", {2: "10.2.1.30"})))
        assert board["machines"] == [{"name": "a", "ip": "10.2.1.30", "skip": [1, 3]}]

    def test_a_row_with_no_hosts_is_kept_with_every_team_skipped(self):
        board = normalize_board(old_board(("empty", {}), ("a", {1: "10.1.1.5", 2: "10.2.1.5"}), teams=(1, 2)))
        assert board["machines"][0]["skip"] == [1, 2]
        assert ("empty", 1) not in addresses(board)

    def test_the_team_number_can_be_in_several_places(self):
        board = normalize_board(old_board(("a", {1: "10.1.1.1", 2: "10.2.1.2"}), teams=(1, 2)))
        assert addresses(board) == {("a", 1): "10.1.1.1", ("a", 2): "10.2.1.2"}

    @pytest.mark.parametrize("cells", [
        {1: "10.1.1.5", 2: "10.2.1.5", 3: "10.3.1.5"},
        {1: "10.1.1.5", 2: "192.168.2.7", 3: "10.3.1.5"},
        {1: "web1.example.com", 2: "web2.example.com", 3: "mail"},
        {1: "10.0.0.1", 2: "10.0.0.2"},
        {3: "fe80::3"},
        {1: "box.x.example", 2: "10.2.1.1"},
    ])
    def test_no_address_is_ever_changed(self, cells):
        board = normalize_board(old_board(("a", cells)))
        assert {team: ip for (_, team), ip in addresses(board).items()} == cells

    def test_repeated_row_names_are_made_unique(self):
        old = copy.deepcopy(V1)
        old["board"][1]["name"] = "DC01"
        assert [m["name"] for m in normalize_board(old)["machines"]] == ["DC01", "DC01 (2)"]

    def test_a_row_without_a_name_gets_one(self):
        old = copy.deepcopy(V1)
        del old["board"][0]["name"]
        assert normalize_board(old)["machines"][0]["name"] == "Machine 1"

    @pytest.mark.parametrize("change, message", [
        (lambda b: b["board"][0]["hosts"][0].pop("team"), "missing 'team'"),
        (lambda b: b["teams"].__setitem__(0, "alpha"), "whole number"),
        (lambda b: b["board"][0]["hosts"][0].update(team="9"), "team 9 is not in 'teams'"),
        (lambda b: b["board"][0]["hosts"].append({"ip": "10.1.1.99", "team": "1"}), "two hosts for team 1"),
        (lambda b: b["board"][0]["hosts"][0].update(ip=5), "the ip must be text"),
        (lambda b: b["board"][1]["hosts"][0].update(ip="10.1.1.10"), "host 10.1.1.10 is used twice"),
        (lambda b: b.update(board="rows"), "'teams' list and a 'board' list"),
        (lambda b: b["board"].append("row"), "board row 3"),
    ])
    def test_problems_are_reported(self, change, message):
        old = copy.deepcopy(V1)
        change(old)
        with pytest.raises(BoardError, match=message):
            normalize_board(old)


class TestTestTeams:
    def board(self, **extra):
        return {**copy.deepcopy(V2), **extra}

    def test_none_by_default(self):
        assert marked_test_teams(V2) == []

    def test_they_are_listed(self):
        assert marked_test_teams(validate_board(self.board(test_teams=[5, 1]))) == [5, 1]

    def test_a_test_team_still_has_its_hosts(self):
        board = validate_board(self.board(test_teams=[5]))
        assert addresses(board)[("DC01", 5)] == "10.5.1.10"
        assert build_indexes(board)[0]["10.5.1.10"] == "Team 5"

    @pytest.mark.parametrize("value, message", [
        ([9], "team 9, which is not in 'teams'"),
        (["5"], "team '5'"),
        ([True], "team True"),
        (5, "'test_teams' must be a list"),
        ([5, 5], "lists a team twice"),
    ])
    def test_problems_are_reported(self, value, message):
        with pytest.raises(BoardError, match=message):
            validate_board(self.board(test_teams=value))

    def test_they_are_written_and_read_back(self):
        board = self.board(test_teams=[5])
        text = format_board(board)
        assert '  "test_teams": [5],\n  "machines"' in text
        assert normalize_board(json.loads(text)) == board

    def test_nothing_is_written_when_there_are_none(self):
        assert "test_teams" not in format_board(self.board(test_teams=[]))


class TestIndexes:
    def test_ip_lookups(self):
        team_map, ip_set = build_indexes(V2)
        assert team_map["10.5.1.10"] == "Team 5"
        assert team_map["10.2.9.30"] == "Team 2"
        assert "10.5.1.20" not in ip_set and "10.1.1.20" in ip_set
        assert len(ip_set) == 8


class TestGrid:
    def test_cells_line_up_under_their_team(self):
        rows = board_rows(V2)
        assert [row["name"] for row in rows] == ["DC01", "Web", "Mail"]
        assert rows[0]["hosts"] == [{"ip": "10.1.1.10"}, {"ip": "10.2.1.10"}, {"ip": "10.5.1.10"}]

    def test_a_skipped_team_leaves_a_blank_cell_without_shifting_the_others(self):
        assert board_rows(V2)[1]["hosts"] == [{"ip": "10.1.1.20"}, {"ip": "10.2.1.20"}, None]

    def test_a_skipped_first_team_does_not_shift_the_rest(self):
        board = broken(lambda b: b["machines"][0].update(skip=[1]))
        assert board_rows(board)[0]["hosts"] == [None, {"ip": "10.2.1.10"}, {"ip": "10.5.1.10"}]

    def test_each_call_returns_fresh_cells(self):
        board_rows(V2)[0]["hosts"][0]["online"] = True
        assert board_rows(V2)[0]["hosts"][0] == {"ip": "10.1.1.10"}


class TestFormatting:
    def test_one_line_per_machine(self):
        assert format_board(V2) == (
            '{\n'
            '  "version": 2,\n'
            '  "teams": [1, 2, 5],\n'
            '  "machines": [\n'
            '    {"name": "DC01", "ip": "10.x.1.10"},\n'
            '    {"name": "Web", "ip": "10.x.1.20", "skip": [5]},\n'
            '    {"name": "Mail", "ip": "10.x.1.30", "ips": {"2": "10.2.9.30"}}\n'
            '  ]\n'
            '}\n'
        )

    def test_the_text_reads_back_to_the_same_board(self):
        assert normalize_board(json.loads(format_board(V2))) == V2

    def test_a_board_with_no_machines_can_be_written(self):
        board = {"version": 2, "teams": [1], "machines": []}
        assert normalize_board(json.loads(format_board(board))) == board


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

    def test_a_missing_file_is_left_to_the_caller(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_board_file(tmp_path / "missing.json")

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


class TestTestTeamHeader:
    def page(self, login, redis, monkeypatch, board):
        monkeypatch.setattr(routes, "BOARD", board)
        redis.set("board_cache", json.dumps([{"name": "box", "hosts": [{"ip": "10.1.1.1"}, {"ip": "10.5.1.1"}]}]))
        return login("user").get("/pwnboard").get_data(as_text=True)

    def test_a_test_team_header_is_labelled_and_styled(self, client, redis, login, monkeypatch):
        html = self.page(login, redis, monkeypatch, {"version": 2, "teams": [1, 5], "test_teams": [5], "machines": []})
        assert 'class="team-test"' in html
        assert "Team 5 <span" in html and ">TEST</span>" in html
        assert html.count("TEST</span>") == 1
        assert "<td>Team 1</td>" in html

    def test_without_test_teams_nothing_is_marked(self, client, redis, login, monkeypatch):
        html = self.page(login, redis, monkeypatch, {"version": 2, "teams": [1, 5], "machines": []})
        assert "team-test" not in html and "TEST</span>" not in html


def load_script(name):
    path = Path(__file__).parent.parent / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestGenerator:
    def test_the_generated_board_is_valid(self):
        config = {"teams": [1, 3], "networks": [
            {"ip": "10.x.1", "hosts": [{"ip": "10", "name": "DC"}, {"ip": "11", "name": "DC"}]},
        ]}
        board = load_script("gen_config").gen_board(config)
        assert board == {"version": 2, "teams": [1, 3], "machines": [
            {"name": "DC", "ip": "10.x.1.10"}, {"name": "DC (2)", "ip": "10.x.1.11"},
        ]}
        assert validate_board(board) is board
        assert addresses(board)[("DC (2)", 3)] == "10.3.1.11"


class TestConverter:
    @pytest.fixture
    def convert_board(self):
        return load_script("convert_board")

    @pytest.fixture
    def old_file(self, tmp_path):
        path = tmp_path / "board.json"
        path.write_text(json.dumps(V1))
        return path

    def test_it_prints_the_new_format_by_default(self, convert_board, old_file, capsys):
        assert convert_board.main([str(old_file)]) == 0
        captured = capsys.readouterr()
        assert captured.out == format_board(V1_AS_V2)
        assert "2 teams, 2 machines, 4 hosts" in captured.err

    def test_it_writes_an_output_file_and_leaves_the_input_alone(self, convert_board, old_file, tmp_path):
        new = tmp_path / "new.json"
        assert convert_board.main([str(old_file), str(new)]) == 0
        assert new.read_text() == format_board(V1_AS_V2)
        assert json.loads(old_file.read_text()) == V1

    def test_it_will_not_overwrite_an_output_file_without_force(self, convert_board, old_file, tmp_path):
        new = tmp_path / "new.json"
        new.write_text("keep me")
        assert convert_board.main([str(old_file), str(new)]) == 1
        assert new.read_text() == "keep me"
        assert convert_board.main([str(old_file), str(new), "--force"]) == 0

    def test_in_place_keeps_a_backup_and_the_same_file(self, convert_board, old_file):
        inode = old_file.stat().st_ino
        assert convert_board.main([str(old_file), "--in-place"]) == 0
        assert old_file.read_text() == format_board(V1_AS_V2)
        assert json.loads(Path(str(old_file) + ".bak").read_text()) == V1
        assert old_file.stat().st_ino == inode

    def test_converting_a_new_board_changes_nothing(self, convert_board, tmp_path, capsys):
        path = tmp_path / "board.json"
        path.write_text(format_board(V2))
        assert convert_board.main([str(path)]) == 0
        assert capsys.readouterr().out == format_board(V2)

    def test_test_teams_survive_the_conversion(self, convert_board, tmp_path, capsys):
        board = {**copy.deepcopy(V2), "test_teams": [5]}
        path = tmp_path / "board.json"
        path.write_text(format_board(board))
        assert convert_board.main([str(path)]) == 0
        assert capsys.readouterr().out == format_board(board)

    def test_renamed_rows_are_reported(self, convert_board, tmp_path, capsys):
        old = copy.deepcopy(V1)
        old["board"][1]["name"] = "DC01"
        path = tmp_path / "board.json"
        path.write_text(json.dumps(old))
        assert convert_board.main([str(path)]) == 0
        assert "renamed 'DC01 (2)'" in capsys.readouterr().err

    def test_irregular_addresses_are_reported(self, convert_board, tmp_path, capsys):
        path = tmp_path / "board.json"
        path.write_text(json.dumps(old_board(("a", {1: "10.1.1.5", 2: "10.2.1.5", 3: "10.3.9.5"}))))
        assert convert_board.main([str(path)]) == 0
        captured = capsys.readouterr()
        assert '"ips": {"3": "10.3.9.5"}' in captured.out
        assert "do not follow its pattern" in captured.err

    def test_a_bad_board_is_reported_and_nothing_is_written(self, convert_board, tmp_path, capsys):
        bad = copy.deepcopy(V1)
        del bad["board"][0]["hosts"][0]["team"]
        path = tmp_path / "board.json"
        path.write_text(json.dumps(bad))
        assert convert_board.main([str(path), "--in-place"]) == 1
        assert "missing 'team'" in capsys.readouterr().err
        assert not Path(str(path) + ".bak").exists()

    def test_a_missing_file_is_reported(self, convert_board, tmp_path, capsys):
        assert convert_board.main([str(tmp_path / "nope.json")]) == 1
        assert "no such file" in capsys.readouterr().err
