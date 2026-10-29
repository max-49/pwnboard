"""board.json: the version 2 format, the conversion of the older one, and how the grid is built."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

from pwnboard.core import board as board_module, data
from pwnboard.core.board_format import (
    BoardError, board_rows, build_indexes, load_board_file, normalize_board, team_ids, validate_board,
)
from tests.test_host_info import FakeBoardDb

V2 = {
    "version": 2,
    "teams": [{"id": 1}, {"id": 5}],
    "machines": ["DC01", "Web"],
    "hosts": [
        {"ip": "10.1.1.10", "team": 1, "machine": "DC01"},
        {"ip": "10.5.1.10", "team": 5, "machine": "DC01"},
        {"ip": "10.1.1.20", "team": 1, "machine": "Web"},
    ],
}

V1 = {
    "teams": [1, 2],
    "board": [
        {"name": "DC01", "hosts": [{"ip": "10.1.1.10", "team": "1"}, {"ip": "10.2.1.10", "team": "2"}]},
        {"name": "Web", "hosts": [{"ip": "10.1.1.20", "team": "1"}, {"ip": "10.2.1.20", "team": "2"}]},
    ],
}


def broken(change):
    board = copy.deepcopy(V2)
    change(board)
    return board


class TestVersion2:
    def test_a_valid_board_is_accepted_unchanged(self):
        assert normalize_board(copy.deepcopy(V2)) == V2

    def test_team_numbers_do_not_have_to_be_contiguous(self):
        assert team_ids(V2) == [1, 5]

    @pytest.mark.parametrize("change, message", [
        (lambda b: b.update(version=3), "unsupported board version"),
        (lambda b: b["teams"].append({"id": 1}), "team 1 is listed twice"),
        (lambda b: b["teams"].append({"id": "7"}), "whole number 'id'"),
        (lambda b: b["teams"].append({"id": True}), "whole number 'id'"),
        (lambda b: b["machines"].append("DC01"), "'DC01' is listed twice"),
        (lambda b: b["machines"].append(" "), "needs a name"),
        (lambda b: b["hosts"].append({"ip": "10.1.1.10", "team": 5, "machine": "Web"}), "10.1.1.10 is listed twice"),
        (lambda b: b["hosts"].append({"ip": "", "team": 1, "machine": "Web"}), "needs an 'ip'"),
        (lambda b: b["hosts"].append({"ip": "10.9.1.1", "team": 9, "machine": "Web"}), "team 9 is not in 'teams'"),
        (lambda b: b["hosts"].append({"ip": "10.9.1.1", "team": 5, "machine": "Mail"}), "'Mail' is not in 'machines'"),
        (lambda b: b["hosts"].append({"ip": "10.9.1.1", "team": 1, "machine": "DC01"}), "two hosts for team 1"),
        (lambda b: b.pop("hosts"), "'hosts' must be a list"),
    ])
    def test_problems_are_reported_by_name(self, change, message):
        with pytest.raises(BoardError, match=message):
            validate_board(broken(change))

    def test_a_file_that_is_neither_format_is_refused(self):
        with pytest.raises(BoardError):
            normalize_board({"hello": "world"})
        with pytest.raises(BoardError):
            normalize_board([])


class TestOlderFormat:
    def test_it_is_converted(self):
        board = normalize_board(copy.deepcopy(V1))
        assert team_ids(board) == [1, 2]
        assert board["machines"] == ["DC01", "Web"]
        assert {"ip": "10.2.1.20", "team": 2, "machine": "Web"} in board["hosts"]
        assert len(board["hosts"]) == 4

    def test_cells_follow_the_hosts_team_not_their_position(self):
        old = copy.deepcopy(V1)
        old["board"][0]["hosts"].reverse()
        board = normalize_board(old)
        assert {"ip": "10.1.1.10", "team": 1, "machine": "DC01"} in board["hosts"]

    def test_repeated_row_names_are_made_unique(self):
        old = copy.deepcopy(V1)
        old["board"][1]["name"] = "DC01"
        assert normalize_board(old)["machines"] == ["DC01", "DC01 (2)"]

    def test_a_row_without_a_name_gets_one(self):
        old = copy.deepcopy(V1)
        del old["board"][0]["name"]
        assert normalize_board(old)["machines"][0] == "Machine 1"

    def test_a_host_without_a_team_is_refused(self):
        old = copy.deepcopy(V1)
        del old["board"][0]["hosts"][0]["team"]
        with pytest.raises(BoardError, match="missing 'team'"):
            normalize_board(old)

    def test_a_team_that_is_not_a_number_is_refused(self):
        old = copy.deepcopy(V1)
        old["teams"][0] = "alpha"
        with pytest.raises(BoardError, match="whole number"):
            normalize_board(old)


class TestIndexes:
    def test_ip_lookups(self):
        team_map, ip_set = build_indexes(V2)
        assert team_map["10.5.1.10"] == "Team 5"
        assert ip_set == {"10.1.1.10", "10.5.1.10", "10.1.1.20"}


class TestGrid:
    def test_cells_line_up_under_their_team(self):
        rows = board_rows(V2)
        assert [row["name"] for row in rows] == ["DC01", "Web"]
        assert rows[0]["hosts"] == [{"ip": "10.1.1.10"}, {"ip": "10.5.1.10"}]

    def test_a_missing_host_leaves_a_blank_cell_without_shifting_the_others(self):
        # Web has no team 5 host; the Web row keeps team 1's host under team 1
        assert board_rows(V2)[1]["hosts"] == [{"ip": "10.1.1.20"}, None]

    def test_a_missing_host_in_the_first_column_does_not_shift_the_second(self):
        board = broken(lambda b: b["hosts"].pop(0))
        assert board_rows(board)[0]["hosts"] == [None, {"ip": "10.5.1.10"}]

    def test_each_call_returns_fresh_cells(self):
        board_rows(V2)[0]["hosts"][0]["online"] = True
        assert board_rows(V2)[0]["hosts"][0] == {"ip": "10.1.1.10"}


class TestFiles:
    def write(self, tmp_path, content):
        path = tmp_path / "board.json"
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return path

    def test_both_formats_load_from_a_file(self, tmp_path):
        assert load_board_file(self.write(tmp_path, V2)) == V2
        assert team_ids(load_board_file(self.write(tmp_path, V1))) == [1, 2]

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


class TestGenerator:
    @pytest.fixture
    def gen_config(self):
        path = Path(__file__).parent.parent / "scripts" / "gen_config.py"
        spec = importlib.util.spec_from_file_location("gen_config", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_the_generated_board_is_valid(self, gen_config):
        config = {"teams": [1, 3], "networks": [
            {"ip": "10.x.1", "hosts": [{"ip": "10", "name": "DC"}, {"ip": "11", "name": "DC"}]},
        ]}
        board = gen_config.gen_board(config)
        assert validate_board(board) is board
        assert board["machines"] == ["DC", "DC (2)"]
        assert {"ip": "10.3.1.11", "team": 3, "machine": "DC (2)"} in board["hosts"]


class TestConverter:
    @pytest.fixture
    def convert_board(self):
        path = Path(__file__).parent.parent / "scripts" / "convert_board.py"
        spec = importlib.util.spec_from_file_location("convert_board", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @pytest.fixture
    def old_file(self, tmp_path):
        path = tmp_path / "board.json"
        path.write_text(json.dumps(V1))
        return path

    def test_it_prints_the_new_format_by_default(self, convert_board, old_file, capsys):
        assert convert_board.main([str(old_file)]) == 0
        out = capsys.readouterr().out
        assert normalize_board(json.loads(out)) == normalize_board(copy.deepcopy(V1))
        assert json.loads(out)["version"] == 2

    def test_it_writes_an_output_file_and_leaves_the_input_alone(self, convert_board, old_file, tmp_path):
        new = tmp_path / "new.json"
        assert convert_board.main([str(old_file), str(new)]) == 0
        assert json.loads(new.read_text())["version"] == 2
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
        assert json.loads(old_file.read_text())["version"] == 2
        assert json.loads(Path(str(old_file) + ".bak").read_text()) == V1
        assert old_file.stat().st_ino == inode

    def test_converting_a_new_board_changes_nothing(self, convert_board, tmp_path, capsys):
        path = tmp_path / "board.json"
        path.write_text(json.dumps(V2))
        assert convert_board.main([str(path)]) == 0
        assert json.loads(capsys.readouterr().out) == V2

    def test_renamed_rows_are_reported(self, convert_board, tmp_path, capsys):
        old = copy.deepcopy(V1)
        old["board"][1]["name"] = "DC01"
        path = tmp_path / "board.json"
        path.write_text(json.dumps(old))
        assert convert_board.main([str(path)]) == 0
        assert "renamed 'DC01 (2)'" in capsys.readouterr().err

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
