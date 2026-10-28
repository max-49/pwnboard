"""Host information: key/value notes that tools attach to a host (POST /info), the worker that
stores them, and how they show up on the board and in the host popup."""
import json
import logging

import pytest

from pwnboard.core import data, info
from pwnboard.core.schema import DATA_TABLES, _TABLES_DDL
from pwnboard.worker import __main__ as worker
from pwnboard.worker.reset import REDIS_KEYS
from tests.conftest import IP_A, IP_B

BODY = {"ip": IP_A, "application": "c2", "key": "hostname", "value": "web-01"}


def queued(redis):
    return [json.loads(item) for item in redis.lrange("info_queue", 0, -1)]


class TestInfoEndpoint:
    def test_valid_note_is_queued(self, client, redis, tokens_disabled):
        response = client.post("/info", json=BODY)
        assert response.status_code == 200
        assert response.get_data(as_text=True) == "valid\n"
        [item] = queued(redis)
        assert (item["ip"], item["application"], item["key"], item["value"]) == (IP_A, "c2", "hostname", "web-01")
        assert redis.llen("callback_queue") == redis.llen("creds_queue") == 0

    def test_key_and_value_are_trimmed(self, client, redis, tokens_disabled):
        client.post("/info", json={**BODY, "key": "  hostname ", "value": "  web-01\n"})
        [item] = queued(redis)
        assert (item["key"], item["value"]) == ("hostname", "web-01")

    def test_an_empty_value_is_accepted_because_it_deletes_the_note(self, client, redis, tokens_disabled):
        for value in ("", "   "):
            assert client.post("/info", json={**BODY, "value": value}).status_code == 200
        assert [item["value"] for item in queued(redis)] == ["", ""]

    def test_ips_sends_the_note_for_several_hosts(self, client, redis, tokens_disabled):
        body = {k: v for k, v in BODY.items() if k != "ip"}
        assert client.post("/info", json={**body, "ips": [IP_A, IP_B]}).status_code == 200
        assert sorted(item["ip"] for item in queued(redis)) == sorted([IP_A, IP_B])

    @pytest.mark.parametrize("missing", ["application", "key", "value"])
    def test_required_fields(self, client, redis, tokens_disabled, missing):
        response = client.post("/info", json={k: v for k, v in BODY.items() if k != missing})
        assert response.status_code == 400
        assert response.get_data(as_text=True) == "Invalid: Missing 'application', 'key' or 'value' in the request\n"

    @pytest.mark.parametrize("body, message", [
        ({**BODY, "key": "k" * 65}, "Invalid: 'key' must be a string of at most 64 characters\n"),
        ({**BODY, "key": 5}, "Invalid: 'key' must be a string of at most 64 characters\n"),
        ({**BODY, "value": "v" * 1001}, "Invalid: 'value' must be a string of at most 1000 characters\n"),
        ({**BODY, "value": ["x"]}, "Invalid: 'value' must be a string of at most 1000 characters\n"),
        ({**BODY, "key": "   "}, "Invalid: 'key' must not be empty\n"),
        ({**BODY, "ip": "9.9.9.9"}, "invalid IP\n"),
    ])
    def test_bad_notes_are_rejected_and_not_queued(self, client, redis, tokens_disabled, body, message):
        response = client.post("/info", json=body)
        assert response.status_code == 400
        assert response.get_data(as_text=True) == message
        assert redis.llen("info_queue") == 0

    def test_limits_are_accepted_exactly(self, client, redis, tokens_disabled):
        assert client.post("/info", json={**BODY, "key": "k" * 64, "value": "v" * 1000}).status_code == 200

    def test_the_other_ingest_endpoints_still_accept_fields_named_key_and_value(self, client, redis, tokens_disabled):
        response = client.post("/pwn", json={"ip": IP_A, "application": "c2", "key": 5, "value": ["anything"]})
        assert response.status_code == 200

    def test_needs_a_token_for_the_notes_application(self, client, redis, tokens_enabled, valid_token):
        assert client.post("/info", json=BODY).status_code == 401
        assert client.post("/info", json=BODY, headers={"Authorization": "Bearer abc"}).status_code == 200
        assert valid_token == [("abc", "c2")]


class TestHostInfoRead:
    def test_requires_a_login(self, client):
        assert client.get(f"/hosts/{IP_A}/info").status_code == 401

    def test_unknown_addresses_are_a_404(self, login, db):
        assert login("user").get("/hosts/9.9.9.9/info").status_code == 404

    @pytest.mark.parametrize("role", ["admin", "user", "guest", "restricted"])
    def test_every_role_can_read_notes(self, login, db, role):
        db.cur.fetchall.return_value = [("hostname", "web-01", "c2", 1760000000), ("os", "Ubuntu 24.04", "scanner", 1760000100)]
        response = login(role).get(f"/hosts/{IP_A}/info")
        assert response.status_code == 200
        assert response.get_json() == [
            {"key": "hostname", "value": "web-01", "application": "c2", "updated": 1760000000},
            {"key": "os", "value": "Ubuntu 24.04", "application": "scanner", "updated": 1760000100},
        ]
        assert db.cur.execute.call_args.args[1] == (IP_A,)

    def test_a_host_without_notes_returns_an_empty_list(self, login, db):
        assert login("user").get(f"/hosts/{IP_A}/info").get_json() == []


class FakeHostInfoTable:
    """Just enough of the host_info table for the SQL that core.info runs."""

    def __init__(self):
        self.rows = {}  # (ip, key) -> (value, application)
        self._one = None

    def execute(self, sql, params=None):
        query = " ".join(sql.split())
        if query.startswith("DELETE FROM host_info"):
            self.rows.pop(tuple(params), None)
        elif query.startswith("SELECT count(*)"):
            key, ip = params
            keys = [k for (i, k) in self.rows if i == ip]
            self._one = (len(keys), key in keys)
        elif query.startswith("INSERT INTO host_info"):
            ip, key, value, application = params
            self.rows[(ip, key)] = (value, application)
        else:
            raise AssertionError(f"unexpected SQL: {query}")

    def fetchone(self):
        return self._one

    def keys(self, ip):
        return sorted(k for (i, k) in self.rows if i == ip)


class TestApplyInfoItem:
    def test_set_overwrite_and_delete(self):
        table = FakeHostInfoTable()
        assert info.apply_info_item(table, IP_A, "hostname", "web-01", "c2") == info.SET
        assert table.rows[(IP_A, "hostname")] == ("web-01", "c2")

        # another tool overwrites the same key: one note, not two
        assert info.apply_info_item(table, IP_A, "hostname", "web-01.corp", "scanner") == info.SET
        assert table.rows == {(IP_A, "hostname"): ("web-01.corp", "scanner")}

        assert info.apply_info_item(table, IP_A, "hostname", "", "c2") == info.DELETED
        assert table.rows == {}

    def test_deleting_a_missing_note_is_fine(self):
        assert info.apply_info_item(FakeHostInfoTable(), IP_A, "nope", "", "c2") == info.DELETED

    def test_keys_are_per_host(self):
        table = FakeHostInfoTable()
        info.apply_info_item(table, IP_A, "hostname", "a", "c2")
        info.apply_info_item(table, IP_B, "hostname", "b", "c2")
        assert table.rows[(IP_A, "hostname")][0] == "a" and table.rows[(IP_B, "hostname")][0] == "b"

    def test_a_host_holds_at_most_the_maximum_number_of_keys(self):
        table = FakeHostInfoTable()
        for n in range(info.MAX_KEYS_PER_HOST):
            assert info.apply_info_item(table, IP_A, f"key{n}", "v", "c2") == info.SET
        assert info.apply_info_item(table, IP_A, "one-too-many", "v", "c2") == info.REJECTED
        assert "one-too-many" not in table.keys(IP_A)
        # existing keys can still be updated and deleted, and a delete frees a slot
        assert info.apply_info_item(table, IP_A, "key0", "new value", "c2") == info.SET
        assert info.apply_info_item(table, IP_A, "key1", "", "c2") == info.DELETED
        assert info.apply_info_item(table, IP_A, "one-too-many", "v", "c2") == info.SET
        # other hosts are not affected by this host being full
        assert info.apply_info_item(table, IP_B, "hostname", "x", "c2") == info.SET


class TestWorker:
    def item(self, **fields):
        return json.dumps({**BODY, **fields})

    def run(self, items, monkeypatch):
        table = FakeHostInfoTable()

        class Db:
            def cursor(self_inner):
                return self_inner
            def __enter__(self_inner):
                return table
            def __exit__(self_inner, *exc):
                return False

        worker.process_info(items, Db())
        return table

    def test_items_apply_in_order_so_the_last_write_wins(self, monkeypatch):
        table = self.run([
            self.item(value="first"), self.item(value="second"),
            self.item(key="os", value="Linux"), self.item(key="os", value=""),
        ], monkeypatch)
        assert table.rows == {(IP_A, "hostname"): ("second", "c2")}

    def test_malformed_items_are_skipped_not_fatal(self, monkeypatch, caplog):
        broken = ["{not json", json.dumps({"ip": IP_A}), json.dumps(["list"]), self.item(value=5)]
        with caplog.at_level(logging.WARNING, logger="pwnboard"):
            table = self.run(broken + [self.item(key="good", value="kept")], monkeypatch)
        assert table.keys(IP_A) == ["good"]
        assert caplog.text.count("malformed") >= 3

    def test_an_empty_batch_does_nothing(self, monkeypatch):
        assert self.run([], monkeypatch).rows == {}


class FakeBoardDb:
    """No callbacks or credentials for any host; the host_info counts are configurable."""

    def __init__(self, counts, fail=False):
        self.counts, self.fail, self.rolled_back = counts, fail, False
        self._sql = ""

    def cursor(self, *args, **kwargs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self._sql = " ".join(sql.split())
        if "FROM host_info" in self._sql and self.fail:
            raise RuntimeError("table is missing")

    def fetchone(self):
        return None

    def fetchall(self):
        return list(self.counts.items()) if "FROM host_info" in self._sql else []

    def rollback(self):
        self.rolled_back = True

    def commit(self):
        pass


class TestBoard:
    def hosts(self, board):
        return {host["ip"]: host for row in board for host in row["hosts"]}

    def test_hosts_with_notes_are_marked(self):
        hosts = self.hosts(data.getBoardDict(FakeBoardDb({IP_A: 2})))
        assert hosts[IP_A]["Info"] == "Yes"
        assert "Info" not in hosts[IP_B]

    def test_the_board_is_still_built_when_the_notes_cannot_be_counted(self):
        db = FakeBoardDb({IP_A: 2}, fail=True)
        hosts = self.hosts(data.getBoardDict(db))
        assert db.rolled_back
        assert IP_A in hosts and "Info" not in hosts[IP_A]


class TestDashboard:
    def page(self, client, redis, login, hosts):
        redis.set("board_cache", json.dumps([{"name": "box", "hosts": hosts}]))
        return login("user").get("/pwnboard").get_data(as_text=True)

    def test_only_hosts_with_notes_get_an_information_section(self, client, redis, login):
        html = self.page(client, redis, login, [{"ip": IP_A, "Info": "Yes"}, {"ip": IP_B}])
        assert html.count('class="host-info"') == 1
        assert f'class="host-info" data-ip="{IP_A}"' in html
        assert "Info: Yes" in html

    def test_the_page_loads_the_scripts_that_fill_the_section(self, client, redis, login):
        html = self.page(client, redis, login, [{"ip": IP_A, "Info": "Yes"}])
        assert "/static/escape.js" in html and "/static/api.js" in html and "loadHostInfo" in html


class TestHousekeeping:
    def test_the_table_is_created_and_covered_by_reset_and_grafana(self):
        assert "CREATE TABLE IF NOT EXISTS host_info" in _TABLES_DDL
        assert "host_info" in DATA_TABLES
        assert "info_queue" in REDIS_KEYS
