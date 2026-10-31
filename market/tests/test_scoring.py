import json
import threading

from pwnmarket.scoring import parse_round_update, parse_sse, stream_rounds

PAYLOAD = {
    "round": 7,
    "responses": [
        {"check_id": c, "user_id": u, "status": "completed", "success": True, "check_output": ""}
        for u in (5, 6) for c in (1, 2, 3)
    ],
    "scores": [
        {"id": 5, "name": "team01", "team_number": 1, "uptime_score": 20, "last_round_points": 3},
        {"id": 6, "name": "team02", "team_number": 2, "uptime_score": 18, "last_round_points": 2},
    ],
}


def test_parse_sse_skips_comments_and_joins_multiline_data():
    lines = [": connected", "", "event: ping", "data: a", "data: b", "", "data: no event name", ""]
    assert list(parse_sse(lines)) == [("ping", "a\nb"), ("message", "no event name")]


def test_parse_round_update():
    update = parse_round_update(PAYLOAD)
    assert update.round == 7
    assert update.uptime_score == {1: 20, 2: 18}
    assert update.last_round_points == {1: 3, 2: 2}
    assert update.checks_per_team == 3


class FakeResponse:
    def __init__(self, lines):
        self.lines = lines

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        pass

    def iter_lines(self, **kwargs):
        return iter(self.lines)


class FakeSession:
    def __init__(self, lines):
        self.lines = lines
        self.calls = 0

    def get(self, url, **kwargs):
        self.calls += 1
        return FakeResponse(self.lines)


def test_stream_yields_rounds_ignores_other_events_and_bad_data_then_reconnects():
    lines = [
        ": connected", "",
        "event: other", "data: {}", "",
        "event: updated_round_data", "data: not json", "",
        "event: updated_round_data", f"data: {json.dumps(PAYLOAD)}", "",
    ]
    stop = threading.Event()
    session = FakeSession(lines)
    seen = []
    for update in stream_rounds("http://x", stop, session):
        seen.append(update.round)
        if session.calls == 2:  # the stream closed once and was reopened
            stop.set()
    assert seen == [7, 7]
