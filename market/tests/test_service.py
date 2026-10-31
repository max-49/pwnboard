import dataclasses
from datetime import datetime, timedelta, timezone

import pytest

from pwnmarket.config import Config
from pwnmarket.scoring import RoundUpdate
from pwnmarket.service import Market

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


class FakeStore:
    def __init__(self, access=None, history=()):
        self.access = access or {}
        self.history = list(history)
        self.rounds, self.odds = [], []
        self.fail_access = False

    def team_access(self):
        if self.fail_access:
            raise RuntimeError("db down")
        return self.access

    def save_round(self, update):
        self.rounds.append(update.round)

    def save_odds(self, rows):
        self.odds.append(rows)

    def load_recent_rounds(self, limit):
        return self.history


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def update(rnd, scores=None, points=None):
    scores = scores or {1: 100 * rnd, 2: 90 * rnd, 3: 80 * rnd}
    points = points or {1: 10, 2: 9, 3: 8}
    return RoundUpdate(rnd, scores, points, 10)


def market(store=None, clock=None, **cfg):
    config = dataclasses.replace(Config(simulations=2000), **cfg)
    return Market(config, store or FakeStore(), now=lambda: NOW, mono=clock or Clock())


def test_old_or_repeated_rounds_are_ignored():
    m = market()
    assert m.on_round(update(5)) and not m.on_round(update(5)) and not m.on_round(update(4))
    assert m.store.rounds == [5]


def test_recent_form_follows_recent_rounds():
    m = market(form_half_life=1)
    m.on_round(update(10))
    for rnd in range(11, 16):
        m.on_round(update(rnd, points={1: 0, 2: 9, 3: 8}))
    assert m.form[1] < 0.1 < 0.8 < m.form[2]


def test_rounds_left_from_end_time_and_measured_round_length():
    clock = Clock()
    m = market(clock=clock, competition_end=NOW + timedelta(hours=1))
    for i, rnd in enumerate((1, 2, 3)):
        clock.t = i * 30.0
        m.on_round(update(rnd))
    assert m.round_seconds() == 30
    assert m.rounds_left() == pytest.approx(120)


def test_rounds_left_without_end_time_counts_down_from_first_round_seen():
    m = market(rounds_remaining=50)
    m.on_round(update(100))
    m.on_round(update(110))
    assert m.rounds_left() == 40


def test_tick_saves_prices_that_sum_to_one_and_red_team_access_hurts():
    m = market(store=FakeStore(access={1: 8}))
    m.on_round(update(10))
    rows = m.tick()
    assert sum(r["price"] for r in rows) == pytest.approx(1)
    assert {r["team"] for r in rows} == {"Team 1", "Team 2", "Team 3"}
    assert next(r for r in rows if r["team_number"] == 1)["access_hosts"] == 8
    assert m.store.odds == [rows]

    clean = market()
    clean.on_round(update(10))
    price = lambda ms, n: next(r["price"] for r in ms.tick() if r["team_number"] == n)
    assert price(m, 1) < price(clean, 1)


def test_no_odds_before_the_first_round_and_stale_after_a_silence():
    clock = Clock()
    m = market(clock=clock)
    assert m.tick() is None
    m.on_round(update(1))
    assert not m.tick()[0]["stale"]
    clock.t = 10_000
    assert m.tick()[0]["stale"]
    assert m.snapshot()["stale"]


def test_database_trouble_does_not_stop_pricing():
    store = FakeStore(access={1: 3})
    m = market(store=store)
    m.on_round(update(10))
    m.tick()
    store.fail_access = True
    rows = m.tick()
    assert next(r for r in rows if r["team_number"] == 1)["access_hosts"] == 3  # last known


def test_restore_rebuilds_form_and_counts_rounds_left_from_now():
    history = [(r, {1: (100 * r, 10), 2: (90 * r, 9), 3: (80 * r, 8)}) for r in range(1, 31)]
    m = market(store=FakeStore(history=history), rounds_remaining=50)
    m.restore()
    assert m.round == 30 and m.form[1] > 0.5
    assert m.rounds_left() == 50
    assert m.store.rounds == []  # replayed rounds are not saved again
