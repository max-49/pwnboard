import dataclasses

import pytest

from pwnmarket.config import Config
from pwnmarket.model import Noise, TeamInput, simulate, to_prices

CFG = Config(simulations=4000)


def team(n, score=1000, rate=0.9, access=0):
    return TeamInput(n, score, rate, rate, access)


def odds(teams, rounds_left=60, cfg=CFG):
    return {o.team: o for o in simulate(teams, rounds_left, 11, cfg, Noise(cfg.simulations))}


def test_win_probabilities_sum_to_one_and_equal_teams_are_equal():
    result = odds([team(1), team(2), team(3), team(4)])
    assert sum(o.win_prob for o in result.values()) == pytest.approx(1)
    assert all(o.win_prob == pytest.approx(0.25, abs=0.05) for o in result.values())


def test_higher_score_wins_more_often():
    result = odds([team(1, score=1200), team(2, score=1000), team(3, score=800)])
    assert result[1].win_prob > result[2].win_prob > result[3].win_prob


def test_red_team_access_lowers_odds_and_moves_them_to_others():
    base = odds([team(1), team(2), team(3), team(4)])
    hit = odds([team(1, access=6), team(2), team(3), team(4)])
    assert hit[1].win_prob < base[1].win_prob
    assert hit[2].win_prob > base[2].win_prob


def test_recent_form_counts():
    cold = TeamInput(1, 1000, 0.9, 0.5, 0)
    hot = TeamInput(2, 1000, 0.9, 1.0, 0)
    result = odds([cold, hot])
    assert result[2].win_prob > result[1].win_prob


def test_leader_is_certain_when_nothing_is_left_to_play_for():
    quiet = dataclasses.replace(CFG, unknown_points_sd=1)
    result = odds([team(1, score=1100), team(2, score=1000)], rounds_left=0, cfg=quiet)
    assert result[1].win_prob == pytest.approx(1)


def test_top3_probabilities_add_up_to_three():
    result = odds([team(n, score=1000 + n) for n in range(1, 8)])
    assert sum(o.top3_prob for o in result.values()) == pytest.approx(3)


def test_odds_do_not_jitter_between_identical_ticks():
    teams = [team(1), team(2), team(3)]
    noise = Noise(CFG.simulations)
    first = simulate(teams, 60, 11, CFG, noise)
    assert first == simulate(teams, 60, 11, CFG, noise)


def test_prices_sum_to_one_respect_the_floor_and_smooth():
    cfg = dataclasses.replace(CFG, price_floor=0.01, price_keep=0.5)
    prices = to_prices({1: 1.0, 2: 0.0}, {}, cfg)
    assert sum(prices.values()) == pytest.approx(1)
    assert prices[2] > 0
    moved = to_prices({1: 0.0, 2: 1.0}, prices, cfg)
    assert sum(moved.values()) == pytest.approx(1)
    assert moved[1] > prices[2]  # still remembers being the favourite
