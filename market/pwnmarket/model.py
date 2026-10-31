"""The odds model: simulate the rest of the competition many times and count who wins.

A team's final score is its score now plus what it is projected to earn in the rounds left,
plus a fat-tailed random amount for everything we cannot see (injects and so on). Hosts red
team holds lower a team's projected uptime, and recent rounds count for more than old ones,
so the odds move whenever either changes.
"""
from dataclasses import dataclass
from math import sqrt

import numpy as np

MIN_RATE = 0.02
MAX_ACCESS_PENALTY = 0.9


@dataclass(frozen=True)
class TeamInput:
    team: int
    score: float  # uptime points so far
    rate_long: float  # share of possible points earned over the whole game
    rate_form: float  # the same over recent rounds (exponentially weighted)
    access: int  # hosts red team currently holds


@dataclass(frozen=True)
class TeamOdds:
    team: int
    win_prob: float
    top3_prob: float
    exp_final: float
    rate_proj: float


def project_rate(team, cfg):
    """Share of the available uptime points this team is expected to keep earning."""
    blended = (1 - cfg.form_weight) * team.rate_long + cfg.form_weight * team.rate_form
    penalty = min(MAX_ACCESS_PENALTY, cfg.access_penalty * team.access)
    return max(MIN_RATE, min(1.0, blended)) * (1 - penalty)


class Noise:
    """Random draws kept fixed between ticks, so odds only move when the inputs do."""

    def __init__(self, n_paths, seed=7):
        self.n_paths = n_paths
        self.seed = seed
        self._draws = None
        self._key = None

    def draws(self, n_teams, df):
        df = max(df, 2.1)
        if self._key != (n_teams, df):
            rng = np.random.default_rng(self.seed)
            # scaled to unit variance, so a team's standard deviation means what it says
            self._draws = rng.standard_t(df, size=(self.n_paths, n_teams)) * sqrt((df - 2) / df)
            self._key = (n_teams, df)
        return self._draws


def simulate(teams, rounds_left, checks, cfg, noise):
    """Return a TeamOdds for each team, in the order given."""
    if not teams:
        return []
    rounds_left = max(0.0, rounds_left)
    rates = np.array([project_rate(t, cfg) for t in teams])
    scores = np.array([t.score for t in teams], dtype=float)

    points_left = rounds_left * checks
    mean = scores + points_left * rates
    per_round = rates * (1 - rates)
    play_sd = np.sqrt(points_left * per_round)
    # how unsure we are of the rate itself, from about two half-lives of recent results
    rate_sd = points_left * np.sqrt(per_round / (checks * max(1.0, 2 * cfg.form_half_life)))
    unknown_sd = cfg.unknown_points_sd * min(1.0, sqrt(rounds_left / cfg.unknown_ref_rounds))
    sd = np.sqrt(play_sd**2 + rate_sd**2 + unknown_sd**2)

    final = mean[None, :] + noise.draws(len(teams), cfg.tail_df) * sd[None, :]
    n_paths = final.shape[0]
    wins = np.bincount(np.argmax(final, axis=1), minlength=len(teams)) / n_paths
    if len(teams) > 3:
        podium = np.argpartition(-final, 2, axis=1)[:, :3].ravel()
        top3 = np.bincount(podium, minlength=len(teams)) / n_paths
    else:
        top3 = np.ones(len(teams))
    return [
        TeamOdds(t.team, float(wins[i]), float(top3[i]), float(mean[i]), float(rates[i]))
        for i, t in enumerate(teams)
    ]


def to_prices(win_probs, previous, cfg):
    """Win probabilities -> market prices: floored, smoothed against last tick, summing to 1."""
    floored = {team: max(p, cfg.price_floor) for team, p in win_probs.items()}
    total = sum(floored.values())
    prices = {team: p / total for team, p in floored.items()}
    if previous:
        keep = cfg.price_keep
        prices = {team: keep * previous.get(team, p) + (1 - keep) * p for team, p in prices.items()}
        total = sum(prices.values())
        prices = {team: p / total for team, p in prices.items()}
    return prices
