"""Ties the pieces together: score updates in, odds out."""
import logging
import threading
import time
from collections import deque
from dataclasses import replace
from datetime import datetime, timezone

from .model import MAX_ACCESS_PENALTY, MIN_RATE, Noise, TeamInput, components, simulate, to_prices

logger = logging.getLogger("market.service")

REPLAY_ROUNDS = 40  # recent rounds reloaded after a restart to rebuild "recent form"
HISTORY_POINTS = 240  # about how many points a chart line gets
HISTORY_CACHE_SECONDS = 5  # many browsers may ask at once; ask the database once
MAX_HISTORY_MINUTES = 72 * 60


def shape_history(rows, bucket_seconds):
    """[(epoch, team, price, top3)] -> aligned series for charts, with None where a team has no data."""
    times = sorted({row[0] for row in rows})
    index = {t: i for i, t in enumerate(times)}
    teams = {}
    for epoch, team, price, top3 in rows:
        series = teams.setdefault(
            str(team), {"price": [None] * len(times), "top3": [None] * len(times)}
        )
        series["price"][index[epoch]] = price
        series["top3"][index[epoch]] = top3
    return {"bucket_seconds": bucket_seconds, "times": times, "teams": teams}


class Market:
    def __init__(self, cfg, store, now=None, mono=time.monotonic):
        self.cfg = cfg
        self.store = store
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._mono = mono
        self.noise = Noise(cfg.simulations)
        self.lock = threading.RLock()

        self.round = None
        self.first_round = None
        self.scored_rounds = 0.0  # rounds that actually awarded points (not paused, not before scoring began)
        self.checks = 11
        self.scores = {}
        self.form = {}
        self.access = {}
        self.prices = {}
        self.arrivals = deque(maxlen=12)  # (round, monotonic time) of recent rounds
        self.last_update = None
        self.latest = []
        self._history_cache = {}

    # --- inputs -------------------------------------------------------------------------

    def restore(self):
        """Rebuild recent form from the rounds saved before a restart."""
        from .scoring import RoundUpdate

        for rnd, teams in self.store.load_recent_rounds(REPLAY_ROUNDS):
            self.on_round(
                RoundUpdate(
                    round=rnd,
                    uptime_score={t: v[0] for t, v in teams.items()},
                    last_round_points={t: v[1] for t, v in teams.items()},
                    checks_per_team=self.checks,
                ),
                replay=True,
            )
        if self.round is not None:
            self.first_round = self.round  # ROUNDS_REMAINING counts from now, not from the replay
            logger.info("restored recent rounds up to round %d", self.round)

    def on_round(self, update, replay=False):
        """Take in one round of scores. Returns False for a round already seen."""
        saved = update  # saved whole: the excluded teams' scores are how rounds are counted
        update = replace(
            update,
            uptime_score=self._without_excluded(update.uptime_score),
            last_round_points=self._without_excluded(update.last_round_points),
        )
        with self.lock:
            if self.round is not None and update.round <= self.round:
                return False
            alpha = 1 - 0.5 ** (1 / self.cfg.form_half_life)
            checks = update.checks_per_team
            # A team that never fails (the test team) has earned `checks` points in every round that
            # scored, so the best score tells us how many rounds that was, whatever the round number says.
            self.scored_rounds = max(self.scored_rounds, max(saved.uptime_score.values(), default=0) / checks)
            idle = not any(update.last_round_points.values())  # scoring paused: says nothing about form
            for team, points in update.last_round_points.items():
                long_rate = self._rate_long(update.uptime_score[team], self.scored_rounds, checks)
                if idle:
                    self.form.setdefault(team, long_rate)
                else:
                    previous = self.form.get(team, long_rate)
                    self.form[team] = previous + alpha * (points / checks - previous)
            self.round, self.checks = update.round, checks
            self.scores = dict(update.uptime_score)
            if self.first_round is None:
                self.first_round = update.round
            if not replay:
                self.arrivals.append((update.round, self._mono()))
                self.last_update = self._mono()
        if not replay:
            try:
                self.store.save_round(saved)
            except Exception:
                logger.exception("could not save round %d", update.round)
        return True

    def _without_excluded(self, by_team):
        return {team: v for team, v in by_team.items() if team not in self.cfg.excluded_teams}

    @staticmethod
    def _rate_long(score, scored_rounds, checks):
        return max(0.0, min(1.0, score / max(1.0, scored_rounds * checks)))

    # --- time left ----------------------------------------------------------------------

    def round_seconds(self):
        """Seconds per round, measured from the rounds seen so far."""
        if len(self.arrivals) >= 2:
            (r0, t0), (r1, t1) = self.arrivals[0], self.arrivals[-1]
            if r1 > r0 and t1 > t0:
                return max(5.0, min(3600.0, (t1 - t0) / (r1 - r0)))
        return self.cfg.round_seconds

    def rounds_left(self):
        if self.cfg.competition_end:
            seconds = (self.cfg.competition_end - self._now()).total_seconds()
            return max(0.0, seconds / self.round_seconds())
        return max(0.0, self.cfg.rounds_remaining - (self.round - self.first_round))

    # --- output -------------------------------------------------------------------------

    def _inputs(self, access):
        return [
            TeamInput(
                team=team,
                score=self.scores[team],
                rate_long=self._rate_long(self.scores[team], self.scored_rounds, self.checks),
                rate_form=self.form.get(team, 0.0),
                access=access.get(team, 0),
            )
            for team in sorted(self.scores)
        ]

    def tick(self):
        """Recompute and save everyone's odds. Returns the rows saved (None before any scores)."""
        with self.lock:
            if self.round is None:
                return None
        try:
            access = self.store.team_access()
        except Exception:
            logger.exception("could not read red team access; using the last known values")
            access = self.access
        with self.lock:
            self.access = access
            stale = self.last_update is None or self._mono() - self.last_update > self.cfg.stale_seconds
            teams = self._inputs(access)
            odds = simulate(teams, self.rounds_left(), self.checks, self.cfg, self.noise)
            self.prices = to_prices({o.team: o.win_prob for o in odds}, self.prices, self.cfg)
            ts = self._now()
            rows = [
                {
                    "ts": ts, "round": self.round, "team": f"Team {o.team}", "team_number": o.team,
                    "price": self.prices[o.team], "win_prob": o.win_prob, "top3_prob": o.top3_prob,
                    "score": int(self.scores[o.team]), "exp_final": o.exp_final,
                    "rate_long": t.rate_long, "rate_form": t.rate_form, "rate_proj": o.rate_proj,
                    "access_hosts": t.access, "stale": stale,
                }
                for o, t in zip(odds, teams)
            ]
            self.latest = rows
        try:
            self.store.save_odds(rows)
        except Exception:
            logger.exception("could not save odds")
        return rows

    def snapshot(self):
        """The latest odds as JSON-ready data, best price first."""
        with self.lock:
            rows = sorted(self.latest, key=lambda r: -r["price"])
            return {
                "round": self.round,
                "rounds_left": None if self.round is None else round(self.rounds_left(), 1),
                "stale": bool(rows and rows[0]["stale"]),
                "teams": [
                    {k: (v.isoformat() if k == "ts" else v) for k, v in row.items()} for row in rows
                ],
            }

    def history(self, minutes):
        """Chart series for the last `minutes`, bucketed so a line has about HISTORY_POINTS points."""
        minutes = max(5, min(int(minutes), MAX_HISTORY_MINUTES))
        cached = self._history_cache.get(minutes)
        if cached and self._mono() - cached[0] < HISTORY_CACHE_SECONDS:
            return cached[1]
        bucket = max(15, round(minutes * 60 / HISTORY_POINTS))
        data = shape_history(self.store.history(minutes, bucket), bucket)
        if len(self._history_cache) > 16:
            self._history_cache.clear()
        self._history_cache[minutes] = (self._mono(), data)
        return data

    # The settings that shape the odds. Listed one by one so nothing secret (the database password)
    # can leak into the public "How it works" page.
    PUBLIC_PARAMS = (
        "form_weight", "form_half_life", "access_penalty", "unknown_points_sd", "unknown_ref_rounds",
        "tail_df", "simulations", "price_floor", "price_keep", "tick_seconds", "excluded_teams",
    )

    def explain(self):
        """The model's settings, the live round state, and every step of the math for every team."""
        with self.lock:
            params = {name: getattr(self.cfg, name) for name in self.PUBLIC_PARAMS}
            params["excluded_teams"] = list(params["excluded_teams"])
            params["min_rate"] = MIN_RATE
            params["max_access_penalty"] = MAX_ACCESS_PENALTY
            params["form_alpha"] = 1 - 0.5 ** (1 / self.cfg.form_half_life)
            if self.round is None:
                return {"ready": False, "params": params}
            teams = self._inputs(self.access)
            rounds_left = self.rounds_left()
            c = components(teams, rounds_left, self.checks, self.cfg)
            latest = {row["team_number"]: row for row in self.latest}
            out = []
            for i, t in enumerate(teams):
                row = latest.get(t.team, {})
                out.append({
                    "team": t.team, "score": int(t.score), "hosts": t.access,
                    "rate_long": t.rate_long, "rate_form": t.rate_form,
                    "blended": float(c["blended"][i]), "penalty": float(c["penalty"][i]),
                    "rate_proj": float(c["rate"][i]), "mean_final": float(c["mean"][i]),
                    "play_sd": float(c["play_sd"][i]), "rate_sd": float(c["rate_sd"][i]),
                    "sd": float(c["sd"][i]),
                    "win_prob": row.get("win_prob"), "top3_prob": row.get("top3_prob"), "price": row.get("price"),
                })
            out.sort(key=lambda r: -(r["price"] or 0))
            return {
                "ready": True,
                "params": params,
                "live": {
                    "round": self.round, "rounds_left": rounds_left, "round_seconds": self.round_seconds(),
                    "scored_rounds": self.scored_rounds, "checks_per_round": self.checks,
                    "points_left": c["points_left"], "unknown_sd": float(c["unknown_sd"]),
                },
                "teams": out,
            }
