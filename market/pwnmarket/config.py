"""Settings, all read from environment variables (see market/README.md)."""
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


def _float(name, default):
    return float(os.environ.get(name) or default)


def _int(name, default):
    return int(os.environ.get(name) or default)


# The competition runs on Eastern time (the scoring site reports -04:00). Hardcoded for this competition.
LOCAL_TZ = timezone(timedelta(hours=-4))


def _end_time(raw):
    """COMPETITION_END as an ISO timestamp, e.g. 2026-10-31T15:30:00-04:00.

    Without a UTC offset the time is Eastern (-04:00), the same clock as the scoring site and the
    people running the competition, so `2026-10-31T15:30:00` means 3:30 PM there.
    """
    if not raw:
        return None
    end = datetime.fromisoformat(raw.strip())
    return end if end.tzinfo else end.replace(tzinfo=LOCAL_TZ)


@dataclass(frozen=True)
class Config:
    scoring_url: str = "https://scoring.irsec.club/api"
    db_host: str = "db"
    db_name: str = "pwnboard_db"
    db_user: str = "pwnboard_user"
    db_password: str = ""

    # How much of the competition is left. COMPETITION_END wins when it is set.
    competition_end: datetime | None = None
    rounds_remaining: float = 60
    round_seconds: float = 60  # used until the real round length has been measured

    # Teams that get no odds: 19 did not show up, 20 and 21 are the red team and blue team test teams.
    # Hardcoded for this competition.
    excluded_teams: tuple = (19, 20, 21)

    tick_seconds: float = 15
    stale_seconds: float = 180
    access_window_minutes: int = 5
    http_port: int = 8080

    # The "fun" knobs. Bigger numbers mean twitchier odds.
    unknown_points_sd: float = 250  # points we cannot see (injects etc.), as a standard deviation
    unknown_ref_rounds: float = 100  # that uncertainty shrinks as fewer rounds than this remain
    form_weight: float = 0.7  # 0 = judge a team by its whole-game uptime, 1 = only by recent form
    form_half_life: float = 6  # rounds for old results to count half as much
    access_penalty: float = 0.06  # share of a team's projected uptime lost per compromised host
    tail_df: float = 4  # fat-tailed luck; lower is wilder (must be above 2)
    simulations: int = 20000
    price_floor: float = 0.005  # nobody trades at 0%
    price_keep: float = 0.4  # share of the previous price kept each tick (0 = no smoothing)

    @classmethod
    def from_env(cls):
        return cls(
            scoring_url=os.environ.get("SCORING_URL") or cls.scoring_url,
            db_host=os.environ.get("POSTGRES_HOST") or cls.db_host,
            db_password=os.environ.get("POSTGRES_PASSWORD", ""),
            competition_end=_end_time(os.environ.get("COMPETITION_END")),
            rounds_remaining=_float("ROUNDS_REMAINING", cls.rounds_remaining),
            round_seconds=_float("ROUND_SECONDS", cls.round_seconds),
            tick_seconds=_float("TICK_SECONDS", cls.tick_seconds),
            stale_seconds=_float("STALE_SECONDS", cls.stale_seconds),
            access_window_minutes=_int("ACCESS_WINDOW_MINUTES", cls.access_window_minutes),
            http_port=_int("MARKET_HTTP_PORT", cls.http_port),
            unknown_points_sd=_float("UNKNOWN_POINTS_SD", cls.unknown_points_sd),
            unknown_ref_rounds=_float("UNKNOWN_REF_ROUNDS", cls.unknown_ref_rounds),
            form_weight=_float("FORM_WEIGHT", cls.form_weight),
            form_half_life=_float("FORM_HALF_LIFE", cls.form_half_life),
            access_penalty=_float("ACCESS_PENALTY", cls.access_penalty),
            tail_df=_float("TAIL_DF", cls.tail_df),
            simulations=_int("SIMULATIONS", cls.simulations),
            price_floor=_float("PRICE_FLOOR", cls.price_floor),
            price_keep=_float("PRICE_KEEP", cls.price_keep),
        )
