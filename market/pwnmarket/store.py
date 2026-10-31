"""Postgres access: the market's own schema, plus a read of PWNBoard's callback data."""
import logging

import psycopg2
from psycopg2.extras import execute_values

from .access import team_access

logger = logging.getLogger("market.store")

_DDL = """
CREATE SCHEMA IF NOT EXISTS market;

CREATE TABLE IF NOT EXISTS market.round_scores (
    round INTEGER NOT NULL,
    team_number INTEGER NOT NULL,
    uptime_score INTEGER NOT NULL,
    last_round_points INTEGER NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (round, team_number)
);

CREATE TABLE IF NOT EXISTS market.odds (
    ts TIMESTAMPTZ NOT NULL,
    round INTEGER NOT NULL,
    team TEXT NOT NULL,
    team_number INTEGER NOT NULL,
    price DOUBLE PRECISION NOT NULL,
    win_prob DOUBLE PRECISION NOT NULL,
    top3_prob DOUBLE PRECISION NOT NULL,
    score INTEGER NOT NULL,
    exp_final DOUBLE PRECISION NOT NULL,
    rate_long DOUBLE PRECISION NOT NULL,
    rate_form DOUBLE PRECISION NOT NULL,
    rate_proj DOUBLE PRECISION NOT NULL,
    access_hosts INTEGER NOT NULL,
    stale BOOLEAN NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_market_odds_ts ON market.odds(ts);
"""

# Grafana's read-only user is created by PWNBoard; give it the market schema too.
_GRAFANA_GRANTS = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'grafana_user') THEN
        GRANT USAGE ON SCHEMA market TO grafana_user;
        GRANT SELECT ON ALL TABLES IN SCHEMA market TO grafana_user;
        ALTER DEFAULT PRIVILEGES IN SCHEMA market GRANT SELECT ON TABLES TO grafana_user;
    END IF;
END
$$;
"""

_ODDS_COLUMNS = (
    "ts", "round", "team", "team_number", "price", "win_prob", "top3_prob", "score",
    "exp_final", "rate_long", "rate_form", "rate_proj", "access_hosts", "stale",
)


class Store:
    def __init__(self, cfg):
        self.cfg = cfg
        self._conn = None

    def _connection(self):
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(
                host=self.cfg.db_host, dbname=self.cfg.db_name,
                user=self.cfg.db_user, password=self.cfg.db_password,
                connect_timeout=5,
            )
        return self._conn

    def _run(self, fn):
        """Run fn(conn); on a database error drop the connection so the next call reconnects."""
        conn = self._connection()
        try:
            return fn(conn)
        except psycopg2.Error:
            try:
                conn.rollback()
            except psycopg2.Error:
                pass
            conn.close()
            self._conn = None
            raise

    def setup(self):
        def run(conn):
            with conn.cursor() as cur:
                cur.execute(_DDL)
                cur.execute(_GRAFANA_GRANTS)
                cur.execute("DELETE FROM market.odds WHERE ts < NOW() - INTERVAL '3 days'")
            conn.commit()
        self._run(run)

    def team_access(self):
        return self._run(lambda conn: team_access(conn, self.cfg.access_window_minutes))

    def save_round(self, update):
        rows = [
            (update.round, team, update.uptime_score[team], update.last_round_points[team])
            for team in update.uptime_score
        ]

        def run(conn):
            with conn.cursor() as cur:
                execute_values(
                    cur,
                    "INSERT INTO market.round_scores (round, team_number, uptime_score, last_round_points) "
                    "VALUES %s ON CONFLICT DO NOTHING",
                    rows,
                )
            conn.commit()
        self._run(run)

    def load_recent_rounds(self, limit):
        """The last `limit` rounds seen, oldest first, as [(round, {team: (score, points)})]."""
        def run(conn):
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT round, team_number, uptime_score, last_round_points FROM market.round_scores "
                    "WHERE round > (SELECT COALESCE(MAX(round), 0) FROM market.round_scores) - %s "
                    "ORDER BY round, team_number",
                    (limit,),
                )
                rows = cur.fetchall()
            conn.commit()
            return rows
        rounds = {}
        for rnd, team, score, points in self._run(run):
            rounds.setdefault(rnd, {})[team] = (score, points)
        return sorted(rounds.items())

    def save_odds(self, rows):
        values = [tuple(row[c] for c in _ODDS_COLUMNS) for row in rows]

        def run(conn):
            with conn.cursor() as cur:
                execute_values(
                    cur, f"INSERT INTO market.odds ({', '.join(_ODDS_COLUMNS)}) VALUES %s", values
                )
            conn.commit()
        self._run(run)
