"""One-time database setup for the web container."""
import os

from ..core.db import direct_connection
from ..core.logger import logger
from ..core.schema import ensure_schema
from . import ph

DEFAULT_SECRET_KEYS = {"dev-secret", "change-me-please"}


def initialize():
    """Create the schema and make sure the default admin account exists.

    Runs once per container start (from the gunicorn master, or from the dev
    runner) rather than once per gunicorn worker.
    """
    username = os.environ.get("DEFAULT_USER", "admin")
    password = os.environ.get("DEFAULT_USER_PASSWORD", "password")

    if os.environ.get("SECRET_KEY", "dev-secret") in DEFAULT_SECRET_KEYS:
        logger.warning("SECRET_KEY is a default value, so anyone can forge login cookies. "
                       "Set a random SECRET_KEY in .env (scripts/setup.py generates one).")
    if password == "password":
        logger.warning("The admin password is the default 'password'. Set PWNBOARD_PASSWORD in .env.")

    with direct_connection() as conn:
        ensure_schema(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users(username, password, role)
                VALUES (%s, %s, 'admin')
                ON CONFLICT (username) DO NOTHING
                """,
                (username, ph.hash(password)),
            )
        conn.commit()
