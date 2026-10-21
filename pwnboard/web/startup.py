"""One-time database setup for the web container."""
import os

from ..core.db import direct_connection
from ..core.schema import ensure_schema
from . import ph


def initialize():
    """Create the schema and make sure the default admin account exists.

    Runs once per container start (from the gunicorn master, or from the dev
    runner) rather than once per gunicorn worker.
    """
    username = os.environ.get("DEFAULT_USER", "admin")
    password = os.environ.get("DEFAULT_USER_PASSWORD", "password")

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
