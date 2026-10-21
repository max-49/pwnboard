import os
from contextlib import contextmanager

import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extras import RealDictCursor

_pool = None


def build_dsn():
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        return database_url

    host = os.environ.get("POSTGRES_HOST", "db")
    port = os.environ.get("POSTGRES_PORT", "5432")
    dbname = os.environ.get("POSTGRES_DB", "pwnboard_db")
    user = os.environ.get("POSTGRES_USER", "pwnboard_user")
    password = os.environ.get("POSTGRES_PASSWORD", "password")

    return (
        f"host={host} "
        f"port={port} "
        f"dbname={dbname} "
        f"user={user} "
        f"password={password} "
        "connect_timeout=5"
    )


def init_pool():
    global _pool
    if _pool is not None:
        return _pool

    minconn = int(os.environ.get("POSTGRES_POOL_MIN", "1"))
    maxconn = int(os.environ.get("POSTGRES_POOL_MAX", "20"))
    dsn = build_dsn()
    _pool = ThreadedConnectionPool(minconn, maxconn, dsn=dsn)
    return _pool


def get_pool():
    return init_pool()


@contextmanager
def pooled_connection():
    pool = get_pool()
    conn = pool.getconn()
    try:
        yield conn
    finally:
        try:
            conn.rollback()
        except Exception:
            pass
        pool.putconn(conn)


@contextmanager
def direct_connection():
    """Short-lived connection outside the pool.

    Used for one-off startup work (schema setup) so that no pooled sockets exist
    before gunicorn forks its workers.
    """
    conn = psycopg2.connect(build_dsn())
    try:
        yield conn
    finally:
        conn.close()


def dict_cursor(conn):
    return conn.cursor(cursor_factory=RealDictCursor)
