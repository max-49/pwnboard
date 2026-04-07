import os
from contextlib import contextmanager

from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extras import RealDictCursor
from flask import g

_pool = None


def _build_dsn():
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        return database_url

    host = os.environ.get("POSTGRES_HOST", os.environ.get("PGHOST", "localhost"))
    port = os.environ.get("POSTGRES_PORT", os.environ.get("PGPORT", "5432"))
    dbname = os.environ.get("POSTGRES_DB", os.environ.get("PGDATABASE", "pwnboard_db"))
    user = os.environ.get("POSTGRES_USER", os.environ.get("PGUSER", "pwnboard_user"))
    password = os.environ.get("POSTGRES_PASSWORD", os.environ.get("PGPASSWORD", "password"))

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
    dsn = _build_dsn()
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


def get_db_connection():
    """Return request-scoped PostgreSQL connection on flask.g."""
    if getattr(g, "db", None) is None:
        pool = get_pool()
        g.db = pool.getconn()
    return g.db


def close_db_connection():
    conn = getattr(g, "db", None)
    if conn is not None:
        try:
            try:
                conn.rollback()
            except Exception:
                pass
            get_pool().putconn(conn)
        finally:
            delattr(g, "db")


def init_schema(default_user, default_password_hash, default_password):
    escaped_default_password = default_password.replace("'", "''")
    ddl = f"""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'grafana_user'
        ) THEN
            CREATE USER grafana_user WITH PASSWORD '{escaped_default_password}';
        ELSE
            ALTER USER grafana_user WITH PASSWORD '{escaped_default_password}';
        END IF;
    END
    $$;

    GRANT CONNECT ON DATABASE pwnboard_db TO grafana_user;
    GRANT USAGE ON SCHEMA public TO grafana_user;
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_user;
    GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO grafana_user;

    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana_user;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO grafana_user;

    CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS access_tokens (
        token_hash CHAR(64) PRIMARY KEY,
        token_name TEXT NOT NULL,
        application TEXT NOT NULL,
        description TEXT,
        username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
        prefix TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS idx_access_tokens_username ON access_tokens(username);
    CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at);

    CREATE TABLE IF NOT EXISTS hosts (
        ip INET PRIMARY KEY,
        server TEXT NOT NULL,
        application TEXT NOT NULL,
        last_seen DOUBLE PRECISION NOT NULL,
        message TEXT NOT NULL,
        access_type TEXT NOT NULL DEFAULT 'generic',
        online BOOLEAN NOT NULL DEFAULT TRUE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS callbacks (
        ip INET NOT NULL,
        application TEXT NOT NULL,
        access_info TEXT NOT NULL DEFAULT '',
        last_seen DOUBLE PRECISION NOT NULL,
        online BOOLEAN NOT NULL DEFAULT TRUE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (ip, application)
    );

    CREATE INDEX IF NOT EXISTS idx_callbacks_ip ON callbacks(ip);
    CREATE INDEX IF NOT EXISTS idx_callbacks_last_seen ON callbacks(last_seen);

    CREATE TABLE IF NOT EXISTS callback_events (
        id BIGSERIAL PRIMARY KEY,
        ip INET NOT NULL,
        team TEXT NOT NULL,
        application TEXT NOT NULL,
        access_info TEXT NOT NULL DEFAULT '',
        last_seen DOUBLE PRECISION NOT NULL,
        received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_callback_events_ip ON callback_events(ip);
    CREATE INDEX IF NOT EXISTS idx_callback_events_application_received_at ON callback_events(application, received_at DESC);
    CREATE INDEX IF NOT EXISTS idx_callback_events_received_at ON callback_events(received_at);

    CREATE TABLE IF NOT EXISTS credentials_latest (
        ip INET PRIMARY KEY,
        creds TEXT NOT NULL,
        server TEXT NOT NULL,
        last_seen DOUBLE PRECISION NOT NULL,
        creds_online BOOLEAN NOT NULL DEFAULT TRUE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS credentials_by_user (
        ip INET NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        server TEXT NOT NULL,
        last_seen DOUBLE PRECISION NOT NULL,
        creds_online BOOLEAN NOT NULL DEFAULT TRUE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (ip, username)
    );

    CREATE INDEX IF NOT EXISTS idx_credentials_by_user_ip ON credentials_by_user(ip);
    CREATE INDEX IF NOT EXISTS idx_credentials_by_user_last_seen ON credentials_by_user(last_seen);

    CREATE TABLE IF NOT EXISTS alerts (
        id SMALLINT PRIMARY KEY CHECK (id = 1),
        event_time DOUBLE PRECISION,
        message TEXT
    );

    CREATE TABLE IF NOT EXISTS logs (
        id BIGSERIAL PRIMARY KEY,
        timestamp TIMESTAMPTZ NOT NULL,
        level TEXT NOT NULL,
        ip INET,
        app TEXT,
        message TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_logs_app_timestamp ON logs(app, timestamp);
    """

    with pooled_connection() as conn:
        conn.autocommit = False
        try:
            with conn.cursor() as cur:
                cur.execute(ddl)
                cur.execute(
                    """
                    INSERT INTO users(username, password, role)
                    VALUES (%s, %s, 'admin')
                    ON CONFLICT (username) DO NOTHING
                    """,
                    (default_user, default_password_hash),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

def clear_callbacks():
    ddl = """
    TRUNCATE TABLE hosts;
    TRUNCATE TABLE callbacks;
    TRUNCATE TABLE callback_events;
    TRUNCATE TABLE credentials_latest;
    TRUNCATE TABLE credentials_by_user;
    """

    with pooled_connection() as conn:
        conn.autocommit = False
        try:
            with conn.cursor() as cur:
                cur.execute(ddl)
            conn.commit()
        except Exception:
            conn.rollback()
            raise

def dict_cursor(conn):
    return conn.cursor(cursor_factory=RealDictCursor)
