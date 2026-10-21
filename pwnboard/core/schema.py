# Password of the read-only Postgres role that Grafana connects as. Must match
# conf/grafana/provisioning/datasources/pwnboard-datasource.yaml.
GRAFANA_DB_PASSWORD = "pwnB0ard-p4ssw0rd1#"

# Arbitrary constant used to serialize schema setup between the web and worker
# containers when both start at the same time.
_SCHEMA_LOCK_ID = 7281001

_DDL = f"""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'grafana_user'
        ) THEN
            CREATE USER grafana_user WITH PASSWORD '{GRAFANA_DB_PASSWORD}';
        ELSE
            ALTER USER grafana_user WITH PASSWORD '{GRAFANA_DB_PASSWORD}';
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
"""


def ensure_schema(conn):
    """Create the tables and Grafana role if they do not exist yet.

    Safe to call from several processes at once: the whole setup runs inside one
    transaction that holds a Postgres advisory lock.
    """
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK_ID,))
            cur.execute(_DDL)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
