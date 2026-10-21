"""Clear callback and credential data while keeping users and access tokens.

Usage: python -m pwnboard.worker.reset --yes

Stop the web and worker containers first, otherwise they can write new data while
the reset runs. See "Resetting test data" in doc/setup.md.
"""
import argparse
import sys

from ..core.db import direct_connection
from ..core.queues import BOARD_CACHE_KEY, CALLBACK_QUEUE, CREDS_QUEUE, redis_client

# Everything beacons and credential reports write. The users and access_tokens tables are kept.
DATA_TABLES = (
    "hosts",
    "callbacks",
    "callback_events",
    "credentials_latest",
    "credentials_by_user",
)

REDIS_KEYS = (CALLBACK_QUEUE, CREDS_QUEUE, BOARD_CACHE_KEY)


def clear_tables(conn):
    """Empty the data tables in one transaction and return the row count removed from each."""
    counts = {}
    try:
        with conn.cursor() as cur:
            for table in DATA_TABLES:
                cur.execute(f"SELECT count(*) FROM {table}")
                counts[table] = cur.fetchone()[0]
            cur.execute(f"TRUNCATE TABLE {', '.join(DATA_TABLES)} RESTART IDENTITY")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return counts


def clear_redis():
    """Drop queued beacons/creds and the cached board; return how many keys existed."""
    return redis_client.delete(*REDIS_KEYS)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Delete all callbacks, credentials and cached board data. Users and access tokens are kept."
    )
    parser.add_argument("--yes", action="store_true", help="confirm that the data should be deleted")
    args = parser.parse_args(argv)

    if not args.yes:
        print("This permanently deletes all callback and credential data. Re-run with --yes to continue.")
        return 1

    # Fail before deleting anything if Redis is unreachable
    redis_client.ping()

    with direct_connection() as conn:
        counts = clear_tables(conn)
    for table, count in counts.items():
        print(f"{table}: removed {count} rows")

    print(f"redis: removed {clear_redis()} keys")
    print("Reset complete. Users and access tokens were kept.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
