"""Host information: key/value notes that tools attach to a host (hostname, OS, a flag, ...).

A note is identified by (ip, key). Sending the same key for a host again overwrites it, and
sending an empty value deletes it. Notes do not expire.
"""
from .logger import logger

MAX_KEY_LENGTH = 64
MAX_VALUE_LENGTH = 1000
MAX_KEYS_PER_HOST = 50

SET = "set"
DELETED = "deleted"
REJECTED = "rejected"


def apply_info_item(cur, ip, key, value, application):
    """Store, overwrite or delete one note. Returns SET, DELETED or REJECTED.

    A note is rejected when it would be a new key on a host that already has MAX_KEYS_PER_HOST.
    """
    if value == "":
        cur.execute("DELETE FROM host_info WHERE ip = %s AND info_key = %s", (ip, key))
        return DELETED

    cur.execute(
        "SELECT count(*), coalesce(bool_or(info_key = %s), false) FROM host_info WHERE ip = %s",
        (key, ip),
    )
    count, key_exists = cur.fetchone()
    if not key_exists and count >= MAX_KEYS_PER_HOST:
        return REJECTED

    cur.execute(
        """
        INSERT INTO host_info(ip, info_key, info_value, application, updated_at)
        VALUES (%s, %s, %s, %s, NOW())
        ON CONFLICT (ip, info_key)
        DO UPDATE SET
            info_value = EXCLUDED.info_value,
            application = EXCLUDED.application,
            updated_at = NOW()
        """,
        (ip, key, value, application),
    )
    return SET


def get_host_info(db, ip):
    """Every note for one host, sorted by key: [{key, value, application, updated}]."""
    with db.cursor() as cur:
        cur.execute(
            """
            SELECT info_key, info_value, application, extract(epoch from updated_at)::bigint
            FROM host_info
            WHERE ip = %s
            ORDER BY lower(info_key), info_key
            """,
            (ip,),
        )
        rows = cur.fetchall()
    return [{"key": k, "value": v, "application": app, "updated": updated} for k, v, app, updated in rows]


def get_info_counts(db):
    """{ip: number of notes} for every host that has any. Empty if the lookup fails."""
    try:
        with db.cursor() as cur:
            cur.execute("SELECT ip, count(*) FROM host_info GROUP BY ip")
            return {str(ip): count for ip, count in cur.fetchall()}
    except Exception:
        db.rollback()
        logger.exception("Could not count host info")
        return {}
