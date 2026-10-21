import time
import json
import threading
from psycopg2.extras import execute_values

from ..core.board import TEAM_MAP
from ..core.data import getBoardDict
from ..core.db import init_pool, pooled_connection, direct_connection
from ..core.logger import logger
from ..core.queues import BOARD_CACHE_KEY, CALLBACK_QUEUE, CREDS_QUEUE, redis_client
from ..core.schema import ensure_schema

TIMEOUT_SECONDS = 15
TOKEN_PURGE_INTERVAL_SECONDS = 3600

cache_update_event = threading.Event()

def process_callbacks(batch_json, db):
    if not batch_json: return
    
    events_data = []
    latest_hosts = {}
    latest_callbacks = {}

    logger.info(f"Processing {len(batch_json)} callbacks at once from the redis queue.")

    # Since we RPOP, the batch is older -> newer.
    for item in batch_json:
        data = json.loads(item)
        ip = data['ip']
        app = data.get('application', 'unknown')
        access_info = data.get('access_info', '')
        last_seen = data.get('last_seen', 0)
        server = data.get('server', 'pwnboard')
        message = data.get('message', f"Callback received to {server}")
        team = TEAM_MAP.get(ip, "Unknown")

        # 1. Every event goes to the historical log
        events_data.append((ip, team, app, access_info, last_seen))

        # 2. Deduplicate state tables by dict key assignment (Newer events overwrite older ones)
        latest_callbacks[(ip, app)] = (ip, app, access_info, last_seen)
        latest_hosts[ip] = (ip, app, message, server, last_seen)

    with db.cursor() as cur:
        # Insert all historical events
        execute_values(
            cur,
            """
            INSERT INTO callback_events(ip, team, application, access_info, last_seen, received_at)
            VALUES %s
            """,
            events_data,
            template="(%s, %s, %s, %s, %s, NOW())"
        )

        # Insert latest callback states
        if latest_callbacks:
            execute_values(
                cur,
                """
                INSERT INTO callbacks(ip, application, access_info, last_seen, online, updated_at)
                VALUES %s
                ON CONFLICT (ip, application) DO UPDATE SET
                    access_info = EXCLUDED.access_info,
                    last_seen = EXCLUDED.last_seen,
                    online = TRUE,
                    updated_at = NOW()
                """,
                list(latest_callbacks.values()),
                template="(%s, %s, %s, %s, TRUE, NOW())"
            )

        # Insert latest host states
        if latest_hosts:
            execute_values(
                cur,
                """
                INSERT INTO hosts(ip, application, message, server, last_seen, online, updated_at)
                VALUES %s
                ON CONFLICT (ip) DO UPDATE SET
                    application = EXCLUDED.application,
                    message = EXCLUDED.message,
                    server = EXCLUDED.server,
                    last_seen = EXCLUDED.last_seen,
                    online = TRUE,
                    updated_at = NOW()
                """,
                list(latest_hosts.values()),
                template="(%s, %s, %s, %s, %s, TRUE, NOW())"
            )
        logger.info("Saved to Postgres!")


def process_creds(batch_json, db):
    if not batch_json: return
    
    latest_creds_by_user = {}
    latest_creds_by_ip = {}

    for item in batch_json:
        data = json.loads(item)
        ip = data['ip']
        username = data.get('username')
        password = data.get('password')
        
        if not password or len(password) <= 1:
            continue

        server = data.get('server', 'pwnboard')
        last_seen = data.get('last_seen', 0)
        is_admin = data.get('admin', 0)
        
        credstring = f"{'* ' if is_admin == 1 else ''}{username}:{password}"

        # Deduplicate
        latest_creds_by_user[(ip, username)] = (ip, username, password, server, last_seen)
        latest_creds_by_ip[ip] = (ip, credstring, server, last_seen)

    with db.cursor() as cur:
        if latest_creds_by_user:
            execute_values(
                cur,
                """
                INSERT INTO credentials_by_user(ip, username, password, server, last_seen, creds_online, updated_at)
                VALUES %s
                ON CONFLICT (ip, username) DO UPDATE SET
                    password = EXCLUDED.password,
                    server = EXCLUDED.server,
                    last_seen = EXCLUDED.last_seen,
                    creds_online = TRUE,
                    updated_at = NOW()
                """,
                list(latest_creds_by_user.values()),
                template="(%s, %s, %s, %s, %s, TRUE, NOW())"
            )

        if latest_creds_by_ip:
            execute_values(
                cur,
                """
                INSERT INTO credentials_latest(ip, creds, server, last_seen, creds_online, updated_at)
                VALUES %s
                ON CONFLICT (ip) DO UPDATE SET
                    creds = EXCLUDED.creds,
                    server = EXCLUDED.server,
                    last_seen = EXCLUDED.last_seen,
                    creds_online = TRUE,
                    updated_at = NOW()
                """,
                list(latest_creds_by_ip.values()),
                template="(%s, %s, %s, %s, TRUE, NOW())"
            )


def ingest_thread():
    logger.info("Background worker started. Listening to Redis queues...")
    while True:
        try:
            # RPOP up to 500 items chronologically
            callbacks_batch = redis_client.rpop(CALLBACK_QUEUE, 500)
            creds_batch = redis_client.rpop(CREDS_QUEUE, 500)

            # If there is data in either queue, process it
            if callbacks_batch or creds_batch:
                logger.info("Callbacks and/or creds found in redis")

                with pooled_connection() as db:
                    if callbacks_batch:
                        process_callbacks(callbacks_batch, db)
                    if creds_batch:
                        process_creds(creds_batch, db)
                
                    db.commit()

                # Data has changed, notify event so other thread can process data
                cache_update_event.set()
            else:
                time.sleep(0.5)

        except Exception as e:
            logger.error(f"Worker Error: {e}")
            time.sleep(2)


def purge_expired_tokens(db):
    """Delete access tokens that expired more than a week ago.

    Expired tokens already stop working. They stay listed for a week so users can see why
    a token was rejected.
    """
    with db.cursor() as cur:
        cur.execute("DELETE FROM access_tokens WHERE expires_at < NOW() - INTERVAL '7 days'")
        removed = cur.rowcount
    db.commit()
    if removed:
        logger.info(f"Removed {removed} expired access tokens")


def cache_thread():
    logger.info("Cache thread started...")
    last_purge = 0.0
    while True:
        try:
            # wait until ingest thread sends an update
            callback = cache_update_event.wait(timeout=TIMEOUT_SECONDS)
            
            if callback:
                # clear the event so we don't infinitely loop
                cache_update_event.clear()
            
            with pooled_connection() as db:
                new_board_data = getBoardDict(db)
                redis_client.set(BOARD_CACHE_KEY, json.dumps(new_board_data))

            logger.info("Board cache updated")

            if time.monotonic() - last_purge >= TOKEN_PURGE_INTERVAL_SECONDS:
                last_purge = time.monotonic()
                with pooled_connection() as db:
                    purge_expired_tokens(db)

        except Exception as e:
            logger.error(f"Cache Generation Error: {e}")
            time.sleep(2)


def main():
    # The web container normally creates the schema; this only matters if the worker wins the race
    with direct_connection() as conn:
        ensure_schema(conn)
    init_pool()

    # Start board cache generation thread on a different thread
    t_cache = threading.Thread(target=cache_thread, daemon=True)
    t_cache.start()

    # Start redis queue ingestion thread on this thread
    ingest_thread()

if (__name__ == '__main__'):
    main()