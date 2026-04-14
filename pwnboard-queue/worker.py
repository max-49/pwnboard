import time
import json
import redis
import threading
from psycopg2.extras import execute_values

# Import from your existing pwnboard modules
from db import pooled_connection, init_pool
from data import getBoardDict
from . import TEAM_MAP

init_pool()
r = redis.StrictRedis(host="redis", port=6379, decode_responses=True)

cache_update_event = threading.Event()

def process_creds(batch_json, db):
    pass

def process_callbacks(batch_json, db):
    pass

def ingest_thread():
    print("Background worker started. Listening to Redis queues...")
    while True:
        try:
            # RPOP up to 500 items chronologically
            callbacks_batch = r.rpop('callback_queue', 500)
            creds_batch = r.rpop('creds_queue', 500)

            # If there is data in either queue, process it
            if callbacks_batch or creds_batch:
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
            print(f"Worker Error: {e}")
            time.sleep(2)

def cache_thread():
    print("Cache thread started...")
    while True:
        try:
            # wait until ingest thread sends an update
            cache_update_event.wait()
            
            # clear the event so we don't infinitely loop
            cache_update_event.clear()
            
            with pooled_connection() as db:
                new_board_data = getBoardDict(db_conn=db)
                r.set('board_cache', json.dumps(new_board_data))
                
        except Exception as e:
            print(f"Cache Generation Error: {e}")
            time.sleep(2)

if (__name__ == '__main__'):
    pass