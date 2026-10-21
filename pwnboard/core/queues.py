"""Redis connection and the key names shared by the web app and the worker."""
import os

import redis

# Beacons/creds pushed by the web endpoints, popped in batches by the worker
CALLBACK_QUEUE = "callback_queue"
CREDS_QUEUE = "creds_queue"

# JSON of the rendered board, written by the worker, read by the dashboard
BOARD_CACHE_KEY = "board_cache"

# Connections are opened lazily, so importing this module never touches the network
redis_client = redis.StrictRedis(
    host=os.environ.get("REDIS_HOST", "redis"),
    port=int(os.environ.get("REDIS_PORT", "6379")),
    decode_responses=True,
)
