"""Limit failed logins per client IP and per username using Redis counters.

Counters live for a fixed window after the first failure, so an attacker cannot keep an
account locked by continuing to fail. If Redis cannot be reached, logins are allowed
rather than blocked.
"""
import redis

from ..core.logger import logger
from ..core.queues import redis_client

WINDOW_SECONDS = 15 * 60
MAX_FAILURES_PER_IP = 10
MAX_FAILURES_PER_USERNAME = 20


def _keys(ip, username):
    return f"login_fail:ip:{ip}", f"login_fail:user:{username.lower()[:64]}"


def is_blocked(ip, username):
    """True if this IP or this username has too many recent failed logins."""
    ip_key, user_key = _keys(ip, username)
    try:
        ip_failures, user_failures = redis_client.mget(ip_key, user_key)
    except redis.RedisError:
        logger.warning("Login throttling is unavailable: could not reach Redis")
        return False
    return (int(ip_failures or 0) >= MAX_FAILURES_PER_IP
            or int(user_failures or 0) >= MAX_FAILURES_PER_USERNAME)


def record_failure(ip, username):
    try:
        # One transaction: create the counter with its expiry if it is new, then count
        pipe = redis_client.pipeline()
        for key in _keys(ip, username):
            pipe.set(key, 0, ex=WINDOW_SECONDS, nx=True)
            pipe.incr(key)
        pipe.execute()
    except redis.RedisError:
        logger.warning("Login throttling is unavailable: could not reach Redis")


def clear_username_failures(username):
    """Forget a user's failed attempts after they log in successfully."""
    try:
        redis_client.delete(_keys("", username)[1])
    except redis.RedisError:
        logger.warning("Login throttling is unavailable: could not reach Redis")
