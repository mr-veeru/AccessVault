"""
Redis token blocklist for JWT revocation (logout / refresh rotation).

Uses Redis when BLOCKLIST_REDIS_URL is set; otherwise blocklist is disabled
(memory mode). Fail-closed when Redis is configured but unavailable.
"""
import sys
import redis

blocklist_redis = None
blocklist_redis_required = False


def init_redis_blocklist(blocklist_url):
    """Initialize Redis client for token blocklist. Call once at app startup with URL from config."""
    global blocklist_redis, blocklist_redis_required
    if blocklist_url.startswith("redis://"):
        try:
            blocklist_redis = redis.from_url(blocklist_url, decode_responses=True)
            blocklist_redis.ping()
            blocklist_redis_required = True
        except Exception as e:
            blocklist_redis = None
            blocklist_redis_required = True
            print(
                f"WARNING: Redis blocklist unavailable: {str(e)} - All tokens will be rejected",
                file=sys.stderr,
            )
    else:
        blocklist_redis = None
        blocklist_redis_required = False
