"""Tiny in-memory sliding-window rate limiter.

Used to throttle the captive portal's email-send endpoint so anyone on the
SSID can't hammer it to spam arbitrary addresses (and burn your SMTP relay's
reputation or quota).

In-memory means:
  - Counters reset on service restart. Not a problem — rate limits are about
    sustained abuse, not absolute bookkeeping.
  - Each gunicorn worker tracks its own bucket. Effective limit per origin
    is N * worker_count rather than N globally. Acceptable for the threat
    model (small, deliberate cap is enough to deter abuse).

For tighter / multi-worker-aware limits, swap the dict for Redis later.
"""
from __future__ import annotations

import threading
import time
from collections import deque


_lock = threading.Lock()
# {(scope, key) -> deque of unix timestamps}
_hits: dict[tuple[str, str], deque[float]] = {}


def check(scope: str, key: str, *, limit: int, window_seconds: int) -> bool:
    """Return True if the (scope, key) is within budget and consume one hit.
    Return False if the budget is already exhausted (caller should reject).

    `scope` separates different rate-limit families (e.g. "email-send-ip",
    "email-send-dest"). `key` is the actor identity (an IP, an email).
    """
    if not key:
        return True   # Caller should reject malformed input separately.
    now = time.monotonic()
    cutoff = now - window_seconds
    bucket_key = (scope, key)
    with _lock:
        q = _hits.get(bucket_key)
        if q is None:
            q = deque()
            _hits[bucket_key] = q
        # Drop hits older than the window.
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


def gc(_max_buckets: int = 10000) -> None:
    """Trim the dict to prevent unbounded growth (per-IP keys can pile up).
    Called opportunistically; cheap if the dict is small."""
    with _lock:
        if len(_hits) <= _max_buckets:
            return
        # Drop the half with the oldest most-recent hit. Best-effort.
        sorted_items = sorted(
            _hits.items(),
            key=lambda kv: kv[1][-1] if kv[1] else 0,
        )
        to_drop = sorted_items[: len(sorted_items) // 2]
        for k, _ in to_drop:
            _hits.pop(k, None)
