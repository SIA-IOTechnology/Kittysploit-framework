"""C2 channel helpers (beacon timing, polling agents)."""

from lib.c2.beacon_timing import compute_poll_delay, jitter_seconds

__all__ = ["compute_poll_delay", "jitter_seconds"]
