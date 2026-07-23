"""Read-only audit view for the dashboard: reads the worker's digest off the
read-only store. The worker aggregates everything (access, host, trail, rotations)
with no secret value; `ts` gives the freshness shown by the front.
"""
import json

from bvsecrets.config import WORKER_DIGEST

MERGE_LIMIT = 300


def digest():
    try:
        d = json.loads(WORKER_DIGEST.read_text())
    except (OSError, ValueError):
        d = {}
    return {"events": (d.get("events") or [])[:MERGE_LIMIT], "ts": d.get("ts")}
