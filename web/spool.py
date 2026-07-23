"""Drop jobs into the spool.

The dashboard only writes a job descriptor; the privileged worker runs it and
writes back a value-free result. Writes go through a renamed temp file so the
worker never reads a partial job.
"""
import json
import os
import secrets as pysecrets
import time
from pathlib import Path

from bvsecrets.config import SPOOL

REQ = Path(os.environ.get("BV_SPOOL") or SPOOL) / "requests"
RES = Path(os.environ.get("BV_SPOOL") or SPOOL) / "results"


def queue(**fields):
    jid = pysecrets.token_hex(8)
    REQ.mkdir(parents=True, exist_ok=True)
    job = {"id": jid, "ts": time.time(), "src": "web", **fields}
    tmp = REQ / f".{jid}.tmp"
    tmp.write_text(json.dumps(job))
    tmp.replace(REQ / f"{jid}.json")
    return jid


def job_result(jid, id_re):
    if not id_re.match(jid):
        return {"status": "error", "log": ["id invalide"]}
    path = RES / f"{jid}.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return {"status": "error", "log": ["résultat illisible"]}
    if (REQ / f"{jid}.json").exists():
        return {"status": "pending", "log": []}
    return {"status": "queued", "log": []}
