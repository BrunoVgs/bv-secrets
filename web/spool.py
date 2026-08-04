"""Drop jobs into the spool.

The dashboard only writes a job descriptor; the privileged worker runs it and
writes back a value-free result. Writes go through a renamed temp file so the
worker never reads a partial job.

A job MAY carry a secret value (adding a password or an API key from the UI): the
file is created 0600 before anything is written to it, and the worker deletes such
a job instead of archiving it (see worker/loop.py).
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
    # O_CREAT|O_EXCL with an explicit 0600: the mode is set at creation, so the
    # payload is never briefly world-readable the way write_text() + chmod would
    # leave it (the container umask is not ours to assume).
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(job))
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
