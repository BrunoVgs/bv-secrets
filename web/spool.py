"""Dépôt de jobs dans le spool.

Le dashboard ne fait qu'écrire un descripteur de job ; le worker privilégié
l'exécute et réécrit un résultat sans valeur. L'écriture passe par un fichier
temporaire renommé pour que le worker ne lise jamais un job partiel.
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
