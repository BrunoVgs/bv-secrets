"""Le spool : des descripteurs de job deposes ici, un worker privilegie les draine.

Seul canal d'ecriture des faces non privilegiees — le dashboard en lecture seule,
et l'ecouteur HTTP qui recoit les jobs d'une autre instance. Aucune des deux
n'execute quoi que ce soit : elles deposent, le worker agit.

Une ecriture passe par un fichier temporaire renomme, pour que le worker ne lise
jamais un job partiel. Un job PEUT porter une valeur en clair (pousser un mot de
passe chez un hote distant) : le fichier est cree 0600 avant que quoi que ce soit
n'y soit ecrit, et le worker le supprime au lieu de l'archiver.
"""
import json
import os
import secrets as pysecrets
import time
from pathlib import Path

from .config import SPOOL


def root() -> Path:
    """Lu a chaque appel, pas au chargement : les tests et le conteneur posent
    BV_SPOOL apres l'import du module."""
    return Path(os.environ.get("BV_SPOOL") or SPOOL)


def requests_dir() -> Path:
    return root() / "requests"


def results_dir() -> Path:
    return root() / "results"


def queue(src: str = "web", **fields) -> str:
    """Depose un job et rend son identifiant."""
    req = requests_dir()
    jid = pysecrets.token_hex(8)
    req.mkdir(parents=True, exist_ok=True)
    job = {"id": jid, "ts": time.time(), "src": src, **fields}
    tmp = req / f".{jid}.tmp"
    # O_CREAT|O_EXCL avec un 0600 explicite : le mode est pose a la creation, donc
    # la charge n'est jamais brievement lisible par tous comme le laisserait un
    # write_text() suivi d'un chmod (le umask du conteneur ne nous appartient pas).
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(job))
    tmp.replace(req / f"{jid}.json")
    return jid


def job_result(jid: str, id_re) -> dict:
    if not id_re.match(jid):
        return {"status": "error", "log": ["id invalide"]}
    path = results_dir() / f"{jid}.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return {"status": "error", "log": ["résultat illisible"]}
    if (requests_dir() / f"{jid}.json").exists():
        return {"status": "pending", "log": []}
    return {"status": "queued", "log": []}
