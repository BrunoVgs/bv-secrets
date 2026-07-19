"""Boucle du worker : vide le spool alimenté par l'UI web read-only.

Seul composant privilégié de bv-secrets (docker + store en écriture), il tourne
sur l'hôte sous l'utilisateur `bv`, sans réseau entrant. Les sinks `linux:` sont
refusés ici : l'élévation doas est interactive et reste réservée au CLI.
"""
import json
import sys
import time
import traceback
from pathlib import Path

from ..config import SPOOL
from ..engine import ConfigError, Engine, RotateAborted
from .jobs import HANDLERS

REQ, RES, DONE = SPOOL / "requests", SPOOL / "results", SPOOL / "done"
POLL_SECONDS = 2.0
SECRET_ACTIONS = {"rotate", "apply", "doctor"}
FLUSH_INTERVAL = 0.3


def _has_linux(cfg, name):
    return any(s.startswith("linux:") for s in cfg.get(name, {}).get("sinks", []))


def write_result(jid, status, log, data):
    """Écrit RES/<jid>.json de façon atomique. Appelé aussi PENDANT le job avec
    status=running : l'UI lit ce fichier et affiche le log en direct."""
    RES.mkdir(parents=True, exist_ok=True)
    tmp = RES / f".{jid}.tmp"
    tmp.write_text(json.dumps({"id": jid, "status": status, "log": log,
                               "data": data, "ts": time.time()}))
    tmp.replace(RES / f"{jid}.json")


def _make_logger(jid, log):
    """Journalise et flushe sur disque au plus une fois par FLUSH_INTERVAL."""
    last = [0.0]

    def emit(msg=""):
        log.append(str(msg))
        now = time.time()
        if now - last[0] >= FLUSH_INTERVAL:
            last[0] = now
            try:
                write_result(jid, "running", log, None)
            except OSError:
                pass
    return emit


def run_secret_action(job, action, emit):
    """rotate / apply / doctor — passent tous par Engine."""
    engine = Engine()
    only = job.get("only") or []
    unknown = [n for n in only if n not in engine.cfg]
    if unknown:
        raise RuntimeError(f"secrets inconnus: {unknown}")
    if action != "doctor":
        blocked = [n for n in only if _has_linux(engine.cfg, n)]
        if blocked:
            raise RuntimeError(f"sinks linux -> CLI uniquement (élévation interactive): {blocked}")
    if not only:
        if action != "doctor":
            raise RuntimeError("aucune cible")
        only = sorted(engine.cfg)          # doctor sans cible = tout vérifier
    emit(f"# {action} {only}")
    if action == "rotate":
        engine.rotate(only, True, emit)
    elif action == "doctor":
        engine.doctor(only, emit)
    else:
        engine.apply(only, True, emit)


def process(job_path: Path):
    log = []
    jid, status, data = job_path.stem, "error", None
    emit = _make_logger(jid, log)
    try:
        job = json.loads(job_path.read_text())
        jid = job.get("id", jid)
        emit = _make_logger(jid, log)
        action = job.get("action")
        handler = HANDLERS.get(action)
        if handler:
            emit(f"# {action}")
            data = handler(job, emit)
        elif action in SECRET_ACTIONS:
            run_secret_action(job, action, emit)
        else:
            raise RuntimeError(f"action inconnue: {action}")
        status = "done"
    except (RotateAborted, ConfigError) as e:
        emit(f"abort: {e}")
    except Exception as e:
        emit(f"EXC: {e}")
    write_result(jid, status, log, data)
    DONE.mkdir(parents=True, exist_ok=True)
    try:
        job_path.rename(DONE / job_path.name)
    except OSError:
        job_path.unlink(missing_ok=True)


def main():
    for d in (REQ, RES, DONE):
        d.mkdir(parents=True, exist_ok=True)
    sys.stderr.write(f"bvsecrets-worker: surveille {REQ}\n")
    while True:
        for job_path in sorted(REQ.glob("*.json")):
            try:
                process(job_path)
            except Exception:
                traceback.print_exc()
                try:
                    job_path.rename(DONE / job_path.name)
                except OSError:
                    pass
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
