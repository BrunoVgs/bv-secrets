"""Worker loop: drains the spool fed by the read-only web UI.

The only privileged bv-secrets component (docker + store write), it runs on the
host as `bv` with no inbound network. `linux:` sinks are refused here: doas
elevation is interactive and stays CLI-only.
"""
import json
import sys
import time
import traceback
from pathlib import Path

from .. import audit
from ..config import SPOOL
from ..engine import ConfigError, Engine, RotateAborted
from .jobs import HANDLERS

REQ, RES, DONE = SPOOL / "requests", SPOOL / "results", SPOOL / "done"
POLL_SECONDS = 2.0
DIGEST_SECONDS = 60.0             # periodic audit-digest rebuild
SECRET_ACTIONS = {"rotate", "apply", "doctor"}
FLUSH_INTERVAL = 0.3


def _has_linux(cfg, name):
    return any(s.startswith("linux:") for s in cfg.get(name, {}).get("sinks", []))


def write_result(jid, status, log, data):
    """Write RES/<jid>.json atomically. Also called DURING the job with
    status=running: the UI reads this file and shows the log live."""
    RES.mkdir(parents=True, exist_ok=True)
    tmp = RES / f".{jid}.tmp"
    tmp.write_text(json.dumps({"id": jid, "status": status, "log": log,
                               "data": data, "ts": time.time()}))
    tmp.replace(RES / f"{jid}.json")


def _make_logger(jid, log):
    """Log and flush to disk at most once per FLUSH_INTERVAL."""
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
    """rotate / apply / doctor — all go through Engine."""
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
        only = sorted(engine.cfg)          # doctor with no target = check all
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


def rebuild_digest():
    """Rebuild the audit digest for the dashboard. Best-effort: a failure here must
    never block job processing."""
    try:
        audit.build_worker_digest()
    except Exception:
        traceback.print_exc()


def main():
    for d in (REQ, RES, DONE):
        d.mkdir(parents=True, exist_ok=True)
    sys.stderr.write(f"bvsecrets-worker: watching {REQ}\n")
    rebuild_digest()
    next_digest = time.time() + DIGEST_SECONDS
    while True:
        did_job = False
        for job_path in sorted(REQ.glob("*.json")):
            did_job = True
            try:
                process(job_path)
            except Exception:
                traceback.print_exc()
                try:
                    job_path.rename(DONE / job_path.name)
                except OSError:
                    pass
        if did_job or time.time() >= next_digest:
            rebuild_digest()                       # after a job, and on a timer
            next_digest = time.time() + DIGEST_SECONDS
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
