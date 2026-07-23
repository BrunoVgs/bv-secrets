"""Handlers for jobs the web UI drops in the spool.

Each handler takes (job, log) and returns a JSON payload or None. Logs surface
verbatim in the dashboard console, so they must contain no secret value.
"""
import json
import os
import subprocess

from ..config import (ACCESS_RELOAD_SERVICES, ACCESS_RENDER, ALL_KINDS,
                      AUTH_CMD_DELETE, AUTH_CMD_LIST, AUTH_CMD_SETROLE, AUTH_CONSOLE,
                      AUTH_SERVICE, COMPOSE_FILE, GEN_KINDS, GROUPS, PROXY_SERVICE,
                      ROLES, looks_like_apikey)
from ..engine import Engine
from .confedit import read_conf_lines, rewrite_section, write_conf_lines

ROLES_OK = set(ROLES)


def _render(*args):
    """Invoke the access renderer: directly if executable, else via python3."""
    r = str(ACCESS_RENDER)
    return [r, *args] if os.access(r, os.X_OK) else ["python3", r, *args]


def run(cmd, log, timeout=180):
    """Run a command and log its output; raise on non-zero exit."""
    log(f"$ {' '.join(cmd)}")
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    for line in (p.stdout + p.stderr).splitlines():
        log("  " + line)
    if p.returncode != 0:
        raise RuntimeError(f"échec ({p.returncode}): {' '.join(cmd)}")


def do_access(job, log):
    """Apply a service -> roles matrix: set (preserving access.conf), render all,
    then reload services that consume the matrix.

    The proxy is recreated, not restarted: its config is mounted file by file, so a
    plain restart would re-read the old one."""
    changes = job.get("changes") or []
    if not changes:
        raise RuntimeError("aucun changement d'accès")
    for ch in changes:
        svc = str(ch.get("service", ""))
        roles = ch.get("roles") or []
        if not svc or not isinstance(roles, list) or any(r not in ROLES_OK for r in roles):
            raise RuntimeError(f"changement invalide: {ch!r}")
        run(_render("set", svc, ",".join(roles)), log)
    run(_render("all"), log)
    if PROXY_SERVICE:
        run(["docker", "compose", "-f", str(COMPOSE_FILE),
             "up", "-d", "--force-recreate", "--no-deps", PROXY_SERVICE], log)
    if ACCESS_RELOAD_SERVICES:
        run(["docker", "compose", "-f", str(COMPOSE_FILE),
             "restart", *ACCESS_RELOAD_SERVICES], log)


def _validate_meta_change(cfg, name, kind, group):
    if name not in cfg:
        raise RuntimeError(f"secret inconnu: {name}")
    if kind is not None and kind not in ALL_KINDS:
        raise RuntimeError(f"kind invalide: {kind}")
    # A third-party key must never become generatable: a rotate would write a random
    # value the app rejects, breaking the service.
    if looks_like_apikey(name) and kind in GEN_KINDS:
        raise RuntimeError(f"{name} est une CLE API : format générable interdit")
    if group is not None and group not in GROUPS:
        raise RuntimeError(f"group invalide: {group}")
    # `computed` depends on a `compute` expression: neither assigned blindly nor
    # removed from a secret that has one.
    current = cfg[name]
    if kind == "computed" and not current.get("compute"):
        raise RuntimeError(f"{name}: computed exige une clé `compute` (CLI)")
    if current["kind"] == "computed" and kind not in (None, "computed"):
        raise RuntimeError(f"{name}: retirer `compute` d'abord (CLI)")


def do_meta(job, log):
    """Change a secret's FORMAT (kind) and/or rotation POLICY (group). Touches no
    value."""
    changes = job.get("changes") or []
    if not changes:
        raise RuntimeError("aucun changement")
    cfg = Engine().cfg
    lines = read_conf_lines()
    for ch in changes:
        name, kind, group = str(ch.get("name", "")), ch.get("kind"), ch.get("group")
        _validate_meta_change(cfg, name, kind, group)
        lines = rewrite_section(lines, name, kind, group, log)
    write_conf_lines(lines)
    Engine()                      # reload: fails here if the conf is broken
    log("secrets.conf relu — OK")


def _console(args, log, timeout=120):
    """Run a console command in the auth service.

    Optional integration: without BV_AUTH_SERVICE, account management is simply
    unavailable rather than pointed at an arbitrary service."""
    if not AUTH_SERVICE:
        raise RuntimeError("gestion des comptes indisponible : BV_AUTH_SERVICE non "
                           "configuré (voir deploy/bvsecrets-worker.confd.example)")
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), "exec", "-T", AUTH_SERVICE,
           *AUTH_CONSOLE.split()] + args
    log(f"$ {AUTH_CONSOLE} {' '.join(args)}")
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    for line in (p.stdout + p.stderr).splitlines():
        if line.strip():
            log("  " + line)
    if p.returncode != 0:
        raise RuntimeError(f"échec ({p.returncode}): app {' '.join(args)}")
    return p.stdout


def _silent(*_):
    pass


def do_users(job, log):
    """List portal accounts; no password is read."""
    out = _console([AUTH_CMD_LIST], _silent)
    for ln in out.splitlines():
        ln = ln.strip()
        if ln.startswith("["):
            users = json.loads(ln)
            log(f"{len(users)} compte(s)")
            return users
    raise RuntimeError(f"sortie {AUTH_CMD_LIST} illisible")


def do_user(job, log):
    """Change an account's role or delete it. The last-admin guard lives in the
    Symfony command."""
    op, name = str(job.get("op", "")), str(job.get("username", ""))
    if not name:
        raise RuntimeError("compte manquant")
    if op == "role":
        role = str(job.get("role", ""))
        if role not in ROLES_OK:
            raise RuntimeError(f"rôle invalide: {role}")
        _console([AUTH_CMD_SETROLE, name, role], log)
    elif op == "delete":
        _console([AUTH_CMD_DELETE, name], log)
    else:
        raise RuntimeError(f"opération inconnue: {op}")
    return do_users(job, _silent)


# Actions that don't touch secrets: handled without instantiating Engine.
HANDLERS = {"access": do_access, "meta": do_meta, "users": do_users, "user": do_user}
