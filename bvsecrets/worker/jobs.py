"""Handlers for jobs the web UI drops in the spool.

Each handler takes (job, log) and returns a JSON payload or None. Logs surface
verbatim in the dashboard console, so they must contain no secret value.
"""
import json
import os
import re
import subprocess
from pathlib import Path

from .. import adopt, locations, validate
from ..conffile import append_sections, render_section
from ..config import (ACCESS_RELOAD_SERVICES, ACCESS_RENDER, ALL_KINDS,
                      AUTH_CMD_CREATE, AUTH_CMD_DELETE, AUTH_CMD_LIST, AUTH_CMD_SETROLE,
                      AUTH_CONSOLE, AUTH_SERVICE, COMPOSE_FILE, GEN_KINDS, GROUPS,
                      MASTER, MIN_ACCOUNT_PASSWORD, PROXY_SERVICE, ROLES, SINK_TYPES,
                      adopt_root_error, looks_like_apikey)
from ..engine import Engine
from ..envfile import parse_env, write_env
from .confedit import read_conf_lines, rewrite_section, write_conf_lines

ROLES_OK = set(ROLES)
# Section names are INI keys read back by configparser and injected into rendered
# env files: keep them to the shape the rest of the tool already assumes.
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
# Same shape as the portal command accepts: an account name travels in HTTP headers
# (X-Auth-User) and in the audit trail.
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")


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


def _console(args, log, timeout=120, stdin=None):
    """Run a console command in the auth service.

    Optional integration: without BV_AUTH_SERVICE, account management is simply
    unavailable rather than pointed at an arbitrary service. `stdin` is how a
    password reaches the command: argv would expose it to `ps` and to the log line
    below."""
    if not AUTH_SERVICE:
        raise RuntimeError("gestion des comptes indisponible : BV_AUTH_SERVICE non "
                           "configuré (voir deploy/bvsecrets-worker.confd.example)")
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), "exec", "-T", AUTH_SERVICE,
           *AUTH_CONSOLE.split()] + args
    log(f"$ {AUTH_CONSOLE} {' '.join(args)}")
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin)
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
    """Create an account, change its role, or delete it. The last-admin and
    duplicate-name guards live in the portal's own commands."""
    op, name = str(job.get("op", "")), str(job.get("username", ""))
    if not name:
        raise RuntimeError("compte manquant")
    if op == "create":
        role, password = str(job.get("role", "")), str(job.get("value") or "")
        if not USERNAME_RE.match(name):
            raise RuntimeError(f"identifiant invalide: {name}")
        if role not in ROLES_OK:
            raise RuntimeError(f"rôle invalide: {role}")
        if len(password) < MIN_ACCOUNT_PASSWORD:
            raise RuntimeError(f"mot de passe trop court ({MIN_ACCOUNT_PASSWORD} minimum)")
        # The password goes in on STDIN and never appears in argv or in the log.
        _console([*AUTH_CMD_CREATE.split(), name, role], log, stdin=password)
    elif op == "role":
        role = str(job.get("role", ""))
        if role not in ROLES_OK:
            raise RuntimeError(f"rôle invalide: {role}")
        _console([AUTH_CMD_SETROLE, name, role], log)
    elif op == "delete":
        _console([AUTH_CMD_DELETE, name], log)
    else:
        raise RuntimeError(f"opération inconnue: {op}")
    return do_users(job, _silent)


def _reject_bad_declaration(cfg, name, kind, group, sinks):
    """Same rules as `Engine.check`, applied BEFORE writing instead of after: the
    UI must not be able to append a section that `check` would then flag."""
    if not NAME_RE.match(name):
        raise RuntimeError(f"nom invalide: {name} (attendu A-Z, chiffres, _)")
    if name in cfg:
        raise RuntimeError(f"{name} existe déjà")
    if kind not in ALL_KINDS:
        raise RuntimeError(f"format invalide: {kind}")
    if group not in GROUPS:
        raise RuntimeError(f"rotation invalide: {group}")
    # A third-party key can't be generated: a rotate would write a random value the
    # app rejects. The reverse also holds, so kind and name can't contradict.
    if looks_like_apikey(name) and kind in GEN_KINDS:
        raise RuntimeError(f"{name} est une clé API : format générable interdit")
    if kind == "apikey" and not looks_like_apikey(name):
        raise RuntimeError(f"{name}: kind=apikey exige API ou TOKEN dans le nom")
    if kind == "computed":
        raise RuntimeError("un secret calculé exige une clé `compute` (CLI)")
    if not sinks:
        raise RuntimeError("donner au moins un sink")
    valid = set(SINK_TYPES) | locations.writable_schemes()
    for s in sinks:
        if s.split(":", 1)[0] not in valid:
            raise RuntimeError(f"sink invalide: {s} (types: {', '.join(sorted(valid))})")


def do_add(job, log):
    """Declare a new secret and give it a value.

    The only job that carries a plaintext value: the spool file is 0600 and the
    loop deletes it instead of archiving it. Nothing here logs or returns the
    value, only its length."""
    engine = Engine()
    name = str(job.get("name", "")).strip()
    kind = str(job.get("kind", "password")).strip()
    group = str(job.get("group", "app")).strip()
    sinks = [str(s).strip() for s in (job.get("sinks") or []) if str(s).strip()]
    _reject_bad_declaration(engine.cfg, name, kind, group, sinks)

    value = job.get("value") or ""
    if value:
        err = validate.check(str(job.get("validate") or ""), value)
        if err:
            raise RuntimeError(f"{name}: {err}")
    elif kind in GEN_KINDS:
        value = Engine.gen(kind, int(job.get("length") or 0))
        log(f"{name}: valeur générée ({kind})")
    else:
        raise RuntimeError(f"{name}: format {kind} non générable, fournir une valeur")

    append_sections([render_section(name, kind, group, sinks,
                                    length=int(job.get("length") or 0),
                                    note=str(job.get("note") or ""),
                                    validate=str(job.get("validate") or ""))])
    log(f"{name}: section ajoutée ({len(sinks)} sink(s))")
    # Write to the store the same way `bv-secrets set` does, then reload so a
    # broken section surfaces here rather than at the next command.
    data = parse_env(MASTER)
    data[name] = value
    write_env(MASTER, data)
    Engine.touch_meta([name])
    Engine()
    log(f"{name}: valeur en store ({len(value)} c). `apply` pour la propager.")
    return {"name": name, "len": len(value)}


def _adopt_path(job):
    """Resolve the target file and refuse anything outside BV_ADOPT_ROOTS."""
    path = Path(str(job.get("file", ""))).resolve()
    err = adopt_root_error(path)
    if err:
        raise RuntimeError(f"{path}: {err}")
    if not path.is_file():
        raise RuntimeError(f"fichier introuvable: {path}")
    return path


def do_adopt_plan(job, log):
    """Detect a file's secrets and propose declarations. Reads only: nothing is
    written until an `adopt` job confirms. Lengths travel, values don't."""
    path = _adopt_path(job)
    engine = Engine()
    proposals, ignored, conflicts = adopt.plan_file(
        path, prefix=str(job.get("prefix") or ""), known=set(engine.cfg))
    log(f"{path}: {len(proposals)} secret(s) détecté(s), {len(ignored)} ignoré(s)")
    return {
        "file": str(path),
        "proposals": [{"key": p.key, "name": p.name, "kind": p.kind,
                       "group": p.group, "len": len(p.value)} for p in proposals],
        "ignored": ignored,
        "conflicts": conflicts,
    }


def do_adopt(job, log):
    """Declare the selected keys and import their in-place values."""
    path = _adopt_path(job)
    engine = Engine()
    wanted = {str(k) for k in (job.get("only") or [])}
    if not wanted:
        raise RuntimeError("aucune clé sélectionnée")
    proposals, _, _ = adopt.plan_file(
        path, prefix=str(job.get("prefix") or ""), known=set(engine.cfg))
    chosen = [p for p in proposals if p.key in wanted]
    missing = wanted - {p.key for p in chosen}
    if missing:
        raise RuntimeError(f"clés absentes du fichier ou déjà déclarées: {sorted(missing)}")

    append_sections([render_section(p.name, p.kind, p.group, [adopt.sink_for(path, p.key)],
                                    note=f"adopté depuis {path.name}") for p in chosen])
    log(f"{len(chosen)} section(s) ajoutée(s) depuis {path.name}")
    reloaded = Engine()                       # reload with the new sections
    for p in chosen:
        reloaded.import_one(p.name, source=adopt.sink_for(path, p.key), log=log)
    return {"file": str(path), "adopted": [p.name for p in chosen]}


# Actions that don't touch secrets: handled without instantiating Engine.
HANDLERS = {"access": do_access, "meta": do_meta, "users": do_users, "user": do_user,
            "add": do_add, "adopt_plan": do_adopt_plan, "adopt": do_adopt}
