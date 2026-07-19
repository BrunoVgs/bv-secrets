"""Handlers des jobs déposés par l'UI web dans le spool.

Chaque handler reçoit (job, log) et renvoie une charge utile JSON ou None. Les
journaux remontent tels quels dans la console du dashboard : ils ne doivent
contenir aucune valeur de secret.
"""
import json
import subprocess

from ..config import (ACCESS_RELOAD_SERVICES, ACCESS_RENDER, ALL_KINDS, AUTH_SERVICE,
                      COMPOSE_FILE, GEN_KINDS, GROUPS, PROXY_SERVICE, ROLES,
                      looks_like_apikey)
from ..engine import Engine
from .confedit import read_conf_lines, rewrite_section, write_conf_lines

ROLES_OK = set(ROLES)


def run(cmd, log, timeout=180):
    """Exécute une commande et journalise sa sortie ; lève si le code est non nul."""
    log(f"$ {' '.join(cmd)}")
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    for line in (p.stdout + p.stderr).splitlines():
        log("  " + line)
    if p.returncode != 0:
        raise RuntimeError(f"échec ({p.returncode}): {' '.join(cmd)}")


def do_access(job, log):
    """Applique une matrice service -> rôles : set (préserve access.conf), render all,
    puis rechargement des services qui consomment la matrice.

    Le proxy est recréé et non redémarré : sa configuration est montée fichier par
    fichier, un simple restart relirait l'ancienne."""
    changes = job.get("changes") or []
    if not changes:
        raise RuntimeError("aucun changement d'accès")
    for ch in changes:
        svc = str(ch.get("service", ""))
        roles = ch.get("roles") or []
        if not svc or not isinstance(roles, list) or any(r not in ROLES_OK for r in roles):
            raise RuntimeError(f"changement invalide: {ch!r}")
        run(["python3", str(ACCESS_RENDER), "set", svc, ",".join(roles)], log)
    run(["python3", str(ACCESS_RENDER), "all"], log)
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
    # Une clé d'app tierce ne doit jamais devenir générable : un rotate écrirait une
    # valeur aléatoire que l'app refuse, ce qui casse le service.
    if looks_like_apikey(name) and kind in GEN_KINDS:
        raise RuntimeError(f"{name} est une CLE API : format générable interdit")
    if group is not None and group not in GROUPS:
        raise RuntimeError(f"group invalide: {group}")
    # `computed` dépend d'une expression `compute` : ni attribué à l'aveugle, ni
    # retiré d'un secret qui en possède une.
    current = cfg[name]
    if kind == "computed" and not current.get("compute"):
        raise RuntimeError(f"{name}: computed exige une clé `compute` (CLI)")
    if current["kind"] == "computed" and kind not in (None, "computed"):
        raise RuntimeError(f"{name}: retirer `compute` d'abord (CLI)")


def do_meta(job, log):
    """Change le FORMAT (kind) et/ou la POLITIQUE de rotation (group) d'un secret.
    Ne touche à aucune valeur."""
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
    Engine()                      # relecture : échoue ici si la conf est cassée
    log("secrets.conf relu — OK")


def _console(args, log, timeout=120):
    """Lance une commande de console dans le service d'authentification.

    Intégration optionnelle : sans BV_AUTH_SERVICE, la gestion des comptes est
    simplement indisponible plutôt que dirigée vers un service arbitraire."""
    if not AUTH_SERVICE:
        raise RuntimeError("gestion des comptes indisponible : BV_AUTH_SERVICE non "
                           "configuré (voir deploy/bvsecrets-worker.confd.example)")
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), "exec", "-T", AUTH_SERVICE,
           "php", "bin/console"] + args
    log(f"$ php bin/console {' '.join(args)}")
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
    """Liste les comptes du portail ; aucun mot de passe n'est lu."""
    out = _console(["app:users"], _silent)
    for ln in out.splitlines():
        ln = ln.strip()
        if ln.startswith("["):
            users = json.loads(ln)
            log(f"{len(users)} compte(s)")
            return users
    raise RuntimeError("sortie app:users illisible")


def do_user(job, log):
    """Change le rôle d'un compte ou le supprime. Le garde-fou du dernier admin
    est porté par la commande Symfony."""
    op, name = str(job.get("op", "")), str(job.get("username", ""))
    if not name:
        raise RuntimeError("compte manquant")
    if op == "role":
        role = str(job.get("role", ""))
        if role not in ROLES_OK:
            raise RuntimeError(f"rôle invalide: {role}")
        _console(["app:set-role", name, role], log)
    elif op == "delete":
        _console(["app:delete-user", name], log)
    else:
        raise RuntimeError(f"opération inconnue: {op}")
    return do_users(job, _silent)


# Actions qui ne touchent pas aux secrets : traitées sans instancier Engine.
HANDLERS = {"access": do_access, "meta": do_meta, "users": do_users, "user": do_user}
