"""Points d'entrée de l'API.

Chaque handler reçoit la requête décodée et renvoie (code, objet JSON). La
mécanique HTTP (cookies, sessions, CSRF, sérialisation) vit dans server.py :
ces fonctions restent testables sans socket.
"""
import re

from bvsecrets import Engine, looks_like_apikey
from bvsecrets.config import ALL_KINDS, GEN_KINDS, GROUPS, ROLES

from . import access, inventory, session, spool

JOB_ID_RE = re.compile(r"^[0-9a-f]{8,32}$")


def _err(code, message, **extra):
    return code, {"error": message, **extra}


# ---- GET ----
def api_list(req):
    return 200, {"secrets": inventory.list_data(), "auto": inventory.auto_targets()}


def api_plan(req):
    return 200, {"selected": inventory.auto_targets()}


def api_job(req):
    return 200, spool.job_result(req.path.rsplit("/", 1)[1], JOB_ID_RE)


# ---- POST ----
def api_rotate(req):
    only = req.body.get("only") or []
    if not isinstance(only, list) or not all(isinstance(x, str) for x in only):
        return _err(400, "only doit être une liste")
    cfg = Engine().cfg
    accepted = [n for n in only if inventory.rotatable(cfg, n)]
    rejected = [n for n in only if n not in accepted]
    if not accepted:
        return _err(400, "aucune cible éligible", rejected=rejected)
    jid = spool.queue(action="rotate", only=accepted)
    return 202, {"id": jid, "accepted": accepted, "rejected": rejected}


def api_doctor(req):
    return 202, {"id": spool.queue(action="doctor", only=[])}


def api_access_apply(req):
    changes = req.body.get("changes") or []
    if not isinstance(changes, list) or not changes:
        return _err(400, "aucun changement")
    problem = access.validate_changes(changes)
    if problem:
        return _err(400, problem)
    return 202, {"id": spool.queue(action="access", changes=changes)}


def api_users(req):
    return 202, {"id": spool.queue(action="users")}


def api_user(req):
    op = req.body.get("op")
    username = req.body.get("username")
    role = req.body.get("role")
    if op not in ("role", "delete") or not isinstance(username, str) or not username:
        return _err(400, "requête invalide")
    if op == "role" and role not in ROLES:
        return _err(400, f"rôle invalide: {role}")
    return 202, {"id": spool.queue(action="user", op=op, username=username, role=role)}


def api_meta_apply(req):
    changes = req.body.get("changes") or []
    if not isinstance(changes, list) or not changes:
        return _err(400, "aucun changement")
    cfg = Engine().cfg
    for ch in changes:
        name, kind, group = ch.get("name"), ch.get("kind"), ch.get("group")
        if name not in cfg:
            return _err(400, f"secret inconnu: {name}")
        if kind is not None and kind not in ALL_KINDS:
            return _err(400, f"format invalide: {kind}")
        if looks_like_apikey(name) and kind in GEN_KINDS:
            return _err(400, f"{name} est une clé API : elle ne peut pas être générée")
        if group is not None and group not in GROUPS:
            return _err(400, f"rotation invalide: {group}")
    return 202, {"id": spool.queue(action="meta", changes=changes)}


def api_reveal(req):
    # Ré-authentification exigée à CHAQUE reveal : une session valide ne suffit pas.
    if not session.check_password(str(req.body.get("password", ""))):
        return _err(401, "bad password")
    name = str(req.body.get("name", ""))
    value = inventory.get_value(name)
    if value is None:
        return _err(404, "inconnu")
    return 200, {"name": name, "value": value}


GET_ROUTES = {"/api/list": api_list, "/api/plan": api_plan}
POST_ROUTES = {
    "/api/rotate": api_rotate,
    "/api/doctor": api_doctor,
    "/api/access/apply": api_access_apply,
    "/api/users": api_users,
    "/api/user": api_user,
    "/api/meta/apply": api_meta_apply,
    "/api/reveal": api_reveal,
}
# Reveal renvoie une valeur : la temporisation anti-bruteforce est appliquée par
# le serveur sur les réponses 401 de ces routes.
RATE_LIMITED = {"/api/reveal", "/api/login"}
