"""API entry points.

Each handler takes the decoded request and returns (code, JSON object). The HTTP
plumbing (cookies, sessions, CSRF, serialization) lives in server.py, so these stay
testable without a socket.
"""
import re

from bvsecrets import Engine, looks_like_apikey
from bvsecrets.config import (ALL_KINDS, GEN_KINDS, GROUPS, MIN_ACCOUNT_PASSWORD,
                              ROLES, SINK_TYPES)
from bvsecrets.locations import writable_schemes

from . import access, audit_read, files, inventory, session, spool

JOB_ID_RE = re.compile(r"^[0-9a-f]{8,32}$")
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")


def _err(code, message, **extra):
    return code, {"error": message, **extra}


# ---- GET ----
def api_list(req):
    return 200, {"secrets": inventory.list_data(), "auto": inventory.auto_targets()}


def api_plan(req):
    return 200, {"selected": inventory.auto_targets()}


def api_job(req):
    return 200, spool.job_result(req.path.rsplit("/", 1)[1], JOB_ID_RE)


def api_audit(req):
    return 200, audit_read.digest()


def api_files(req):
    return 200, files.data()


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


def api_user_create(req):
    """Create a portal account.

    Carries a password, so it re-authenticates on every call like `add` and
    `reveal`. The job keeps it under the key `value`: that is what makes the worker
    delete the spool file instead of archiving it."""
    if not session.check_password(str(req.body.get("password", ""))):
        return _err(401, "bad password")
    username = str(req.body.get("username", "")).strip()
    role = str(req.body.get("role", ""))
    value = str(req.body.get("value", ""))
    if not USERNAME_RE.match(username):
        return _err(400, "identifiant invalide : 2 à 64 caractères parmi lettres, "
                         "chiffres, . _ -")
    if role not in ROLES:
        return _err(400, f"rôle invalide: {role}")
    if len(value) < MIN_ACCOUNT_PASSWORD:
        return _err(400, f"mot de passe trop court ({MIN_ACCOUNT_PASSWORD} caractères minimum)")
    return 202, {"id": spool.queue(action="user", op="create", username=username,
                                   role=role, value=value)}


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


def api_secret_add(req):
    """Declare a secret and set its value.

    Re-auth on every call, like `reveal`: a valid session is not enough to write a
    value. The checks here mirror the worker's — they exist to give the UI a clean
    error, the worker's are the ones that decide."""
    if not session.check_password(str(req.body.get("password", ""))):
        return _err(401, "bad password")
    name = str(req.body.get("name", "")).strip()
    kind = str(req.body.get("kind", "password")).strip()
    group = str(req.body.get("group", "app")).strip()
    sinks = [str(s).strip() for s in (req.body.get("sinks") or []) if str(s).strip()]
    value = str(req.body.get("value", ""))

    if not NAME_RE.match(name):
        return _err(400, "nom invalide : majuscules, chiffres et _ (commençant par une lettre)")
    if name in Engine().cfg:
        return _err(400, f"{name} existe déjà")
    if kind not in ALL_KINDS:
        return _err(400, f"format invalide: {kind}")
    if group not in GROUPS:
        return _err(400, f"rotation invalide: {group}")
    if looks_like_apikey(name) and kind in GEN_KINDS:
        return _err(400, f"{name} est une clé API : elle ne peut pas être générée")
    if kind == "apikey" and not looks_like_apikey(name):
        return _err(400, f"{name} : kind=apikey exige API ou TOKEN dans le nom")
    if not sinks:
        return _err(400, "donner au moins un sink")
    valid = set(SINK_TYPES) | writable_schemes()
    bad = [s for s in sinks if s.split(":", 1)[0] not in valid]
    if bad:
        return _err(400, f"sink invalide: {bad[0]} (types: {', '.join(sorted(valid))})")
    if not value and kind not in GEN_KINDS:
        return _err(400, f"format {kind} non générable : fournir une valeur")

    jid = spool.queue(action="add", name=name, kind=kind, group=group, sinks=sinks,
                      value=value, length=int(req.body.get("length") or 0),
                      note=str(req.body.get("note") or ""),
                      validate=str(req.body.get("validate") or ""))
    return 202, {"id": jid, "name": name}


def api_adopt_plan(req):
    path = str(req.body.get("file", "")).strip()
    if not path.startswith("/"):
        return _err(400, "donner un chemin absolu")
    return 202, {"id": spool.queue(action="adopt_plan", file=path,
                                   prefix=str(req.body.get("prefix") or ""))}


def api_adopt_apply(req):
    path = str(req.body.get("file", "")).strip()
    only = req.body.get("only") or []
    if not path.startswith("/"):
        return _err(400, "donner un chemin absolu")
    if not isinstance(only, list) or not all(isinstance(x, str) for x in only) or not only:
        return _err(400, "aucune clé sélectionnée")
    return 202, {"id": spool.queue(action="adopt", file=path, only=only,
                                   prefix=str(req.body.get("prefix") or ""))}


def api_reveal(req):
    # Re-auth required on EVERY reveal: a valid session isn't enough.
    if not session.check_password(str(req.body.get("password", ""))):
        return _err(401, "bad password")
    name = str(req.body.get("name", ""))
    value = inventory.get_value(name)
    if value is None:
        return _err(404, "inconnu")
    return 200, {"name": name, "value": value}


GET_ROUTES = {"/api/list": api_list, "/api/plan": api_plan, "/api/audit": api_audit,
              "/api/files": api_files}
POST_ROUTES = {
    "/api/rotate": api_rotate,
    "/api/doctor": api_doctor,
    "/api/access/apply": api_access_apply,
    "/api/users": api_users,
    "/api/user": api_user,
    "/api/user/create": api_user_create,
    "/api/meta/apply": api_meta_apply,
    "/api/reveal": api_reveal,
    "/api/secret/add": api_secret_add,
    "/api/adopt/plan": api_adopt_plan,
    "/api/adopt/apply": api_adopt_apply,
}
# Routes that take or return a value behind a password: the server applies the
# anti-bruteforce delay on their 401 responses.
RATE_LIMITED = {"/api/reveal", "/api/secret/add", "/api/user/create", "/api/login"}
