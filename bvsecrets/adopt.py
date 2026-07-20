"""Onboarding d'une application : détecter les secrets d'un fichier de config,
proposer leur déclaration, adopter leurs valeurs.

Le classifieur n'est qu'une heuristique : le résultat est TOUJOURS proposé pour
relecture, jamais écrit sans confirmation. Il transforme « éditer secrets.conf à
la main » en « relire une liste et ajuster ».

Limité aux fichiers env : l'énumération des clés y est fiable et le connecteur
`envfile:` sait relire ET réécrire. Les configs structurés (YAML/JSON) s'adoptent
à la main avec `add` + `regex:` tant que leurs écrivains dédiés n'existent pas.
"""
import re
from collections import namedtuple

from . import locations
from .config import looks_like_apikey

# Un nom se lit par segments (DB_PASSWORD -> {DB, PASSWORD}) pour éviter qu'une
# sous-chaîne trompe la détection (MONKEY ne contient pas le secret « KEY »).
_SECRET_TOKENS = {"PASS", "PASSWORD", "PWD", "SECRET", "TOKEN", "APIKEY", "KEY",
                  "CREDENTIAL", "CREDENTIALS", "AUTH", "SALT", "SEED", "PRIVATE", "DSN"}
_CONFIG_TOKENS = {"HOST", "HOSTNAME", "PORT", "URL", "URI", "PATH", "DIR", "NAME",
                  "USER", "USERNAME", "ENABLE", "ENABLED", "DEBUG", "LEVEL", "LOG",
                  "TZ", "LANG", "LOCALE", "MODE", "ENV", "VERSION", "TIMEOUT", "REGION"}

Proposal = namedtuple("Proposal", "key name kind group value")


def _tokens(name):
    return set(re.split(r"[_\-.]+", name.upper()))


def _embeds_credentials(value):
    # une URL/DSN qui porte des identifiants : scheme://user:pass@host
    return bool(re.search(r"://[^/\s:@]+:[^/\s@]+@", value or ""))


def looks_secret(name, value):
    tokens = _tokens(name)
    if tokens & _SECRET_TOKENS:
        return True
    if _embeds_credentials(value):
        return True
    if tokens & _CONFIG_TOKENS:
        return False
    # ni nom parlant ni config connue : une valeur longue et variée est suspecte
    return bool(value) and len(value) >= 24 and len(set(value)) >= 10


def guess_kind(name, value):
    if looks_like_apikey(name):
        return "apikey"                      # nom en API/TOKEN -> jamais générable
    value = value or ""
    if re.fullmatch(r"[0-9a-fA-F]{16,}", value):
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9_-]{20,}", value) and not value.isalnum():
        return "b64"
    return "password"


def default_group(kind):
    # une clé émise par une app n'est jamais générable -> manual ; le reste part en
    # `app` (rotable uniquement si ciblé), jamais `auto` : on n'aspire pas un secret
    # tiers dans la rotation automatique avant que l'humain ait validé que c'est sûr.
    return "manual" if kind == "apikey" else "app"


def plan_envfile(path, prefix="", known=frozenset()):
    """-> (proposals, ignored, conflicts) pour un fichier env.

    proposals : secrets à déclarer ; ignored : clés jugées non secrètes ;
    conflicts : noms déjà pris dans secrets.conf (à préfixer)."""
    proposals, ignored, conflicts = [], [], []
    for key in locations.env_keys(str(path)):
        value = locations.env_read(str(path), key)
        if not looks_secret(key, value):
            ignored.append(key)
            continue
        name = f"{prefix}{key}" if prefix else key
        if name in known:
            conflicts.append(name)
            continue
        kind = guess_kind(key, value)
        proposals.append(Proposal(key, name, kind, default_group(kind), value or ""))
    return proposals, ignored, conflicts


def sink_for(path, key):
    return f"envfile:{path}#{key}"
