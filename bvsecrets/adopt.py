"""App onboarding: detect a config file's secrets, propose declarations, adopt
their values.

The classifier is a heuristic: the result is ALWAYS proposed for review, never
written without confirmation. Turns "edit secrets.conf by hand" into "review a
list and adjust".

Env files only: key enumeration is reliable there. Structured configs
(json/yaml/ini/toml) have read+write connectors but no key enumeration yet, so they
are declared by hand with `add` targeting the matching scheme.
"""
import re
from collections import namedtuple

from . import locations
from .config import looks_like_apikey

# Names are read by segment (DB_PASSWORD -> {DB, PASSWORD}) so a substring doesn't
# fool detection (MONKEY doesn't contain the "KEY" token).
_SECRET_TOKENS = {"PASS", "PASSWORD", "PWD", "SECRET", "TOKEN", "APIKEY", "KEY",
                  "CREDENTIAL", "CREDENTIALS", "AUTH", "SALT", "SEED", "PRIVATE", "DSN"}
_CONFIG_TOKENS = {"HOST", "HOSTNAME", "PORT", "URL", "URI", "PATH", "DIR", "NAME",
                  "USER", "USERNAME", "ENABLE", "ENABLED", "DEBUG", "LEVEL", "LOG",
                  "TZ", "LANG", "LOCALE", "MODE", "ENV", "VERSION", "TIMEOUT", "REGION"}

Proposal = namedtuple("Proposal", "key name kind group value")


def _tokens(name):
    return set(re.split(r"[_\-.]+", name.upper()))


def _embeds_credentials(value):
    # a URL/DSN carrying credentials: scheme://user:pass@host
    return bool(re.search(r"://[^/\s:@]+:[^/\s@]+@", value or ""))


def looks_secret(name, value):
    tokens = _tokens(name)
    if tokens & _SECRET_TOKENS:
        return True
    if _embeds_credentials(value):
        return True
    if tokens & _CONFIG_TOKENS:
        return False
    # no telltale name, no known config: a long, varied value is suspect
    return bool(value) and len(value) >= 24 and len(set(value)) >= 10


def guess_kind(name, value):
    if looks_like_apikey(name):
        return "apikey"                      # name in API/TOKEN -> never generatable
    value = value or ""
    if re.fullmatch(r"[0-9a-fA-F]{16,}", value):
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9_-]{20,}", value) and not value.isalnum():
        return "b64"
    return "password"


def default_group(kind):
    # an app-issued key is never generatable -> manual; everything else -> `app`
    # (rotated only if targeted), never `auto`: don't pull a third-party secret into
    # automatic rotation before a human confirms it's safe.
    return "manual" if kind == "apikey" else "app"


def plan_envfile(path, prefix="", known=frozenset()):
    """-> (proposals, ignored, conflicts) for a .env file.

    proposals: secrets to declare; ignored: keys judged non-secret;
    conflicts: names already taken in secrets.conf (need a prefix)."""
    proposals, ignored, conflicts = [], [], []
    for key in locations.env_keys(str(path)):
        value = locations.read_location(f"envfile:{path}#{key}")
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
