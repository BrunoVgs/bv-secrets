"""App onboarding: detect a config file's secrets, propose declarations, adopt
their values.

The classifier is a heuristic: the result is ALWAYS proposed for review, never
written without confirmation. Turns "edit secrets.conf by hand" into "review a
list and adjust".

Adopter un fichier, c'est le confier a bv-secrets : il enumere ce qu'il contient,
propose une categorie pour chaque valeur, et ecrit ensuite DEDANS -- le fichier ne
bouge pas de place et n'est jamais reserialise, seule la valeur visee change.

Quatre familles de format, la meme heuristique pour toutes : `.env`, `.toml`,
`.yaml`/`.yml`, `.json`, `.ini`/`.cfg`/`.conf`. Une cle imbriquee devient un chemin
pointe (`server.database.password`), qui est exactement le selecteur attendu par le
sink correspondant.
"""
import configparser
import json
import re
from collections import namedtuple
from pathlib import Path

from . import locations
from .config import looks_like_apikey

# Names are read by segment (DB_PASSWORD -> {DB, PASSWORD}) so a substring doesn't
# fool detection (MONKEY doesn't contain the "KEY" token).
_SECRET_TOKENS = {"PASS", "PASSWORD", "PWD", "PW", "SECRET", "TOKEN", "APIKEY", "KEY",
                  "CREDENTIAL", "CREDENTIALS", "AUTH", "SALT", "SEED", "PRIVATE", "DSN"}
_CONFIG_TOKENS = {"HOST", "HOSTNAME", "PORT", "URL", "URI", "PATH", "DIR", "NAME",
                  "USER", "USERNAME", "ENABLE", "ENABLED", "DEBUG", "LEVEL", "LOG",
                  "TZ", "LANG", "LOCALE", "MODE", "ENV", "VERSION", "TIMEOUT", "REGION"}

# Le DERNIER mot dit ce que la cle est ; ceux d'avant la qualifient. AUTH_USERNAME
# est un nom de compte, pas un secret, meme si AUTH figure dedans.
_IDENTITY_WORDS = {"USER", "USERNAME", "LOGIN", "NAME", "HOST", "HOSTNAME", "PORT"}
# Une cle de chiffrement ne se rote pas : la changer rend illisible tout ce
# qu'elle a chiffre. Seul un humain peut decider de le faire.
_NEVER_ROTATE = {"ENCRYPTION", "ENCRYPT", "MASTER"}

Proposal = namedtuple("Proposal", "key name kind group value")


def _words(name):
    """-> les mots du nom, dans l'ordre. Le camelCase est coupe aussi : c'est la
    convention des fichiers toml/json/yaml, et sans ca `sessionSecret` ne rendait
    qu'un seul mot (SESSIONSECRET) qui ne matchait rien -- il n'etait detecte que
    par accident, parce que sa valeur etait longue."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return [w for w in re.split(r"[_\-.]+", spaced.upper()) if w]


def _tokens(name):
    return set(_words(name))


def _embeds_credentials(value):
    # a URL/DSN carrying credentials: scheme://user:pass@host
    return bool(re.search(r"://[^/\s:@]+:[^/\s@]+@", value or ""))


def _looks_random(value):
    return bool(value) and len(value) >= 24 and len(set(value)) >= 10


def looks_secret(name, value):
    words = _words(name)
    tokens = set(words)
    if _embeds_credentials(value):
        return True
    # Un nom de compte n'est pas un secret -- mais le nom seul ne suffit pas a
    # l'ecarter : une valeur longue et variee sous AUTH_USER reste proposee. Dans
    # le doute on propose, la revue tranche ; l'inverse laisserait un secret
    # hors du coffre sans que personne l'ait decide.
    if words and words[-1] in _IDENTITY_WORDS and not _looks_random(value):
        return False
    if tokens & _SECRET_TOKENS:
        return True
    if tokens & _CONFIG_TOKENS:
        return False
    # no telltale name, no known config: a long, varied value is suspect
    return _looks_random(value)


def guess_kind(name, value):
    if looks_like_apikey(name):
        return "apikey"                      # name in API/TOKEN -> never generatable
    value = value or ""
    if re.fullmatch(r"[0-9a-fA-F]{16,}", value):
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9_-]{20,}", value) and not value.isalnum():
        return "b64"
    return "password"


def default_group(kind, name=""):
    # an app-issued key is never generatable -> manual; everything else -> `app`
    # (rotated only if targeted), never `auto`: don't pull a third-party secret into
    # automatic rotation before a human confirms it's safe.
    if kind == "apikey" or _tokens(name) & _NEVER_ROTATE:
        return "manual"
    return "app"


def _names(prefix, bases):
    """base -> nom du secret. Le prefixe sert a distinguer deux apps qui ont la
    meme cle ; une cle qui le porte deja n'a pas a le recevoir deux fois
    (N8N_N8N_ENCRYPTION_KEY). Sauf quand deux cles du meme fichier finiraient
    sous un seul nom (`N8N_KEY` et `KEY`) : celles-la gardent le prefixe entier,
    sinon l'une ecraserait l'autre en silence."""
    short = {b: b if not prefix or b.startswith(prefix) else f"{prefix}{b}" for b in bases}
    seen = list(short.values())
    return {b: short[b] if seen.count(short[b]) == 1 else f"{prefix}{b}" for b in bases}


def _plan(found, prefix, known):
    """found = [(cle dans le fichier, base du nom, valeur)] deja juges secrets."""
    names = _names(prefix, [base for _, base, _ in found])
    proposals, conflicts = [], []
    for key, base, value in found:
        name = names[base]
        if name in known:
            conflicts.append(name)
            continue
        kind = guess_kind(key, value)
        proposals.append(Proposal(key, name, kind, default_group(kind, key), value or ""))
    return proposals, conflicts


# Extension -> schema de sink. C'est le meme tableau qui decide comment enumerer
# le fichier et comment y ecrire : les deux ne peuvent pas diverger.
SCHEME_BY_SUFFIX = {
    ".env": "envfile", ".toml": "toml", ".yaml": "yaml", ".yml": "yaml",
    ".json": "json", ".ini": "ini", ".cfg": "ini", ".conf": "ini",
}


def scheme_for(path) -> str:
    """-> le schema de sink adapte au fichier. Un nom sans extension connue, ou
    commencant par un point (`.env`, `.env.local`), est traite en env."""
    p = Path(path)
    if p.suffix in SCHEME_BY_SUFFIX:
        return SCHEME_BY_SUFFIX[p.suffix]
    if p.name.startswith(".env") or p.name.endswith(".env"):
        return "envfile"
    return "envfile"


def sink_for(path, key, scheme=None):
    return f"{scheme or scheme_for(path)}:{path}#{key}"


def _flatten(obj, prefix=""):
    """Structure imbriquee -> [(chemin.pointe, valeur)] pour les seuls scalaires.
    Les listes sont ignorees : un sink designe une cle, pas un indice, et viser
    `a.b.0` casserait des que l'ordre de la liste change."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        out.append((prefix, str(obj)))
    return out


def _read_toml(path):
    import tomllib
    with open(path, "rb") as fh:
        return _flatten(tomllib.load(fh))


def _read_json(path):
    return _flatten(json.loads(Path(path).read_text(encoding="utf-8")))


def _read_ini(path):
    cp = configparser.ConfigParser(interpolation=None)
    cp.optionxform = str
    cp.read(path, encoding="utf-8")
    return [(f"{sec}.{k}", v) for sec in cp.sections() for k, v in cp[sec].items()]


def _read_yaml(path):
    """Sous-ensemble YAML suffisant pour enumerer des cles : le lecteur maison du
    projet sert deja a ca, et ajouter une dependance pour lire un fichier tiers
    serait payer cher une commodite."""
    from . import conf_yaml
    rows, stack = [], []
    for _num, indent, body in conf_yaml._lines(Path(path).read_text(encoding="utf-8")):
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*:\s*(.*)$", body)
        if not m:
            continue
        key, rest = m.group(1), m.group(2).strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path_parts = [k for _i, k in stack] + [key]
        if rest:
            rows.append((".".join(path_parts), conf_yaml._unquote(rest)))
        else:
            stack.append((indent, key))
    return rows


READERS = {"envfile": None, "toml": _read_toml, "yaml": _read_yaml,
           "json": _read_json, "ini": _read_ini}


def entries(path):
    """-> [(cle, valeur)] quel que soit le format. La cle est le selecteur exact
    a mettre dans le sink."""
    scheme = scheme_for(path)
    reader = READERS.get(scheme)
    if reader is None:
        return [(k, locations.read_location(f"envfile:{path}#{k}") or "")
                for k in locations.env_keys(str(path))]
    return reader(path)


def plan_file(path, prefix="", known=frozenset()):
    """-> (proposals, ignored, conflicts) pour n'importe quel format supporte."""
    found, ignored = [], []
    for key, value in entries(path):
        if not looks_secret(key, value):
            ignored.append(key)
            continue
        # Le nom du secret ne peut pas porter de point : on remonte le chemin en
        # majuscules, ce qui donne aussi un nom lisible (DB_PASSWORD, pas db.password).
        found.append((key, re.sub(r"[^A-Za-z0-9]+", "_", key).strip("_").upper(), value))
    proposals, conflicts = _plan(found, prefix, known)
    return proposals, ignored, conflicts
