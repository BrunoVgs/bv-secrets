"""Emplacements et vocabulaire du domaine.

Tous les chemins sont surchargeables par variable d'environnement : le paquet
tourne tel quel sur l'hôte (CLI, worker) et dans l'image Docker (web), où le
store et la config sont montés ailleurs.
"""
import os
import re
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent


def _path(env: str, default) -> Path:
    return Path(os.environ.get(env) or default)


SECRETS_DIR = _path("BV_SECRETS_DIR", "/opt/bv-secrets")
MASTER = SECRETS_DIR / "bv-secrets.env"
LOCAL = SECRETS_DIR / "bv-secrets.env.local"
RENDER_DIR = SECRETS_DIR / "rendered"
MIRROR = SECRETS_DIR / "store.enc"
KEYFILE = SECRETS_DIR / ".masterkey"
META = SECRETS_DIR / "meta.env"          # NAME=date du dernier set, non secret
SPOOL = SECRETS_DIR / "spool"

CONF = _path("BV_SECRETS_CONF", PROJECT_DIR / "secrets.conf")
# Par défaut le projet est un sous-dossier de la racine compose : `recreate` et
# `audit` visent donc le bon endroit sans configuration, quel que soit le chemin.
COMPOSE_DIR = _path("BV_COMPOSE_DIR", PROJECT_DIR.parent)
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.yaml"
ACCESS_CONF = _path("BV_ACCESS_CONF", COMPOSE_DIR / "access" / "access.conf")
ACCESS_RENDER = COMPOSE_DIR / "access" / "render-access.py"

# bv-secrets est LOCAL-ONLY : aucune connexion SSH sortante. Les sinks distants
# sont refusés à l'application (cf. Engine._apply_sink).

# DEUX AXES ORTHOGONAUX :
#   kind  = FORMAT de la valeur (ce qu'elle EST)
#   group = POLITIQUE de rotation (quand on la régénère)
# `manual` a vécu sur les deux axes ; côté kind il s'appelle désormais `opaque`
# et reste accepté comme alias pour les configs anciennes.
GEN_KINDS = {"password", "hex", "b64", "userpass", "passphrase"}
# `apikey` = clé émise par une APPLICATION TIERCE. Impossible à générer : la valeur
# n'a de sens que si l'app la connaît. On la régénère dans l'app puis `set`.
FIXED_KINDS = {"apikey", "opaque", "manual", "computed"}
ALL_KINDS = GEN_KINDS | FIXED_KINDS
GROUPS = {"auto", "app", "careful", "manual"}
DEFAULT_LEN = {"password": 20, "hex": 32, "b64": 32, "userpass": 24, "passphrase": 24}

SINK_TYPES = ("env", "file", "linux", "mysql", "cmd")
ROLES = ["admin", "trusted", "guest"]     # du plus fort au plus faible
ROTATE_GROUPS = {"auto", "app", "careful"}


def _csv(env: str) -> list:
    return [x.strip() for x in os.environ.get(env, "").split(",") if x.strip()]


# Intégrations propres au déploiement : le worker pilote des services dont les
# noms varient d'une installation à l'autre. Laissés vides, les fonctionnalités
# correspondantes sont désactivées plutôt que d'agir sur un service au hasard.
# Renseignés en pratique par /etc/conf.d/bvsecrets-worker (voir deploy/).
PROXY_SERVICE = os.environ.get("BV_PROXY_SERVICE", "")
ACCESS_RELOAD_SERVICES = _csv("BV_ACCESS_RELOAD_SERVICES")
AUTH_SERVICE = os.environ.get("BV_AUTH_SERVICE", "")

REF = re.compile(r"\{([A-Za-z0-9_]+)\}")
# Un nom contenant API ou TOKEN désigne une clé d'app tierce -> kind=apikey imposé.
_API_RE = re.compile(r"(?:^|_)(?:API|TOKEN)(?:_|$)")


def looks_like_apikey(name: str) -> bool:
    return bool(_API_RE.search(name.upper()))
