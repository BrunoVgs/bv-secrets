"""Paths and domain vocabulary.

One source of configuration, three ways to set it: a project file `bv-secrets.ini`
(committed, human-readable), overridden by environment variables (Docker, OpenRC),
falling back to sane defaults. Precedence: **env > file > default**. A bare machine
with neither runs on defaults; a full stack sets the file once.
"""
import configparser
import os
import re
import shutil
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent


class ConfigError(RuntimeError):
    """Config absente ou incoherente ; remontee a l'appelant plutot qu'un
    sys.exit, pour que le worker puisse en faire un resultat de job.

    Definie ici et pas dans engine.py : les lecteurs de format (conf_yaml) en ont
    besoin et sont importes PAR engine, donc l'y laisser fermait un cycle."""
XDG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "bv-secrets"
# Starter config written by `init`. Ships inside the package, so an install with
# no checkout has something to start from.
TEMPLATE = Path(__file__).resolve().parent / "secrets.conf.example"


def _project_file(env: str, filename: str) -> Path:
    """Where a project file lives: the env override, then the current directory,
    then ~/.config/bv-secrets, then next to the code. That last one is the git
    checkout; a pip/pipx install lands in site-packages, where nobody edits
    anything, so cwd and XDG are what make an installed `bv-secrets` usable at
    all. Absent everywhere, point at the place the user should create it."""
    forced = os.environ.get(env)
    if forced:
        return Path(forced)
    for candidate in (Path.cwd() / filename, XDG_DIR / filename, PROJECT_DIR / filename):
        if candidate.exists():
            return candidate
    checkout = (PROJECT_DIR / "pyproject.toml").exists()
    return (PROJECT_DIR if checkout else XDG_DIR) / filename


CONFIG_FILE = _project_file("BV_CONFIG", "bv-secrets.ini")


def _load_project_config() -> dict:
    """The `[bv-secrets]` section of the project INI, as a flat dict. Absent or
    unreadable file -> empty dict (a bare machine needs no config file)."""
    path = CONFIG_FILE
    if not path.exists():
        return {}
    cp = configparser.ConfigParser(interpolation=None)
    cp.optionxform = str
    try:
        cp.read(path, encoding="utf-8")
    except (OSError, configparser.Error):
        return {}
    return dict(cp["bv-secrets"]) if cp.has_section("bv-secrets") else {}


_FILE = _load_project_config()


def _setting(env: str, default: str = "") -> str:
    """Resolve one setting by precedence env > file > default. The file key is the
    env name without the `BV_` prefix, lowercased (`BV_COMPOSE_DIR` -> `compose_dir`)."""
    val = os.environ.get(env)
    if val is not None:
        return val
    key = env[3:].lower() if env.startswith("BV_") else env.lower()
    return _FILE.get(key, default)


def _path(env: str, default) -> Path:
    return Path(_setting(env) or default)


def _csv(env: str, default: str = "") -> list:
    return [x.strip() for x in _setting(env, default).split(",") if x.strip()]


SECRETS_DIR = _path("BV_SECRETS_DIR", "/opt/bv-secrets")
MASTER = SECRETS_DIR / "bv-secrets.env"
LOCAL = SECRETS_DIR / "bv-secrets.env.local"
RENDER_DIR = SECRETS_DIR / "rendered"
MIRROR = SECRETS_DIR / "store.enc"
KEYFILE = SECRETS_DIR / ".masterkey"
META = SECRETS_DIR / "meta.env"          # NAME=last-set date, not secret
SPOOL = SECRETS_DIR / "spool"

# Audit: the worker (only privileged component, has docker + wheel) builds the
# full digest; the web reads it read-only. Single writer, no race.
AUDIT_DIR = SECRETS_DIR / "audit"
WORKER_DIGEST = AUDIT_DIR / "digest.json"

def _find_conf() -> Path:
    """Le format declaratif d'abord, l'INI ensuite. Les deux lecteurs coexistent
    le temps que les installations existantes migrent ; `bv-secrets migrate-conf`
    fait la bascule, et un secrets.yaml present gagne toujours."""
    forced = os.environ.get("BV_SECRETS_CONF") or _FILE.get("secrets_conf")
    if forced:
        return Path(forced)
    for filename in ("secrets.yaml", "secrets.yml", "secrets.conf"):
        for candidate in (Path.cwd() / filename, XDG_DIR / filename, PROJECT_DIR / filename):
            if candidate.exists():
                return candidate
    checkout = (PROJECT_DIR / "pyproject.toml").exists()
    return (PROJECT_DIR if checkout else XDG_DIR) / "secrets.conf"


CONF = _find_conf()


def is_yaml(path=None) -> bool:
    """Le format, decide par le contenu, pas par le nom.

    Trois endroits hors du depot figent le nom `secrets.conf` : le bind mount du
    dashboard, `BV_SECRETS_CONF` dans son image, et le modele d'init. Trancher
    sur l'extension aurait impose de les changer tous les trois en meme temps,
    et un oubli se serait vu en production, pas ici. Renifler le contenu rend la
    migration sur place possible : meme nom, meme inode, aucun montage touche."""
    path = Path(path or CONF)
    if str(path).endswith((".yaml", ".yml")):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in head.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # `[NOM]` ouvre une section INI ; `secrets:` ou `x-...:` ouvrent le YAML.
        if s.startswith("[") and s.endswith("]"):
            return False
        if s == "secrets:" or (s.startswith("x-") and ":" in s) or s.startswith("include:"):
            return True
    return False
# The INI ships `secrets_conf = secrets.conf`, so a copied template yields a bare
# filename. Left relative it would resolve against the caller's cwd -- a `list`
# from elsewhere would silently read nothing, and an `adopt` would drop a second
# secrets.conf wherever the shell happened to be. Anchor it to the project.
if not CONF.is_absolute():
    CONF = (PROJECT_DIR / CONF).resolve()
# The declaration file sits under the compose root by default, so `recreate` and
# `leaks` target the right place with no config.
COMPOSE_DIR = _path("BV_COMPOSE_DIR", CONF.parent.parent)
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.yaml"
ACCESS_CONF = _path("BV_ACCESS_CONF", COMPOSE_DIR / "access" / "access.conf")
# Renderer that turns the matrix into whatever enforces access (Caddy, nginx,
# Apache...). Any executable implementing `set <svc> <roles>` and `all`.
ACCESS_RENDER = _path("BV_ACCESS_RENDER", COMPOSE_DIR / "access" / "render-access.py")

# Audit sources read by the worker with the privileges it already has: Caddy log
# (root:0600) via `docker exec`, host log directly (group-readable: adm on Debian,
# wheel on Alpine, systemd-journal for the journal).
CADDY_LOG_DIR = _path("BV_CADDY_LOG_DIR", "/var/log/caddy")
CADDY_CONTAINER = _setting("BV_CADDY_CONTAINER") or _setting("BV_PROXY_SERVICE") or "caddy"

# Distributions disagree on where sshd and elevations are logged, and a systemd box
# may keep no file at all, so the source is resolved rather than assumed.
# `host_syslog` forces one: a path, or the literal `journal`.
HOST_LOG_CANDIDATES = ("/var/log/messages",     # Alpine, busybox syslogd
                       "/var/log/auth.log",     # Debian, Ubuntu with rsyslog
                       "/var/log/secure")       # RHEL, Fedora


def host_log_source():
    """-> ('file', Path) | ('journal', None) | (None, None) when the box logs
    nowhere we can read. Readability decides: an existing but unreadable auth.log
    (missing `adm` group) must not shadow a journal we can read."""
    forced = _setting("BV_HOST_SYSLOG", "")
    if forced:
        return ("journal", None) if forced == "journal" else ("file", Path(forced))
    for cand in HOST_LOG_CANDIDATES:
        if os.access(cand, os.R_OK):
            return "file", Path(cand)
    return ("journal", None) if shutil.which("journalctl") else (None, None)

# Elevation lens. auditd is the authority: it records elevation from cron, scripts
# and containers, which no shell history sees. audit.log is group-readable (adm on
# Debian, wheel on Alpine), so the lens needs no privilege of its own.
AUDIT_LOG = _path("BV_AUDIT_LOG", "/var/log/audit/audit.log")
AUDIT_RULES_FILE = _path("BV_AUDIT_RULES_FILE", "/etc/audit/rules.d/50-bv-elevation.rules")
ELEVATION_KEY = _setting("BV_ELEVATION_KEY", "bv_elevation")
# Context provider: zsh-history works with no extra dependency, atuin adds cwd and
# exit code but has to be installed and hooked into the shell first.
ELEVATION_CONTEXT = _setting("BV_ELEVATION_CONTEXT", "zsh-history")
ELEVATION_WINDOW = int(_setting("BV_ELEVATION_WINDOW", "4"))
# Ecart maximal entre une elevation et une commande presentee comme son contexte.
# Sans borne, une elevation lancee par cron se voit entourer des dernieres
# commandes interactives, vieilles de plusieurs heures : le rapport suggere une
# proximite qui n'existe pas, et c'est precisement ce qu'il est cense etablir.
ELEVATION_MAX_GAP = int(_setting("BV_ELEVATION_MAX_GAP", "900"))
ZSH_HISTORY = _path("BV_ZSH_HISTORY", Path.home() / ".zsh_history")

# LOCAL-ONLY: no outbound SSH. Remote sinks are rejected (see Engine._apply_sink).

# Two orthogonal axes: kind = value FORMAT, group = rotation POLICY.
# `manual` also existed as a kind, now `opaque`; kept as an alias for old configs.
GEN_KINDS = {"password", "hex", "b64", "userpass", "passphrase"}
# apikey = key issued by a third-party app; can't be generated (only valid if the
# app knows it). Regenerate in the app, then `set`.
FIXED_KINDS = {"apikey", "opaque", "manual", "computed"}
ALL_KINDS = GEN_KINDS | FIXED_KINDS
GROUPS = {"auto", "app", "careful", "manual"}
DEFAULT_LEN = {"password": 20, "hex": 32, "b64": 32, "userpass": 24, "passphrase": 24}

# Engine-native sink types. Structured connectors (envfile/regex/json/yaml/ini/toml)
# are validated separately against the locations writer registry (see Engine.check).
SINK_TYPES = ("env", "file", "mysql", "cmd")
# Roles strongest to weakest; the first one is the superuser (passes every gate).
ROLES = [r.strip() for r in _setting("BV_ROLES", "admin,trusted,guest").split(",") if r.strip()]
SUPERUSER = ROLES[0]
ROTATE_GROUPS = {"auto", "app", "careful"}


# Deployment-specific service names. Left empty, the matching feature is disabled
# rather than acting on an arbitrary service. Set via bv-secrets.ini or the env.
PROXY_SERVICE = _setting("BV_PROXY_SERVICE", "")
ACCESS_RELOAD_SERVICES = _csv("BV_ACCESS_RELOAD_SERVICES")

# Account management runs the app's own CLI in its container. Console prefix and
# subcommands are configurable so any framework works, not just Symfony.
AUTH_SERVICE = _setting("BV_AUTH_SERVICE", "")
AUTH_CONSOLE = _setting("BV_AUTH_CONSOLE", "php bin/console")
AUTH_CMD_LIST = _setting("BV_AUTH_CMD_LIST", "app:users")
AUTH_CMD_SETROLE = _setting("BV_AUTH_CMD_SETROLE", "app:set-role")
AUTH_CMD_DELETE = _setting("BV_AUTH_CMD_DELETE", "app:delete-user")
# Creation takes the password on STDIN: it must never appear in argv (ps, logs).
AUTH_CMD_CREATE = _setting("BV_AUTH_CMD_CREATE", "app:create-user --stdin")
MIN_ACCOUNT_PASSWORD = 8

# Access-log path prefixes to drop from the audit (internal polling, health checks).
AUDIT_IGNORE_PREFIXES = tuple(_csv("BV_AUDIT_IGNORE_PATHS"))

# Directories the web UI is allowed to adopt a file from. The worker runs as the
# account that owns the stack, so without this it could be pointed at ~/.ssh or any
# other file that account can read. The CLI is unaffected: it already runs as that
# account, and restricting it would buy nothing.
ADOPT_ROOTS = [Path(p).resolve() for p in _csv("BV_ADOPT_ROOTS", str(COMPOSE_DIR))]


def adopt_root_error(path: Path):
    """-> refusal message, or None if `path` sits under an allowed root."""
    allowed = [r for r in ADOPT_ROOTS if path == r or path.is_relative_to(r)]
    if allowed:
        return None
    roots = ", ".join(str(r) for r in ADOPT_ROOTS) or "(aucune)"
    return f"chemin hors des racines autorisées ({roots})"

REF = re.compile(r"\{([A-Za-z0-9_]+)\}")
# A name containing API or TOKEN marks a third-party key -> kind=apikey enforced.
_API_RE = re.compile(r"(?:^|_)(?:API|TOKEN)(?:_|$)")


def looks_like_apikey(name: str) -> bool:
    return bool(_API_RE.search(name.upper()))


# Visual classification. `kind` and `group` are the right model but they are two
# axes, and reading a list means combining them in your head every line. The class
# collapses them into the one question actually being asked at a glance: is this
# mine to set or the app's, and does `rotate` touch it. Shared here rather than in
# each front end, so the CLI and the dashboard can never disagree.
# Deux axes independants, et surtout SEPARES a l'affichage. Les melanger en une
# seule famille faisait dire deux fois la meme chose ("MDP auto" en titre, "auto"
# dans la colonne groupe) tout en cachant la question qui compte : est-ce MON mot
# de passe, ou une cle emise par une app tierce ?
#
#   objet    ce que la valeur EST      -> mot de passe | token/API | calcule
#   rotation QUAND elle est regeneree  -> auto | sur demande | jamais

OBJ_PASSWORD = "password"      # une valeur que je pose ou que je genere
OBJ_TOKEN = "token"            # emise par une app tierce, jamais generable
OBJ_COMPUTED = "computed"      # derivee d'autres secrets, jamais stockee
OBJ_ORDER = (OBJ_PASSWORD, OBJ_TOKEN, OBJ_COMPUTED)

ROT_AUTO = "auto"              # `rotate` nu la regenere
ROT_ONDEMAND = "ondemand"      # regeneree seulement si explicitement ciblee
ROT_NEVER = "never"            # jamais regeneree
ROT_ORDER = (ROT_AUTO, ROT_ONDEMAND, ROT_NEVER)


def secret_object(kind: str, name: str = "") -> str:
    """-> OBJ_*. Le nom tranche : API/TOKEN dedans designe une cle tierce, meme
    si le `kind` declare pretend le contraire -- la generer casserait l'app."""
    if kind == "computed":
        return OBJ_COMPUTED
    if kind == "apikey" or looks_like_apikey(name):
        return OBJ_TOKEN
    return OBJ_PASSWORD


def secret_rotation(kind: str, group: str, name: str = "") -> str:
    """-> ROT_*. Une cle tierce et une valeur calculee ne se rotent jamais d'ici,
    quel que soit leur groupe : l'une appartient a l'app, l'autre est derivee."""
    if secret_object(kind, name) != OBJ_PASSWORD or kind not in GEN_KINDS:
        return ROT_NEVER
    if group == "auto":
        return ROT_AUTO
    return ROT_ONDEMAND if group in ROTATE_GROUPS else ROT_NEVER