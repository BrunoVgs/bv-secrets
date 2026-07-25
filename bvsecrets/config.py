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
XDG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "bv-secrets"


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
    return (PROJECT_DIR if (PROJECT_DIR / f"{filename}.example").exists() else XDG_DIR) / filename


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

CONF = _path("BV_SECRETS_CONF", _project_file("BV_SECRETS_CONF", "secrets.conf"))
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

# Access-log path prefixes to drop from the audit (internal polling, health checks).
AUDIT_IGNORE_PREFIXES = tuple(_csv("BV_AUDIT_IGNORE_PATHS"))

REF = re.compile(r"\{([A-Za-z0-9_]+)\}")
# A name containing API or TOKEN marks a third-party key -> kind=apikey enforced.
_API_RE = re.compile(r"(?:^|_)(?:API|TOKEN)(?:_|$)")


def looks_like_apikey(name: str) -> bool:
    return bool(_API_RE.search(name.upper()))
