"""Paths and domain vocabulary. Every path is env-overridable so the package runs
as-is on the host (CLI, worker) and in the Docker image (web)."""
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
META = SECRETS_DIR / "meta.env"          # NAME=last-set date, not secret
SPOOL = SECRETS_DIR / "spool"

# Audit: the worker (only privileged component, has docker + wheel) builds the
# full digest; the web reads it read-only. Single writer, no race.
AUDIT_DIR = SECRETS_DIR / "audit"
WORKER_DIGEST = AUDIT_DIR / "digest.json"

CONF = _path("BV_SECRETS_CONF", PROJECT_DIR / "secrets.conf")
# Project sits under the compose root by default, so `recreate`/`leaks` target the
# right place with no config.
COMPOSE_DIR = _path("BV_COMPOSE_DIR", PROJECT_DIR.parent)
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.yaml"
ACCESS_CONF = _path("BV_ACCESS_CONF", COMPOSE_DIR / "access" / "access.conf")
ACCESS_RENDER = COMPOSE_DIR / "access" / "render-access.py"

# Audit sources read by the worker with privileges it already has: Caddy log
# (root:0600) via `docker exec`, host syslog (root:wheel) directly as bv.
CADDY_LOG_DIR = _path("BV_CADDY_LOG_DIR", "/var/log/caddy")
CADDY_CONTAINER = (os.environ.get("BV_CADDY_CONTAINER")
                   or os.environ.get("BV_PROXY_SERVICE") or "caddy")
HOST_SYSLOG = _path("BV_HOST_SYSLOG", "/var/log/messages")

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

SINK_TYPES = ("env", "file", "linux", "mysql", "cmd")
ROLES = ["admin", "trusted", "guest"]     # strongest to weakest
ROTATE_GROUPS = {"auto", "app", "careful"}


def _csv(env: str) -> list:
    return [x.strip() for x in os.environ.get(env, "").split(",") if x.strip()]


# Deployment-specific service names. Left empty, the matching feature is disabled
# rather than acting on an arbitrary service. Set via /etc/conf.d/bvsecrets-worker.
PROXY_SERVICE = os.environ.get("BV_PROXY_SERVICE", "")
ACCESS_RELOAD_SERVICES = _csv("BV_ACCESS_RELOAD_SERVICES")
AUTH_SERVICE = os.environ.get("BV_AUTH_SERVICE", "")

REF = re.compile(r"\{([A-Za-z0-9_]+)\}")
# A name containing API or TOKEN marks a third-party key -> kind=apikey enforced.
_API_RE = re.compile(r"(?:^|_)(?:API|TOKEN)(?:_|$)")


def looks_like_apikey(name: str) -> bool:
    return bool(_API_RE.search(name.upper()))
