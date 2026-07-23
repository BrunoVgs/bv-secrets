"""Audit lens: aggregate existing logs into one timeline. No new source, no
retention, no secret value. Event = {ts, source, actor, target, outcome, detail}.

The worker builds the full digest with the privileges it already has: Caddy log
(root:0600) via `docker exec`, host syslog (root:wheel) read directly as bv.
"""
import configparser
import datetime
import gzip
import json
import os
import re
import subprocess
import time
from pathlib import Path

from .config import (ACCESS_CONF, AUDIT_DIR, AUDIT_IGNORE_PREFIXES, CADDY_CONTAINER,
                     CADDY_LOG_DIR, HOST_SYSLOG, SPOOL, WORKER_DIGEST)
from .engine import Engine

CACHE_LIMIT = 500
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def event(ts, source, actor, target, outcome, detail):
    return {"ts": float(ts), "source": source, "actor": actor,
            "target": target, "outcome": outcome, "detail": detail}


def parse_since(spec) -> float:
    """'24h' | '7d' | '90s' | int seconds -> cutoff epoch. 0 = no cutoff."""
    if not spec:
        return 0.0
    spec = str(spec).strip()
    mult = _UNIT.get(spec[-1:], 0)
    delta = int(spec[:-1]) * mult if mult else int(spec)
    return time.time() - delta


# --- Caddy access log ------------------------------------------------------- #
def _service_roles() -> dict:
    """service -> required roles, from access.conf, to annotate denials."""
    cp = configparser.ConfigParser()
    cp.optionxform = str
    try:
        cp.read(ACCESS_CONF, encoding="utf-8")
    except OSError:
        return {}
    out = {}
    for s in cp.sections():
        if s != "meta":
            raw = cp.get(s, "roles", fallback="")
            out[s] = [r.strip() for r in raw.split(",") if r.strip()]
    return out


def _read_lines(path: Path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", errors="ignore") as f:
            yield from f
    else:
        with path.open(errors="ignore") as f:
            yield from f


def _read_caddy(path: Path):
    """Caddy log lines. root:0600, so read via `docker exec` (docker we already
    have); fall back to direct read if the file ever becomes accessible."""
    try:
        yield from _read_lines(path)
        return
    except (PermissionError, OSError):
        pass
    raw = subprocess.run(["docker", "exec", CADDY_CONTAINER, "cat", str(path)],
                         capture_output=True).stdout
    if path.suffix == ".gz" and raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    yield from raw.decode(errors="ignore").splitlines()


def _caddy_files(cutoff: float):
    """Current access.log then rolled .gz, newest first; stop past the cutoff.
    Dir is 755: bv can list even though the 0600 files aren't directly readable."""
    files = []
    current = CADDY_LOG_DIR / "access.log"
    if current.exists():
        files.append(current)
    for gz in sorted(CADDY_LOG_DIR.glob("access-*.log.gz"), reverse=True):
        if cutoff and gz.stat().st_mtime < cutoff:
            break
        files.append(gz)
    return files


_ASSET_EXT = {"css", "js", "png", "svg", "ico", "jpg", "jpeg", "gif", "webp",
              "woff", "woff2", "ttf", "map"}


def _is_asset(uri: str) -> bool:
    if uri.startswith(("/static", "/assets", "/favicon")):
        return True
    last = uri.rsplit("/", 1)[-1]
    return "." in last and last.rsplit(".", 1)[-1].lower() in _ASSET_EXT


def _client_ip(req: dict) -> str:
    ip = req.get("remote_ip") or req.get("client_ip") or req.get("remote_addr") or ""
    return ip.rsplit(":", 1)[0] if ip.count(":") == 1 else ip


def caddy_events(since: float = 0.0):
    """HTTP accesses in plain words. Drops static assets and any path prefix in
    BV_AUDIT_IGNORE_PATHS (internal polling, health checks)."""
    roles = _service_roles()
    out = []
    for path in _caddy_files(since):
        for line in _read_caddy(path):
            try:
                o = json.loads(line)
            except ValueError:
                continue
            if "status" not in o:
                continue
            ts = float(o.get("ts") or 0)
            if since and ts < since:
                continue
            req = o.get("request", {})
            host = req.get("host", "")
            uri = (req.get("uri", "") or "").split("?", 1)[0]
            if _is_asset(uri) or (AUDIT_IGNORE_PREFIXES and uri.startswith(AUDIT_IGNORE_PREFIXES)):
                continue
            service = host.split(".", 1)[0] or host      # subdomain, or host if none
            status = int(o.get("status") or 0)
            user = (req.get("headers", {}).get("X-Auth-User") or [""])[0]
            actor = user or _client_ip(req)

            if status == 403:
                outcome, detail = "deny", f"refusé sur {service} (rôle insuffisant)"
            elif status == 401:
                outcome, detail = "deny", f"connexion requise — {service}"
            elif status in (301, 302, 303, 307, 308):
                continue                         # redirects (incl. login bounces): not audit events
            elif 500 <= status < 600:
                outcome, detail = "info", f"erreur serveur — {service}"
            elif status == 404:
                outcome, detail = "info", f"page introuvable — {service}"
            elif 200 <= status < 400:            # 2xx and 304 (cached)
                outcome, detail = "allow", f"a consulté {service}"
            else:
                continue
            if outcome == "deny" and roles.get(service):
                detail += f" [rôles requis : {'+'.join(roles[service])}]"
            out.append(event(ts, "access", actor, service, outcome, detail))
    return out


# --- Trail: privileged actions from the spool ------------------------------- #
def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


_DOCTOR_TALLY = re.compile(r"(\d+)\s+ok,\s+(\d+)\s+KO,\s+(\d+)\s+sans probe")


def _doctor_detail(res: dict):
    """(detail, failures) from doctor's tally line. No value in that log."""
    for line in reversed(res.get("log") or []):
        m = _DOCTOR_TALLY.search(line)
        if m:
            ok, ko, none = m.groups()
            return f"Doctor — {ok} OK, {ko} faux, {none} sans sonde", int(ko)
    return "Doctor — vérification des secrets", 0


def _trail_summary(req: dict, res: dict):
    """(target, detail, outcome), or None to skip. A doctor is a check, not a
    change; listing accounts isn't an event."""
    action = req.get("action", "?")
    failed = res.get("status") == "error"
    ko = "deny" if failed else "change"

    if action == "users":
        return None
    if action == "doctor":
        detail, faux = _doctor_detail(res)
        return "", detail, ("deny" if faux else "check")
    if action == "access":
        chg = req.get("changes") or []
        svcs = ", ".join(f"{c.get('service')}→{'+'.join(c.get('roles', []))}" for c in chg)
        return "", f"Accès — {svcs}", ko
    if action == "user":
        u, op = req.get("username", "?"), req.get("op", "?")
        what = f"rôle → {req.get('role')}" if op == "role" else "suppression du compte"
        return u, f"Compte — {what}", ko
    if action == "meta":
        names = [c.get("name") for c in (req.get("changes") or []) if c.get("name")]
        return (names[0] if len(names) == 1 else ""), \
               f"Format/rotation — {', '.join(names)}", ko
    if action in ("rotate", "apply"):
        only = req.get("only") or []
        label = "Rotation" if action == "rotate" else "Application"
        return (only[0] if len(only) == 1 else ""), \
               f"{label} — {', '.join(only) or 'groupe auto'}", ko
    return "", action, ("deny" if failed else "info")


def trail_events(since: float = 0.0):
    done, results = SPOOL / "done", SPOOL / "results"
    out = []
    for req_path in done.glob("*.json"):
        req = _load(req_path)
        if not req:
            continue
        res = _load(results / req_path.name)
        ts = float(res.get("ts") or req.get("ts") or 0)
        if since and ts < since:
            continue
        summary = _trail_summary(req, res)
        if summary is None:
            continue
        target, detail, outcome = summary
        out.append(event(ts, "trail", req.get("src", "?"), target, outcome, detail))
    return out


# --- Rotation dates (meta.env) ---------------------------------------------- #
def rotdate_events(since: float = 0.0):
    out = []
    for name, when in Engine.meta().items():
        try:
            ts = datetime.datetime.strptime(when.strip(), "%Y-%m-%d %H:%M").timestamp()
        except ValueError:
            continue
        if since and ts < since:
            continue
        out.append(event(ts, "rotdate", "system", name, "change", "dernier set du secret"))
    return out


# --- Host: sshd + doas from syslog ------------------------------------------ #
_SYSLOG_TS = re.compile(r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s")
_SSH_OK = re.compile(r"Accepted \S+ for (\S+) from (\S+)")
_SSH_KO = re.compile(r"(?:Failed \S+|Invalid user|authentication failure).* for (?:invalid user )?(\S+)"
                     r"(?: from (\S+))?")
_DOAS = re.compile(r"doas(?:\[\d+\])?:\s*(.*)$")


def _syslog_ts(line: str) -> float:
    m = _SYSLOG_TS.match(line)
    if not m:
        return 0.0
    now = datetime.datetime.now()
    try:
        dt = datetime.datetime.strptime(f"{now.year} {m.group(1)}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return 0.0
    if dt - now > datetime.timedelta(days=1):     # year rollover (Dec line read in Jan)
        dt = dt.replace(year=now.year - 1)
    return dt.timestamp()


def host_events(since: float = 0.0):
    """SSH logins (accepted/refused) and doas elevations."""
    if not HOST_SYSLOG.exists():
        return []
    out = []
    for line in _read_lines(HOST_SYSLOG):
        if "sshd" not in line and "doas" not in line:
            continue
        ts = _syslog_ts(line)
        if since and ts < since:
            continue
        if "sshd" in line:
            m = _SSH_OK.search(line)
            if m:
                out.append(event(ts, "host", m.group(2), m.group(1), "login",
                                 f"connexion SSH réussie ({m.group(1)})"))
                continue
            m = _SSH_KO.search(line)
            if m:
                out.append(event(ts, "host", m.group(2) or "?", m.group(1), "deny",
                                 f"connexion SSH refusée ({m.group(1)})"))
                continue
        d = _DOAS.search(line)
        if d:
            msg = d.group(1)
            actor = msg.split()[0] if msg else "?"
            failed = "fail" in msg.lower()
            out.append(event(ts, "host", actor, "serveur (doas)",
                             "deny" if failed else "change",
                             "élévation doas refusée" if failed else "commande admin via doas"))
    return out


# --- Assembly + digest ------------------------------------------------------ #
ALL_SOURCES = ("access", "trail", "host", "rotdate")


def collect(sources, since: float = 0.0):
    out = []
    if "trail" in sources:
        out += trail_events(since)
    if "rotdate" in sources:
        out += rotdate_events(since)
    if "access" in sources:
        out += caddy_events(since)
    if "host" in sources:
        out += host_events(since)
    return out


def timeline(events, service=None, ip=None, user=None, denied=False, limit=200):
    def keep(e):
        if denied and e["outcome"] != "deny":
            return False
        if service and service not in (e["target"] or ""):
            return False
        if ip and ip not in (e["actor"] or ""):
            return False
        if user and user.lower() not in f"{e['actor']} {e['target']} {e['detail']}".lower():
            return False
        return True
    out = [e for e in events if keep(e)]
    out.sort(key=lambda e: e["ts"], reverse=True)
    return out[:limit]


ACCESS_KEEP = 150       # cap on non-denial accesses after dedup, so they can't drown the rest


def build_worker_digest(days: int = 30):
    """Balanced digest for the dashboard. The Caddy log is huge and repetitive, so
    access events are collapsed to one row per (client, service, outcome) and capped;
    every denial, change, login and rotation is kept. The CLI `audit` stays raw."""
    since = time.time() - days * 86400
    events = []
    for fn in (trail_events, rotdate_events, host_events):   # low volume: keep all
        try:
            events += fn(since)
        except Exception:
            pass
    try:
        gated = set(_service_roles())             # services you actually put behind the matrix
        access = sorted(caddy_events(since), key=lambda e: e["ts"], reverse=True)
        seen, uniq = set(), []
        for e in access:                          # keep the most recent of each triple
            key = (e["actor"], e["target"], e["outcome"])
            if key not in seen:
                seen.add(key)
                uniq.append(e)
        denies = [e for e in uniq if e["outcome"] == "deny"]
        # allows/errors only for gated services: drops public-homepage bot crawl. With no
        # matrix, gating is unknown so everything is kept (just deduped).
        rest = [e for e in uniq if e["outcome"] != "deny" and (not gated or e["target"] in gated)]
        events += denies + rest[:ACCESS_KEEP]
    except Exception:
        pass
    events.sort(key=lambda e: e["ts"], reverse=True)
    AUDIT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = WORKER_DIGEST.with_suffix(".tmp")
    tmp.write_text(json.dumps({"ts": time.time(), "events": events[:CACHE_LIMIT]}))
    os.chmod(tmp, 0o644)
    tmp.replace(WORKER_DIGEST)
