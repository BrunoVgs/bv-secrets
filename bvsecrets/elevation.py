"""Elevation lens: who became root, when, and what surrounded it.

auditd is the authority. It records elevation from cron, scripts and containers,
none of which any shell history sees; the history only supplies the human context
around an event. Reading is unprivileged: audit.log is group-readable (adm on
Debian, wheel on Alpine) and the account already belongs to that group.
"""
import binascii
import datetime
import os
import pwd
import re
import shutil
import subprocess
from pathlib import Path

from .config import (AUDIT_LOG, ELEVATION_CONTEXT, ELEVATION_KEY, ELEVATION_MAX_GAP,
                     ELEVATION_WINDOW, ZSH_HISTORY)

RULES_TEMPLATE = """\
# Rendered by bv-secrets -- do not edit. Elevation trail feeding `bv-secrets elevation`.
# execve with uid != euid catches every path to root; the watches name the usual tools
# so a refused attempt is recorded too.
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k {key}
-w /usr/bin/sudo -p x -k {key}
-w /usr/bin/doas -p x -k {key}
-w /bin/su -p x -k {key}
"""

_MSG = re.compile(r"type=(\w+) msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)$")
_FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')
_HEX = re.compile(r"[0-9A-Fa-f]+")
_ZSH = re.compile(r"^: (\d+):\d+;(.*)$")

# Verified against the atuin CLI: --format placeholders are time, command, duration,
# directory, exit, host, user, relativetime. The local SQLite schema is explicitly
# not stable upstream, so the CLI is the only supported read path.
_ATUIN_FORMAT = "{time}\t{exit}\t{command}"


def render_rules(key: str = None) -> str:
    return RULES_TEMPLATE.format(key=key or ELEVATION_KEY)


def source_error(audit_log=None):
    """-> why the trail cannot be read, or None when it can.

    Kept separate from an empty result on purpose: a lens that answers "nothing
    happened" while it is merely blind is worse than no lens at all.
    """
    path = Path(audit_log or AUDIT_LOG)
    who = pwd.getpwuid(os.getuid()).pw_name
    fix = (f"Donner le journal a un groupe plutot qu'un droit sudo dormant :\n"
           f"    log_group = wheel   dans /etc/audit/auditd.conf   (adm sur Debian/Ubuntu)\n"
           f"    puis redemarrer auditd; le repertoire passe en 0750 et le log en 0640.")
    # An unreadable parent hides the file from stat(), so the directory is checked
    # first: otherwise a permission problem is misreported as a missing auditd.
    parent = path.parent
    if parent.is_dir() and not os.access(parent, os.X_OK):
        return f"{parent} n'est pas traversable par {who} (mode 0700).\n{fix}"
    if not path.exists():
        return (f"{path} est absent: auditd n'ecrit pas la, ou n'est pas installe.\n"
                f"    rc-service auditd status   (ou systemctl status auditd)")
    if not os.access(path, os.R_OK):
        return f"{path} est illisible par {who}.\n{fix}"
    return None


def _plain(raw: str) -> str:
    return raw[1:-1] if len(raw) > 1 and raw[0] == '"' else raw


def _decoded(raw: str) -> str:
    """audit hex-encodes any argument holding a space, a quote or a newline."""
    if len(raw) > 1 and raw[0] == '"':
        return raw[1:-1]
    if len(raw) % 2 == 0 and _HEX.fullmatch(raw):
        try:
            return binascii.unhexlify(raw).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            pass
    return raw


def _user(uid: str) -> str:
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError, TypeError):
        return uid or "?"


def _records(path: Path, since: float, key: str):
    """-> [event] carrying `key`, oldest first.

    One elevation spans several lines sharing a serial: SYSCALL holds the identity,
    EXECVE the arguments, PROCTITLE the full command line.
    """
    events = {}
    try:
        fh = open(path, "r", errors="replace")
    except OSError:
        return []
    with fh:
        for line in fh:
            m = _MSG.match(line)
            if not m:
                continue
            rtype, ts, serial, rest = m.group(1), float(m.group(2)), m.group(3), m.group(4)
            if since and ts < since:
                continue
            fields = dict(_FIELD.findall(rest))
            ev = events.setdefault(serial, {"ts": ts, "f": {}, "argv": [], "proctitle": ""})
            if rtype == "SYSCALL":
                ev["f"] = {k: _plain(v) for k, v in fields.items()}
            elif rtype == "EXECVE":
                argc = int(fields.get("argc", "0") or 0)
                ev["argv"] = [_decoded(fields[f"a{i}"]) for i in range(argc) if f"a{i}" in fields]
            elif rtype == "PROCTITLE" and "proctitle" in fields:
                ev["proctitle"] = _decoded(fields["proctitle"]).replace("\x00", " ").strip()
    out = [e for e in events.values() if e["f"].get("key") == key]
    return sorted(out, key=lambda e: e["ts"])


def _zsh_context(ts: float, window: int, path=None):
    """-> ([before], [after]) from zsh EXTENDED_HISTORY.

    Entries written without a timestamp cannot be placed around an event, so they
    are skipped rather than guessed at.
    """
    rows = []
    try:
        with open(Path(path or ZSH_HISTORY), "r", errors="replace") as fh:
            for line in fh:
                m = _ZSH.match(line)
                if m:
                    rows.append((int(m.group(1)), m.group(2).strip()))
    except OSError:
        return [], []
    rows.sort()
    fmt = lambda t, c: {"when": datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S"),
                        "cmd": c, "exit": None, "ts": t}
    before = [fmt(t, c) for t, c in rows if t <= ts][-window:]
    after = [fmt(t, c) for t, c in rows if t > ts][:window]
    return before, after


class AtuinUnavailable(RuntimeError):
    """atuin est installe mais n'a pas repondu. Remonte plutot qu'avale : un
    contexte vide affiche comme un contexte reel ferait croire qu'il ne s'est
    rien passe autour de l'elevation."""


def _atuin_rows(args):
    # `atuin search` refuse de tourner sans ATUIN_SESSION dans l'environnement.
    # Le hook shell le pose ; bv-secrets n'est pas un shell, donc il en fabrique
    # un le temps de la requete. La valeur n'est pas enregistree en base : seule
    # `atuin history start` ecrit, et on ne l'appelle pas.
    env = dict(os.environ)
    env.setdefault("ATUIN_SESSION", "0" * 32)
    out = subprocess.run(["atuin", "search", "--format", _ATUIN_FORMAT] + args,
                         capture_output=True, text=True, env=env)
    # atuin sort en code 1 quand la recherche ne trouve RIEN, ce qui arrive
    # normalement pour la fenetre `apres` de l'elevation la plus recente. Un vrai
    # probleme (session absente, base illisible) s'annonce sur stderr : c'est lui
    # qui distingue « rien a montrer » de « je ne peux pas regarder ».
    if out.stderr.strip():
        raise AtuinUnavailable(out.stderr.strip().splitlines()[0])
    rows = []
    for line in out.stdout.splitlines():
        parts = line.split("\t", 2)
        if len(parts) == 3:
            when = parts[0].strip()
            try:
                ts = datetime.datetime.strptime(when, "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                ts = None
            rows.append({"when": when, "cmd": parts[2].strip(),
                         "exit": parts[1].strip(), "ts": ts})
    return rows


def _atuin_context(ts: float, window: int):
    """-> ([before], [after]) via the atuin CLI."""
    if not shutil.which("atuin"):
        raise AtuinUnavailable(
            "atuin n'est pas installe.\n"
            "    Le contexte par defaut `zsh-history` fonctionne sans rien installer :\n"
            "        bv-secrets elevation --context zsh-history")
    stamp = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    lim = str(window)
    # L'ordre rendu par `--reverse` n'est pas celui qu'on suppose en le lisant :
    # on trie ici, pour que le rapport se lise toujours dans le sens du temps
    # quelle que soit la version d'atuin installee.
    key = lambda r: r["ts"] or 0
    before = sorted(_atuin_rows(["--before", stamp, "--limit", lim]), key=key)
    after = sorted(_atuin_rows(["--after", stamp, "--limit", lim]), key=key)
    return before[-window:], after[:window]


CONTEXT_PROVIDERS = {"zsh-history": _zsh_context, "atuin": _atuin_context}


def _near(rows, ts, max_gap=None):
    """Ne garde que ce qui encadre reellement l'elevation. Une commande a trois
    heures de la n'est pas un contexte : c'est une coincidence d'affichage."""
    gap = ELEVATION_MAX_GAP if max_gap is None else max_gap
    return [r for r in rows if r.get("ts") is None or abs(r["ts"] - ts) <= gap]


def elevations(since: float = 0.0, window: int = None, context: str = None,
               audit_log=None, key: str = None):
    """-> [row] joining each audited elevation with the commands around it."""
    window = ELEVATION_WINDOW if window is None else window
    context = context or ELEVATION_CONTEXT
    provider = CONTEXT_PROVIDERS.get(context)
    if provider is None:
        raise ValueError(f"contexte inconnu: {context} "
                         f"(disponibles: {', '.join(sorted(CONTEXT_PROVIDERS))})")
    rows = []
    for ev in _records(Path(audit_log or AUDIT_LOG), since, key or ELEVATION_KEY):
        f = ev["f"]
        cmd = " ".join(ev["argv"]) or ev["proctitle"] or f.get("comm", "?")
        before, after = provider(ev["ts"], window)
        before = _near(before, ev["ts"])
        after = _near(after, ev["ts"])
        rows.append({
            "ts": ev["ts"],
            # auid is the login uid: it survives a su/sudo chain and names the human.
            "actor": _user(f.get("auid") if f.get("auid") not in (None, "4294967295")
                           else f.get("uid")),
            "target": _user(f.get("euid", "0")),
            "tool": f.get("comm", "?"),
            "cmd": cmd,
            "uid": f.get("uid", "?"), "euid": f.get("euid", "?"),
            "pid": f.get("pid", "?"), "ppid": f.get("ppid", "?"),
            "tty": f.get("tty", "?"), "success": f.get("success", "?"),
            "before": before, "after": after,
        })
    return rows


def render(rows, window_label: str = "") -> str:
    """Plain-text report: one block per elevation, context around it."""
    if not rows:
        return (f"Aucune elevation enregistree{window_label}.\n"
                f"Si c'est inattendu, verifier que les regles d'audit sont chargees :\n"
                f"    auditctl -l | grep {ELEVATION_KEY}")
    out = []
    for r in rows:
        when = datetime.datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        verdict = "" if r["success"] == "yes" else "  [REFUSE]"
        out.append(f"{when}  {r['actor']} -> {r['target']}  {r['tool']}  {r['cmd']}{verdict}")
        for c in r["before"]:
            out.append(f"    avant  {c['when']}  {c['cmd']}")
        if not r["before"] and not r["after"]:
            # Le dire est utile : c'est la signature d'une elevation qui ne vient
            # pas d'un shell interactif -- cron, un script, un conteneur.
            out.append("    (aucune commande de shell autour : "
                       "elevation non interactive)")
        out.append(f"    ELEVATION  uid={r['uid']} -> euid={r['euid']}  "
                   f"pid={r['pid']}  ppid={r['ppid']}  tty={r['tty']}")
        for c in r["after"]:
            out.append(f"    apres  {c['when']}  {c['cmd']}")
        out.append("")
    return "\n".join(out).rstrip()
