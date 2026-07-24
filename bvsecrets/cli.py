"""CLI: thin wrapper around Engine. No value is printed outside `get` and `open`."""
import argparse
import datetime
import json
import subprocess
import sys
from pathlib import Path

from . import adopt, audit, conffile, ui
from .config import (CONF, COMPOSE_DIR, GEN_KINDS, KEYFILE, LOCAL, MASTER, MIRROR,
                     RENDER_DIR, SECRETS_DIR, looks_like_apikey)
from .engine import ConfigError, Engine, RotateAborted
from .envfile import parse_env, write_env


def _log(msg=""):
    print(msg)


def _report(problems, clean_msg):
    for p in problems:
        print(ui.paint(p, ui.RED))
    print(ui.paint(clean_msg, ui.GREEN) if not problems
          else ui.paint(f"\n{len(problems)} problème(s).", ui.RED))
    return 1 if problems else 0


def cmd_list(a, e):
    svc_of = {}
    for name, c in e.cfg.items():
        for s in c["sinks"]:
            if s.startswith("env:"):
                svc_of.setdefault(name, []).append(s[4:].split("#", 1)[0])
    meta = e.meta()
    rows = []
    for n in sorted(e.cfg):
        c = e.cfg[n]
        value = e.value_of(n)
        present = (f"{len(value)}c", ui.GREEN) if value else ("--", ui.RED)
        rows.append([n, (c["kind"], ui.DIM), c["group"], present,
                     (meta.get(n, ""), ui.DIM),
                     (", ".join(svc_of.get(n, ["(no-env)"])), ui.CYAN)])
    print(ui.table(rows, headers=["SECRET", "KIND", "GROUP", "VAL", "LAST SET", "SERVICES"]))


def cmd_check(a, e):
    return _report(e.check(), "OK — config cohérente, valeurs présentes, perms 0600.")


def cmd_verify_render(a, e):
    return _report(e.render_parity(), "PARITY OK — le render reproduit les rendered actuels.")


def cmd_render(a, e):
    e.render()
    print("rendered/*.env écrits.")


def cmd_plan(a, e):
    e.plan(e.select(a.only), _log)


def cmd_rotate(a, e):
    e.rotate(e.select(a.only), a.yes, _log)


def cmd_apply(a, e):
    e.apply(e.select(a.only), a.yes, _log)


def cmd_get(a, e):
    if a.key not in e.cfg and a.key not in e.data:
        raise ConfigError(f"clé inconnue: {a.key}")
    sys.stdout.write(e.value_of(a.key))


def cmd_set(a, e):
    target = LOCAL if a.local else MASTER
    data = parse_env(target)
    data[a.key] = a.value
    write_env(target, data)
    Engine.touch_meta([a.key])
    print(f"set {a.key} dans {target.name} ; lancer `bv-secrets apply` pour propager.")


def cmd_gen(a, e):
    kind = e.cfg.get(a.key, {}).get("kind", "password")
    if kind == "apikey" or looks_like_apikey(a.key):
        raise ConfigError(f"{a.key} est une CLE API : elle ne peut pas être générée. "
                          f"La régénérer dans l'app, puis `bv-secrets set {a.key} <valeur>`.")
    if kind not in GEN_KINDS:
        kind = a.kind
    data = parse_env(MASTER)
    data[a.key] = Engine.gen(kind, a.length)
    write_env(MASTER, data)
    Engine.touch_meta([a.key])
    print(f"généré {a.key} ({kind}) ; lancer `bv-secrets apply` pour propager.")


def cmd_import(a, e):
    """Adopt in-place values: read them where they live -> store."""
    if a.all:
        e.import_all(_log)
    elif a.name:
        e.import_one(a.name, source=a.source, force=a.force, log=_log)
    else:
        raise ConfigError("préciser un NOM, ou --all")


def cmd_status(a, e):
    """Compare the store to in-place values and report drift."""
    names = e.select(a.only) if a.only else sorted(e.cfg)
    return 1 if e.status(names, _log) else 0


def cmd_scan(a, e):
    """List a .env file's keys to help declare secrets."""
    e.scan(a.path, _log)


def cmd_add(a, e):
    """Add a secret section to secrets.conf in one command."""
    if not a.sink:
        raise ConfigError("donner au moins un sink (env:svc#VAR, file:/p, linux:user, "
                          "mysql:u@ctr, cmd:..., envfile:/p#K, json/yaml/ini/toml:/p#a.b.c)")
    conffile.append_sections(
        [conffile.render_section(a.name, a.kind, a.group, a.sink, a.length, a.note)])
    print(f"ajouté [{a.name}] à {CONF.name}. `bv-secrets gen {a.name}` puis `apply`.")


def cmd_adopt(a, e):
    """Onboard an app: detect a file's secrets, declare + import."""
    path = Path(a.file).resolve()
    if not path.is_file():
        raise ConfigError(f"fichier introuvable: {path}")
    proposals, ignored, conflicts = adopt.plan_envfile(path, prefix=a.prefix, known=set(e.cfg))
    if a.only:
        wanted = {k.strip() for k in a.only.split(",")}
        proposals = [p for p in proposals if p.key in wanted]

    print(f"Depuis {path} — {len(proposals)} secret(s) détecté(s) :")
    for p in proposals:
        print(f"  + {p.name:34} {p.kind:9} {p.group:7} <- {p.key} ({len(p.value)} c)")
    if ignored:
        print(f"  · ignorés (config) : {', '.join(ignored)}")
    if conflicts:
        print(f"  ⚠ noms déjà pris (utiliser --prefix) : {', '.join(conflicts)}")
    if not proposals:
        print("rien à adopter.")
        return
    if not a.yes:
        print("\nRelancer avec --yes pour déclarer ces secrets et importer leurs valeurs.")
        return

    blocks = [conffile.render_section(
        p.name, p.kind, p.group, [adopt.sink_for(path, p.key)],
        note=f"adopté depuis {path.name}") for p in proposals]
    conffile.append_sections(blocks)
    reloaded = Engine()                       # reload with the new sections
    for p in proposals:
        reloaded.import_one(p.name, source=adopt.sink_for(path, p.key), log=_log)
    print(f"\n✓ {len(proposals)} secret(s) adopté(s). `bv-secrets status` pour vérifier.")


def cmd_doctor(a, e):
    names = e.select(a.only) if a.only else sorted(e.cfg)
    return 1 if e.doctor(names, _log) else 0


def cmd_seal(a, e):
    e.seal()


def cmd_open(a, e):
    r = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                        "-pass", f"file:{KEYFILE}", "-in", str(MIRROR)], capture_output=True)
    if r.returncode:
        raise ConfigError(r.stderr.decode())
    sys.stdout.write(r.stdout.decode())


def cmd_leaks(a, e):
    """Scan the repo for managed values sitting in cleartext elsewhere."""
    values = {k: v for k, v in e.data.items() if len(v) >= 6}
    hits = []
    for path in COMPOSE_DIR.rglob("*"):
        if not path.is_file() or RENDER_DIR in path.parents or path.parent == SECRETS_DIR:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        hits += [f"LEAK  {path}  contient la valeur de {k}" for k, v in values.items() if v in text]
    return _report(hits, "\nClean — aucune valeur gérée trouvée en clair ailleurs.")


def cmd_audit(a, e):
    """Unified timeline: who reached what, when, from where, and what changed.
    Reads existing logs with privileges the account already has (docker + wheel)."""
    sources = audit.ALL_SOURCES if a.source == "all" else (a.source,)
    since = audit.parse_since(a.since)
    events = audit.collect(sources, since)
    rows = audit.timeline(events, service=a.service, ip=a.ip, user=a.user,
                          denied=a.denied, limit=a.limit)
    if a.json:
        print(json.dumps(rows, ensure_ascii=False))
        return 0
    if not rows:
        print("aucun événement.")
        return 0
    aw = min(max(len(r["actor"]) for r in rows), 24)
    tw = min(max(len(r["target"]) for r in rows), 18)
    day = None
    for ev in rows:
        dt = datetime.datetime.fromtimestamp(ev["ts"])
        if dt.strftime("%d/%m/%Y") != day:
            day = dt.strftime("%d/%m/%Y")
            print(f"\n{ui.heading(day)}")
        actor = ev["actor"][:aw].ljust(aw)
        target = ev["target"][:tw].ljust(tw)
        print(f"  {ui.paint(dt.strftime('%H:%M'), ui.DIM)}  {ui.outcome(ev['outcome'])}  "
              f"{ui.paint(ev['source'][:7].ljust(7), ui.DIM)}  "
              f"{actor}  {ui.paint(target, ui.CYAN)}  {ev['detail']}")
    print(ui.paint(f"\n{len(rows)} événement(s).", ui.DIM))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(
        prog="bv-secrets", description="gestionnaire de secrets et de rotation côté serveur")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, help_, func, *args):
        sp = sub.add_parser(name, help=help_)
        for flags, kwargs in args:
            sp.add_argument(*flags, **kwargs)
        sp.set_defaults(func=func)
        return sp

    only = (("--only",), {})
    yes = (("--yes",), {"action": "store_true"})

    add("list", "secrets, formats, groupes, services cibles (aucune valeur)", cmd_list)
    add("check", "cohérence de la config, valeurs présentes, permissions", cmd_check)
    add("verify-render", "vérifie que render() reproduit les rendered actuels", cmd_verify_render)
    add("render", "écrit rendered/<svc>.env depuis config + valeurs", cmd_render)
    add("plan", "montre ce que rotate ferait (dry-run)", cmd_plan, only)
    add("rotate", "régénère + applique partout (défaut : groupe auto)", cmd_rotate, only, yes)
    add("apply", "pousse les valeurs courantes vers les sinks (sans régénérer)", cmd_apply, only, yes)
    add("get", "imprime une valeur (scripting)", cmd_get, (("key",), {}))
    add("set", "écrit une valeur", cmd_set,
        (("key",), {}), (("value",), {}), (("--local",), {"action": "store_true"}))
    add("gen", "génère une valeur pour une clé", cmd_gen, (("key",), {}),
        (("--kind",), {"choices": sorted(GEN_KINDS), "default": "password"}),
        (("--length",), {"type": int, "default": 0}))
    add("add", "enregistre un nouveau secret + ses sinks dans secrets.conf", cmd_add,
        (("name",), {}), (("--kind",), {"default": "password"}),
        (("--group",), {"default": "auto"}), (("--length",), {"type": int, "default": 0}),
        (("--sink",), {"action": "append", "default": []}), (("--note",), {"default": ""}))
    add("import", "adopte des valeurs déjà en place (fichier/config) vers le store", cmd_import,
        (("name",), {"nargs": "?"}), (("--all",), {"action": "store_true"}),
        (("--source",), {}), (("--force",), {"action": "store_true"}))
    add("status", "compare le store aux valeurs en place, signale les dérives", cmd_status, only)
    add("scan", "liste les clés d'un fichier env pour aider à déclarer", cmd_scan,
        (("path",), {}))
    add("adopt", "onboarde une app : détecte les secrets d'un fichier, déclare + importe",
        cmd_adopt, (("file",), {}), (("--prefix",), {"default": ""}),
        (("--only",), {}), (("--yes",), {"action": "store_true"}))
    add("doctor", "vérifie que chaque valeur stockée MARCHE (probes réels)", cmd_doctor, only)
    add("seal", "chiffre le store -> store.enc", cmd_seal)
    add("open", "déchiffre store.enc sur stdout", cmd_open)
    add("audit", "timeline des accès : qui a atteint quoi, quand, d'où, ce qui a changé",
        cmd_audit,
        (("--source",), {"choices": ["all", "access", "trail", "host", "rotdate"], "default": "all"}),
        (("--service",), {"default": ""}), (("--ip",), {"default": ""}),
        (("--user",), {"default": ""}), (("--since",), {"default": "7d"}),
        (("--denied",), {"action": "store_true"}), (("--limit",), {"type": int, "default": 200}),
        (("--json",), {"action": "store_true"}))
    add("leaks", "cherche des valeurs gérées présentes en clair dans le repo", cmd_leaks)
    return ap


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "__complete":          # appel des scripts de complétion
        from . import complete
        complete.run(argv[1:])
        return
    args = build_parser().parse_args()
    try:
        sys.exit(args.func(args, Engine()) or 0)
    except (ConfigError, RotateAborted) as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
