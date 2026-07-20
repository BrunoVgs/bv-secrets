"""Interface en ligne de commande — enveloppe mince autour d'Engine.

Aucune valeur n'est imprimée en dehors des commandes explicites `get` et `open`.
"""
import argparse
import subprocess
import sys
from pathlib import Path

from . import adopt, conffile
from .config import (CONF, COMPOSE_DIR, GEN_KINDS, KEYFILE, LOCAL, MASTER, MIRROR,
                     RENDER_DIR, SECRETS_DIR, looks_like_apikey)
from .engine import ConfigError, Engine, RotateAborted
from .envfile import parse_env, write_env


def _log(msg=""):
    print(msg)


def _report(problems, clean_msg):
    for p in problems:
        print(p)
    print(clean_msg if not problems else f"\n{len(problems)} problème(s).")
    return 1 if problems else 0


def cmd_list(a, e):
    svc_of = {}
    for name, c in e.cfg.items():
        for s in c["sinks"]:
            if s.startswith("env:"):
                svc_of.setdefault(name, []).append(s[4:].split("#", 1)[0])
    meta = e.meta()
    for n in sorted(e.cfg):
        c = e.cfg[n]
        value = e.value_of(n)
        present = f"{len(value):>3}c" if value else " -- "
        print(f"{n:34} {c['kind']:9} {c['group']:8} [{present}] {meta.get(n, ''):17} "
              f"-> {','.join(svc_of.get(n, ['(no-env)']))}")


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
    """Adopte des valeurs déjà en place : les lit là où elles vivent -> store."""
    if a.all:
        e.import_all(_log)
    elif a.name:
        e.import_one(a.name, source=a.source, force=a.force, log=_log)
    else:
        raise ConfigError("préciser un NOM, ou --all")


def cmd_status(a, e):
    """Compare le store aux valeurs en place et signale les dérives."""
    names = e.select(a.only) if a.only else sorted(e.cfg)
    return 1 if e.status(names, _log) else 0


def cmd_scan(a, e):
    """Liste les clés d'un fichier env pour aider à déclarer les secrets."""
    e.scan(a.path, _log)


def cmd_add(a, e):
    """Ajoute une section de secret à secrets.conf en une commande."""
    if not a.sink:
        raise ConfigError("donner au moins un sink "
                          "(env:svc#VAR, file:/p, linux:user, mysql:u@ctr, cmd:...)")
    conffile.append_sections(
        [conffile.render_section(a.name, a.kind, a.group, a.sink, a.length, a.note)])
    print(f"ajouté [{a.name}] à {CONF.name}. `bv-secrets gen {a.name}` puis `apply`.")


def cmd_adopt(a, e):
    """Onboarde une app : détecte les secrets d'un fichier, déclare + importe."""
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
    reloaded = Engine()                       # relit avec les nouvelles sections
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


def cmd_audit(a, e):
    """Cherche les valeurs gérées présentes en clair ailleurs dans le repo."""
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
    add("audit", "cherche des valeurs en clair dans le repo", cmd_audit)
    return ap


def main():
    args = build_parser().parse_args()
    try:
        sys.exit(args.func(args, Engine()) or 0)
    except (ConfigError, RotateAborted) as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
