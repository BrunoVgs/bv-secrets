"""CLI: thin wrapper around Engine. No value is printed outside `get` and `open`."""
import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

import secrets as pysecrets

from . import (adopt, audit, conf_yaml, conffile, elevation, host, hosts,
               remote, service, totp, ui, validate)
from .config import (CONF, COMPOSE_DIR, CONFIG_FILE, GEN_KINDS, LEAKS_MAX_BYTES, is_identifier, KEYFILE,
                     LOCAL, MASTER, MIRROR, PROJECT_DIR, RENDER_DIR, SECRETS_DIR,
                     OBJ_ORDER, is_yaml, looks_like_apikey, secret_object,
                     secret_rotation)
from .engine import ConfigError, Engine, RotateAborted
from .envfile import parse_env, write_env


# Coloration du flux moteur : le glyphe de tete porte le sens (etat d'un secret,
# succes, echec), les lignes de detail indentees passent en attenue.
_LINE_STYLE = {
    "✓": ui.GREEN, "=": ui.GREEN,
    "✗": ui.RED, "!": ui.RED,
    "~": ui.YELLOW,
    "+": ui.CYAN, "•": ui.CYAN,
    "-": ui.DIM, "·": ui.DIM, "?": ui.DIM,
}


def _log(msg=""):
    s = msg.lstrip()
    style = _LINE_STYLE.get(s[:1])
    if style and (len(s) == 1 or s[1] == " "):
        indent = msg[:len(msg) - len(s)]
        print(f"{indent}{ui.paint(s[:1], style)}{s[1:]}")
    elif msg.startswith("    ") and s:
        print(ui.paint(msg, ui.DIM))
    else:
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

    def row(n):
        c = e.cfg[n]
        value = e.value_of(n)
        present = (f"{len(value)}c", ui.GREEN) if value else ("--", ui.RED)
        # La rotation est un axe a part entiere : sa colonne porte sa couleur,
        # elle n'est pas repetee dans le titre du bloc.
        label, style = ui.rotation_tag(secret_rotation(c["kind"], c["group"], n))
        return [n, (c["kind"], ui.DIM), (label, style), present,
                (meta.get(n, ""), ui.DIM),
                (", ".join(svc_of.get(n, ["(no-env)"])), ui.CYAN)]

    headers = ["SECRET", "KIND", "ROTATION", "VAL", "LAST SET", "SERVICES"]
    if a.flat:
        print(ui.table([row(n) for n in sorted(e.cfg)], headers=headers))
        return
    # Un bloc par OBJET : mes mots de passe d'un cote, les cles des apps tierces
    # de l'autre. C'est la seule question a laquelle un coup d'oeil doit repondre.
    by_obj = {}
    for n in sorted(e.cfg):
        by_obj.setdefault(secret_object(e.cfg[n]["kind"], n), []).append(n)
    first = True
    for obj in OBJ_ORDER:
        names = by_obj.get(obj)
        if not names:
            continue
        print(("" if first else "\n") + ui.section(obj))
        first = False
        print(ui.table([row(n) for n in names], headers=headers))


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
    e.apply(e.select_apply(a.only), a.yes, _log)


TOTP_SEED = "SECRETS_DASHBOARD_TOTP"
TOTP_RECOVERY = "SECRETS_DASHBOARD_RECOVERY"


def _totp_declare(e):
    """Declare les deux secrets s'ils manquent. Le seed est `kind: totp`, donc
    hors GEN_KINDS : aucun `rotate` nu ne peut le regenerer et desynchroniser le
    jeton."""
    missing = []
    if TOTP_SEED not in e.cfg:
        missing.append(conffile.render_section(
            TOTP_SEED, "totp", "manual", [f"env:bv-secrets-web#BV_DASH_TOTP"],
            note="seed TOTP du dashboard - regenere UNIQUEMENT par `bv-secrets totp --enrol`"))
    if TOTP_RECOVERY not in e.cfg:
        missing.append(conffile.render_section(
            TOTP_RECOVERY, "opaque", "manual",
            [f"env:bv-secrets-web#BV_DASH_RECOVERY"],
            note="empreintes scrypt des codes de secours, separees par des virgules"))
    if missing:
        conffile.append_sections(missing)
        print(f"{len(missing)} section(s) ajoutée(s) à {CONF}")


def cmd_totp(a, e):
    """Etat de l'enrolement, ou nouvel enrolement avec `--enrol`."""
    seed = e.data.get(TOTP_SEED, "")
    hashes = [h for h in (e.data.get(TOTP_RECOVERY, "") or "").split(",") if h]

    if not a.enrol:
        if not seed:
            print("TOTP non enrôlé. `bv-secrets totp --enrol` pour commencer.")
            return 1
        print(f"TOTP enrôlé · période {totp.STEP}s · {totp.DIGITS} chiffres · "
              f"tolérance ±{totp.DRIFT * totp.STEP}s")
        print(f"codes de secours restants : {len(hashes)}")
        print(f"code attendu en ce moment : {totp.code(seed)}")
        return 0

    if seed and not a.yes:
        raise ConfigError(
            "un seed existe déjà. Le remplacer invalide le jeton enrôlé ET tous "
            "les codes de secours. Ajouter --yes pour le faire quand même.")

    new_seed = totp.new_seed()
    codes = totp.new_recovery_codes()
    _totp_declare(e)

    data = parse_env(MASTER)
    data[TOTP_SEED] = new_seed
    data[TOTP_RECOVERY] = ",".join(totp.hash_recovery(c) for c in codes)
    write_env(MASTER, data)
    Engine.touch_meta([TOTP_SEED, TOTP_RECOVERY])

    bar = "=" * 72
    print(f"\n{bar}\nÀ NOTER MAINTENANT — rien de tout ceci ne sera réaffiché.\n{bar}\n")
    print(f"  base32 (application / QR) : {new_seed}")
    print(f"  hex 20 octets (firmware)  : {totp.seed_hex(new_seed)}")
    print(f"  période / chiffres        : {totp.STEP}s / {totp.DIGITS}")
    print(f"  URI                       : {totp.uri(new_seed, 'bv', 'bv-secrets')}")
    print("\n  CODES DE SECOURS (usage unique) :")
    for i in range(0, len(codes), 2):
        print("     " + "   ".join(codes[i:i + 2]))
    print(f"\n{bar}")
    print("Les sortir de cette machine : c'est le seul chemin de retour si le")
    print("jeton est perdu. Le seed est en store ; les codes, eux, ne sont")
    print("gardés que hachés — personne ne peut les réafficher.")
    print(f"{bar}\n")
    print(f"Code attendu à l'instant : {totp.code(new_seed)}")
    print("\nEnsuite : `bv-secrets apply --only "
          f"{TOTP_SEED},{TOTP_RECOVERY} --yes` pour les pousser vers le dashboard.")
    return 0


def cmd_hosts(a, e):
    """Les instances joignables, et ce qui manque pour les joindre."""
    if a.key:
        value = a.key if a.key != "-" else pysecrets.token_urlsafe(32)
        path = hosts.write_key(a.name, value)
        print(f"clé de {a.name} écrite dans {path} (0600)")
        print("La même valeur doit être posée sur l'hôte distant, dans "
              "BV_WORKER_KEY ou <store>/hosts/self.key.")
        if a.key == "-":
            print(f"\n{value}\n")
        return
    if not hosts.names():
        print("Aucun hôte déclaré. Section [hosts] de bv-secrets.ini :\n"
              "\n    [hosts]\n    xeon = http://10.8.0.4:8765\n")
        return
    hosted = {}
    for n, c in e.cfg.items():
        if c.get("host"):
            hosted.setdefault(c["host"], []).append(n)
    print(f"{'HÔTE':12} {'URL':34} {'CLÉ':5} {'SECRETS':8} ÉTAT")
    for name in hosts.names():
        key = "oui" if hosts.key(name) else "NON"
        state = "(non testé, --test pour interroger)"
        if a.test:
            # Meme diagnostic que le dashboard : un seul endroit decide ce que
            # « joignable » veut dire.
            result = remote.probe(name)
            state = f"{result['state']} — {result['detail']}"
        print(f"{name:12} {hosts.url(name):34} {key:5} "
              f"{len(hosted.get(name, [])):<8} {state}")


def cmd_push(a, e):
    """Envoie la valeur courante d'un secret à l'instance qui l'héberge."""
    names = e.select_apply(a.only) if a.only else \
        [n for n, c in e.cfg.items() if c.get("host")]
    remote_names = [n for n in names if e.cfg[n].get("host")]
    if not remote_names:
        raise ConfigError("aucun secret hébergé à distance dans la sélection "
                          "(champ `host:` dans secrets.conf)")
    e._push_remote(remote_names, _log)
    print(f"✓ {len(remote_names)} secret(s) poussé(s).")


def cmd_get(a, e):
    if a.key not in e.cfg and a.key not in e.data:
        raise ConfigError(f"clé inconnue: {a.key}")
    sys.stdout.write(e.value_of(a.key))


def cmd_set(a, e):
    c = e.cfg.get(a.key)
    if c and c["validate"]:
        err = validate.check(c["validate"], a.value)
        if err:
            raise ConfigError(f"{a.key}: {err}")
    target = LOCAL if a.local else MASTER
    data = parse_env(target)
    data[a.key] = a.value
    write_env(target, data)
    Engine.touch_meta([a.key])
    print(f"set {a.key} dans {target.name} ; lancer `bv-secrets apply` pour propager.")


def cmd_run(a, e):
    """Exécute une commande avec les secrets en variables d'env, rien sur disque."""
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        raise ConfigError("commande manquante : bv-secrets run [--svc S] -- <cmd> ...")
    services = [s.strip() for s in a.svc.split(",") if s.strip()] if a.svc else None
    env = {**os.environ, **e.env_for(services)}
    return subprocess.run(cmd, env=env).returncode


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
        raise ConfigError("donner au moins un sink (env:svc#VAR, file:/p, "
                          "mysql:u@ctr, cmd:..., envfile:/p#K, json/yaml/ini/toml:/p#a.b.c)")
    conffile.append_sections(
        [conffile.render_section(a.name, a.kind, a.group, a.sink, a.length, a.note, a.validate)])
    print(f"ajouté [{a.name}] à {CONF.name}. `bv-secrets gen {a.name}` puis `apply`.")


def cmd_adopt(a, e):
    """Onboard an app: detect a file's secrets, declare + import."""
    path = Path(a.file).resolve()
    if not path.is_file():
        raise ConfigError(f"fichier introuvable: {path}")
    proposals, ignored, conflicts = adopt.plan_file(path, prefix=a.prefix, known=set(e.cfg))
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


def _sink_paths(engine) -> dict:
    """-> {NOM: {chemins que ses sinks ecrivent}}.

    Une valeur trouvee a l'endroit ou on l'a deliberement ecrite n'est pas une
    fuite, c'est le fonctionnement nominal. Sans ca, chaque sink fichier se
    signalait lui-meme a chaque scan et noyait les vraies trouvailles."""
    out = {}
    for name, c in engine.cfg.items():
        paths = set()
        for sink in c["sinks"]:
            scheme, _, rest = sink.partition(":")
            if scheme in ("env", "mysql", "cmd", ""):
                continue                      # rendu ailleurs, ou sans fichier
            target = rest.partition("#")[0].strip()
            if scheme == "sqlite":
                target = target.partition("@")[0]
            target = target.partition(":")[0]  # `file:/chemin:0600`
            if target.startswith("/"):
                paths.add(Path(target))
        out[name] = paths
    return out


def _leaks_tree(values):
    """Fouille la racine compose. Elle heberge aussi les DONNEES des services --
    ROMs, enregistrements, bases -- et les decoder en entier pour y chercher une
    chaine ne rendait jamais la main. Au-dela de LEAKS_MAX_BYTES ce n'est plus une
    configuration, et un fichier binaire ne porte pas une valeur « en clair » au
    sens ou on la chercherait ici. Les octets sont compares tels quels : aucun
    decodage, donc aucun cout de conversion."""
    needles = {k: v.encode() for k, v in values.items()}
    own = _sink_paths(Engine())
    hits, skipped = [], 0
    for path in COMPOSE_DIR.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        if RENDER_DIR in path.parents or path.parent == SECRETS_DIR:
            continue
        # Les entrailles de git ne sont pas « l'arbre » : objets, index et URL de
        # remote s'y retrouvent sans que personne ne les ait ecrits.
        if ".git" in path.parts:
            continue
        try:
            if path.stat().st_size > LEAKS_MAX_BYTES:
                skipped += 1
                continue
            blob = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in blob:
            continue
        hits += [f"LEAK  {path}  contient la valeur de {k}"
                 for k, v in needles.items()
                 if v in blob and path not in own.get(k, ())]
    return hits, skipped


def _leaks_staged(values):
    """Scanne le contenu STAGÉ (index git), pas l'arbre : ce qui part au commit."""
    listing = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                             capture_output=True, text=True)
    hits = []
    for f in listing.stdout.split("\n"):
        if not f:
            continue
        blob = subprocess.run(["git", "show", f":{f}"], capture_output=True, text=True)
        if blob.returncode:
            continue
        hits += [f"LEAK  {f}  contient la valeur de {k}" for k, v in values.items() if v in blob.stdout]
    return hits


def cmd_leaks(a, e):
    """Cherche des valeurs gérées présentes en clair : dans l'arbre, ou --staged
    dans l'index git (pour un hook pre-commit)."""
    values = {k: v for k, v in e.data.items()
              if len(v) >= 6 and not is_identifier(k)}
    if a.staged:
        hits, skipped = _leaks_staged(values), 0
    else:
        hits, skipped = _leaks_tree(values)
    if skipped:
        # Dire ce qui n'a pas ete regarde : un scan muet sur sa propre couverture
        # se lit comme une garantie qu'il ne donne pas. Mais ce n'est pas une
        # trouvaille : le compter ferait echouer un hook pre-commit a chaque fois.
        print(f"({skipped} fichier(s) > {LEAKS_MAX_BYTES} o non lus — "
              f"BV_LEAKS_MAX_BYTES pour élargir)")
    return _report(hits, "\nClean — aucune valeur gérée trouvée en clair.")


HEADER_YAML = """\
# =============================================================================
# bv-secrets -- SOURCE DECLARATIVE (structure uniquement, AUCUNE valeur secrete).
# Versionnable. Les valeurs vivent dans le store, jamais ici.
#
# Deux axes independants :
#   kind   ce que la valeur EST      password|hex|b64|userpass|passphrase|apikey|opaque|computed
#   group  QUAND on la regenere      auto (rotate nu) | app (seulement si ciblee) | manual (jamais)
#          Optionnel : deduit du kind s'il est absent -- auto si generable, manual sinon.
#
# Un sink dit ou pousser la valeur :  schema:cible#selecteur
#   env:pihole#FTLCONF_...      variable du .env d'un service compose
#   envfile:/chemin/.env#CLE    fichier adopte, ecrit en place, ligne par ligne
#   file:/chemin                fichier dedie
#   sqlite:/b.db@ctr#t.col?id=1 une cellule ; la condition doit viser UNE ligne
#   cmd:...                     commande, {value} interpole
#
# Les gabarits `x-` se reprennent avec `<<: *nom` ; ce qui est pose en propre
# dans un secret gagne sur le gabarit.
# =============================================================================
"""


def cmd_host(a, e):
    """La posture declaree par les cles `egress:` et `audit:` du fichier.

    Rien n'est applique en douce : les regles sont rendues dans le store, que le
    compte possede deja, et les commandes qui demandent root sont imprimees."""
    if not is_yaml():
        raise ConfigError(
            "les cles `egress:` et `audit:` demandent le format declaratif.\n"
            "    bv-secrets migrate-conf --in-place --yes")
    doc = conf_yaml.parse(CONF.read_text(encoding="utf-8"))
    spec = doc.get("host") or {}
    if not spec:
        _log("Aucune cle `egress:` ni `audit:` declaree. Exemple :\n")
        print(host.EXAMPLE)
        return 0

    p = host.plan(spec)
    rc = 0

    if p["rules"]:
        print(ui.paint("-- audit : trace des elevations", ui.BOLD))
        for w in p["warnings"]:
            _log(f"! {w}")
        state, msg = host.diff(p)
        _log({"ok": f"✓ {msg}", "unknown": f"? {msg}"}.get(state, f"~ {msg}"))
        rc = {"ok": 0, "unknown": 2}.get(state, 1)
        if a.show:
            print(ui.paint(p["rules"], ui.DIM))
        if a.write or state != "ok":
            staged = host.write(p)
            _log(f"+ rendu dans {staged}")
            if state != "ok":
                _log("\n  Les poser demande root une fois :")
                priv = host.privilege_tool()
                _log(f"    {priv} install -m 640 {staged} {p['rules_target']}")
                _log(f"    {priv} augenrules --load")

    if p["egress"]:
        print("\n" + ui.paint("-- egress : cloisonnement des conteneurs", ui.BOLD))
        for z in p["egress"]:
            _log(f"• {z['zone']}: {z['subnet']} ne doit joindre "
                 f"ni {', '.join(z['block'])}")
            _log(f"    {z['cmd']}")
    return rc


cmd_host.no_engine = True


def cmd_migrate_conf(a, e):
    """secrets.conf (INI) -> secrets.yaml. Rien n'est remplace tant que la
    relecture du YAML ne redonne pas exactement la config d'origine."""
    from . import migrate
    if is_yaml():
        _log(f"{CONF.name} est deja au format declaratif, rien a faire.")
        return 0
    # Par defaut on ecrit DANS le fichier existant : le dashboard le bind-monte
    # par son nom et son image fige BV_SECRETS_CONF, donc renommer casserait les
    # deux. Le format se reconnait au contenu, l'extension n'a plus d'importance.
    target = CONF if a.in_place else CONF.with_name("secrets.yaml")
    if target != CONF and target.exists() and not a.force:
        _log(f"{target} existe deja ; --force pour l'ecraser.")
        return 1

    text = migrate.convert(e.cfg, HEADER_YAML)       # leve si la conversion perd quoi que ce soit
    tpl = migrate.plan_templates(e.cfg)
    _log(f"{len(e.cfg)} secrets, {len(tpl)} gabarit(s), {len(text.splitlines())} lignes.")
    _log(f"Relecture verifiee : identique a {CONF.name}, champ par champ.\n")
    if not a.yes:
        print(text if a.show else "\n".join(text.splitlines()[:24]))
        _log(f"\n--yes pour ecrire {target} (l'INI est conserve), --show pour tout voir.")
        return 0

    if target == CONF:
        backup = CONF.with_name(CONF.name + ".ini.bak")
        backup.write_text(CONF.read_text(encoding="utf-8"), encoding="utf-8")
        backup.chmod(0o600)
        conffile.write_text(text)            # sur place, inode conserve
        _log(f"✓ {CONF.name} est maintenant declaratif (inode conserve, "
             f"montages intacts).\n  L'INI d'origine est dans {backup.name}.")
    else:
        target.write_text(text, encoding="utf-8")
        target.chmod(0o600)
        _log(f"✓ {target} ecrit. {CONF.name} est conserve ; le YAML gagne des "
             f"qu'il existe.")
    return 0


cmd_migrate_conf.no_engine = False


def cmd_init(a, e):
    """Première installation, en une commande : le store, la config de départ, et
    l'unité du worker pour l'init détecté. Chaque étape est idempotente, et c'est
    le seul endroit qui peut demander root — jamais sans afficher la commande ni
    hors TTY."""
    if a.unit:                                  # inspection : l'unité, rien d'autre
        sys.stdout.write(service.unit_text(a.unit))
        return 0

    user, group = service.account()
    init = service.detect_init()
    _log(f"compte  : {user}:{group}\nprojet  : {PROJECT_DIR}\npython  : {sys.executable}\n"
         f"init    : {init or 'non détecté'}\n")

    store = Path(a.dir).expanduser() if a.dir else SECRETS_DIR
    if service.create_store(store, _log) != 0:
        return 1
    if a.dir and store != SECRETS_DIR:
        service.pin_secrets_dir(store)
        _log(f"✓ secrets_dir = {store} écrit dans {CONFIG_FILE.name}")
    if service.create_conf(CONF, _log) != 0:
        return 1

    if a.no_service:
        _log("· worker : ignoré (--no-service)")
    elif not init:
        _log("· worker : ni systemd ni OpenRC détecté, le lancer à la main :\n"
             f"    {sys.executable} -u -m bvsecrets.worker.loop")
    else:
        service.install_unit(init, a.yes, _log)  # sans root : affiche, n'échoue pas

    _log(f"\nPrêt. Déclarer tes secrets dans {CONF}, puis `bv-secrets list`.")
    return 0


cmd_init.no_engine = True                 # tourne avant qu'il y ait une config


def cmd_elevation(a, e):
    """Elevation trail: auditd names who became root, the shell history says what
    surrounded it. Needs no config and no privilege of its own."""
    if a.rules:
        print(elevation.render_rules(), end="")
        return 0
    blind = elevation.source_error()
    if blind:
        print(f"trace d'elevation indisponible.\n{blind}", file=sys.stderr)
        return 1
    try:
        rows = elevation.elevations(audit.parse_since(a.since), window=a.window,
                                    context=a.context)
    except elevation.AtuinUnavailable as exc:
        print(f"contexte indisponible.\n    {exc}", file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps(rows, ensure_ascii=False))
        return 0
    print(elevation.render(rows, f" depuis {a.since}"))
    return 0
cmd_elevation.no_engine = True            # lisible sans store ni secrets.conf


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


_FAMILIES = [
    ("mise en place", ["init"]),
    ("inventaire & santé", ["list", "status", "check", "doctor", "audit", "elevation", "leaks"]),
    ("rotation & application", ["plan", "rotate", "apply", "render", "verify-render"]),
    ("valeurs", ["get", "set", "gen", "add", "run"]),
    ("adoption", ["scan", "import", "adopt"]),
    ("store chiffré", ["seal", "open"]),
    ("instances distantes", ["hosts", "push"]),
    ("second facteur", ["totp"]),
]

_EXAMPLES = [
    ("bv-secrets status", "store vs déployé : synchro / dérive / non déployé"),
    ("bv-secrets rotate --only APP_SECRET --yes", "régénère un secret et le propage"),
    ("bv-secrets adopt /srv/app/.env --prefix APP_", "onboarde les secrets d'une app"),
    ("bv-secrets audit --since 24h --denied", "accès refusés des dernières 24h"),
    ("bv-secrets hosts --test", "instances distantes : joignables ? clé bonne ?"),
    ("bv-secrets push --only QB_PASSWORD", "envoie une valeur à l'instance qui l'héberge"),
]


def _epilog(helps):
    width = max(len(n) for n in helps) + 2
    out = [ui.heading("Commandes")]
    for title, names in _FAMILIES:
        out.append("  " + ui.paint(title, ui.BOLD))
        out += [f"    {n.ljust(width)}{ui.paint(helps[n], ui.DIM)}" for n in names]
    out += ["", ui.heading("Exemples")]
    for cmd, what in _EXAMPLES:
        out.append(f"  {ui.paint(cmd, ui.CYAN)}\n      {ui.paint(what, ui.DIM)}")
    out += ["", ui.paint("Détail d'une commande : bv-secrets <commande> -h   ·   "
                         "complétion : source completions/bv-secrets.bash", ui.DIM)]
    return "\n".join(out)


def build_parser():
    ap = argparse.ArgumentParser(
        prog="bv-secrets", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Gestionnaire de secrets et de rotation, côté serveur. Zéro dépendance.")
    sub = ap.add_subparsers(dest="cmd", metavar="<commande>")
    helps = {}

    def add(name, help_, func, *args):
        helps[name] = help_
        sp = sub.add_parser(name, description=help_)      # help_ visible via `<cmd> -h`
        for flags, kwargs in args:
            sp.add_argument(*flags, **kwargs)
        sp.set_defaults(func=func)
        return sp

    only = (("--only",), {})
    yes = (("--yes",), {"action": "store_true"})

    add("host", "posture de la machine declaree par `egress:` et `audit:`", cmd_host,
        (("--write",), {"action": "store_true", "help": "rendre les fichiers dans le store"}),
        (("--show",), {"action": "store_true", "help": "afficher les regles rendues"}))
    add("migrate-conf", "convertit secrets.conf (INI) en secrets.yaml declaratif",
        cmd_migrate_conf, yes,
        (("--force",), {"action": "store_true", "help": "ecraser un secrets.yaml existant"}),
        (("--show",), {"action": "store_true", "help": "afficher tout le rendu"}),
        (("--in-place",), {"action": "store_true",
                           "help": "reecrire le fichier actuel au lieu d'en creer un"}))
    add("init", "première installation : store, config de départ, service du worker",
        cmd_init,
        (("--dir",), {"default": "", "help": "autre emplacement du store, épinglé "
                      "dans bv-secrets.ini (aucun root nécessaire)"}),
        (("--no-service",), {"action": "store_true",
                             "help": "ne pas toucher à l'init système"}),
        (("--unit",), {"choices": ["systemd", "openrc"], "default": "",
                       "help": "imprimer l'unité sur stdout et sortir"}), yes)
    add("list", "secrets groupes par famille : mots de passe d'un cote, cles API de l'autre",
        cmd_list, (("--flat",), {"action": "store_true"}))
    add("check", "cohérence de la config, valeurs présentes, permissions", cmd_check)
    add("verify-render", "vérifie que render() reproduit les rendered actuels", cmd_verify_render)
    add("render", "écrit rendered/<svc>.env depuis config + valeurs", cmd_render)
    add("plan", "montre ce que rotate ferait (dry-run)", cmd_plan, only)
    add("rotate", "régénère + applique partout (défaut : groupe auto)", cmd_rotate, only, yes)
    add("apply", "pousse les valeurs courantes vers les sinks (sans régénérer)", cmd_apply, only, yes)
    add("totp", "état de l'enrôlement TOTP du dashboard, ou nouvel enrôlement",
        cmd_totp, (("--enrol",), {"action": "store_true"}), yes)
    add("hosts", "instances bv-secrets distantes : URL, clé, état", cmd_hosts,
        (("name",), {"nargs": "?", "default": ""}),
        (("--test",), {"action": "store_true", "help": "interroger chaque hôte"}),
        (("--key",), {"default": "", "help": "poser la clé partagée d'un hôte "
                                             "(`-` pour en générer une)"}))
    add("push", "envoie la valeur courante d'un secret à l'instance qui l'héberge",
        cmd_push, only)
    add("get", "imprime une valeur (scripting)", cmd_get, (("key",), {}))
    add("set", "écrit une valeur", cmd_set,
        (("key",), {}), (("value",), {}), (("--local",), {"action": "store_true"}))
    add("gen", "génère une valeur pour une clé", cmd_gen, (("key",), {}),
        (("--kind",), {"choices": sorted(GEN_KINDS), "default": "password"}),
        (("--length",), {"type": int, "default": 0}))
    add("run", "exécute une commande avec les secrets en variables d'env (rien sur disque)",
        cmd_run, (("--svc",), {"default": ""}), (("cmd",), {"nargs": argparse.REMAINDER}))
    add("add", "enregistre un nouveau secret + ses sinks dans secrets.conf", cmd_add,
        (("name",), {}), (("--kind",), {"default": "password"}),
        (("--group",), {"default": "auto"}), (("--length",), {"type": int, "default": 0}),
        (("--sink",), {"action": "append", "default": []}), (("--note",), {"default": ""}),
        (("--validate",), {"default": ""}))
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
    add("elevation", "qui est passé root, quand, via quoi, et ce qu'il faisait autour",
        cmd_elevation,
        (("--since",), {"default": "24h"}),
        (("--window",), {"type": int, "default": None}),
        (("--context",), {"choices": sorted(elevation.CONTEXT_PROVIDERS), "default": None}),
        (("--rules",), {"action": "store_true"}),
        (("--json",), {"action": "store_true"}))
    add("leaks", "cherche des valeurs gérées présentes en clair dans le repo", cmd_leaks,
        (("--staged",), {"action": "store_true"}))
    ap.epilog = _epilog(helps)
    return ap


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "__complete":          # appel des scripts de complétion
        from . import complete
        complete.run(argv[1:])
        return
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):        # aucune commande : aide au lieu d'une erreur
        parser.print_help()
        return
    try:
        # Setup commands run before there is a store or a secrets.conf to load.
        engine = None if getattr(args.func, "no_engine", False) else Engine()
        sys.exit(args.func(args, engine) or 0)
    except (ConfigError, RotateAborted) as e:
        sys.exit(str(e))
    except BrokenPipeError:
        # `bv-secrets init --unit openrc | tee ...` or `| head`: the reader closed
        # first. Nothing failed, so exit quietly instead of dumping a traceback.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)


if __name__ == "__main__":
    main()
