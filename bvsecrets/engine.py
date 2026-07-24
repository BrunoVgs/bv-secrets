"""bv-secrets engine: resolution, render, rotation, apply.

One brain for three faces: CLI, worker and web import this class and call the same
methods. No value is ever logged; `log` callbacks get names and targets, never a
secret.
"""
import base64
import configparser
import os
import secrets as pysecrets
import string
import subprocess
from pathlib import Path

from . import locations
from .config import (ALL_KINDS, COMPOSE_DIR, CONF, DEFAULT_LEN, GEN_KINDS, KEYFILE,
                     LOCAL, MASTER, META, MIRROR, REF, RENDER_DIR)
from .envfile import parse_env, write_env


class ConfigError(RuntimeError):
    """Missing or inconsistent config; raised to the caller instead of sys.exit so
    the worker can turn it into a job result."""


class RotateAborted(RuntimeError):
    """A sink failed; already-applied sinks were rolled back and the store is
    untouched."""


class Engine:
    def __init__(self):
        self.cfg = self._load_conf()
        self.data = self._combined()

    # ---- config + values ----
    @staticmethod
    def _load_conf() -> dict:
        cp = configparser.ConfigParser(interpolation=None)
        cp.optionxform = str
        if not CONF.exists():
            raise ConfigError(
                f"config introuvable: {CONF}\n"
                f"Partir du modèle : cp secrets.conf.example secrets.conf")
        cp.read(CONF)
        out = {}
        for name in cp.sections():
            s = cp[name]
            out[name] = {
                "kind": s.get("kind", "manual").strip(),
                "length": int((s.get("length", "") or "0").strip() or 0),
                "group": s.get("group", "manual").strip(),
                "sinks": [x.strip() for x in s.get("sinks", "").splitlines() if x.strip()],
                "norestart": [x.strip() for x in s.get("norestart", "").splitlines() if x.strip()],
                "compute": s.get("compute", "").strip(),
                "probe": s.get("probe", "").strip(),
                "note": s.get("note", "").strip(),
            }
        return out

    @staticmethod
    def _combined() -> dict:
        data = parse_env(MASTER)
        data.update(parse_env(LOCAL))
        return data

    def value_of(self, name: str, data: dict = None) -> str:
        """Effective value of a secret; `computed` ones derive from others."""
        data = self.data if data is None else data
        c = self.cfg.get(name)
        if c and c["kind"] == "computed" and c["compute"]:
            transform, _, tpl = c["compute"].partition(" ")
            interp = REF.sub(lambda m: self.value_of(m.group(1), data), tpl)
            if transform == "basicauth":
                return "Basic " + base64.b64encode(interp.encode()).decode()
            return interp
        return data.get(name, "")

    # ---- generation ----
    @staticmethod
    def gen(kind: str, length: int) -> str:
        length = length or DEFAULT_LEN.get(kind, 24)
        alpha = string.ascii_letters + string.digits
        if kind == "hex":
            return pysecrets.token_hex(max(1, length // 2))
        if kind == "b64":
            return pysecrets.token_urlsafe(length)
        if kind == "userpass":
            return "bv:" + "".join(pysecrets.choice(alpha) for _ in range(length))
        return "".join(pysecrets.choice(alpha) for _ in range(length))

    # ---- render env sinks -> rendered/<svc>.env ----
    def service_map(self, data: dict = None) -> dict:
        data = self.data if data is None else data
        services = {}
        for name, c in self.cfg.items():
            for sink in c["sinks"]:
                if sink.startswith("env:"):
                    svc, _, var = sink[4:].partition("#")
                    services.setdefault(svc, {})[var] = self.value_of(name, data)
        return services

    def render(self, data: dict = None) -> dict:
        services = self.service_map(data)
        RENDER_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(RENDER_DIR, 0o700)
        for svc, kv in services.items():
            write_env(RENDER_DIR / f"{svc}.env", kv,
                      header=f"RENDERED for '{svc}' by bv-secrets — do not edit; "
                             f"change secrets.conf / bv-secrets.env then re-render.")
        return services

    # ---- appliers ----
    def _run(self, argv, inp=None, cwd=None):
        return subprocess.run(argv, input=inp, capture_output=True, cwd=cwd)

    def _apply_sink(self, sink: str, value: str, eff: dict, dry: bool, log) -> bool:
        typ, _, arg = sink.partition(":")
        if typ == "env":
            return True                      # materialized by render()
        if dry:
            log(f"    would apply {typ}: {arg[:60]}")
            return True
        if typ == "file":
            path, _, mode = arg.partition(":")
            p = Path(path)
            p.write_text(value)
            os.chmod(p, int(mode, 8) if mode else 0o600)
            return True
        if typ == "linux":
            user, _, host = arg.partition("@")
            if host:
                log(f"    remote linux sink refused (local-only): {arg}")
                return False
            # doas prompts for elevation on the TTY: interactive CLI only
            return self._run(["doas", "chpasswd"], inp=f"{user}:{value}\n".encode()).returncode == 0
        if typ == "mysql":
            return self._apply_mysql(arg, value, eff)
        if typ == "cmd":
            return self._apply_cmd(arg, value, eff)
        if typ in locations.writable_schemes():
            try:
                locations.write_location(sink, value)
                return True
            except locations.LocationError as e:
                log(f"    {e}")
                return False
        log(f"    type de sink inconnu: {sink}")
        return False

    def _apply_mysql(self, arg: str, value: str, eff: dict) -> bool:
        dbuser, _, ctr = arg.partition("@")
        rootpw = eff.get("MARIADB_ROOT_PASSWORD", "")

        def alter(host):
            sql = (f"ALTER USER IF EXISTS '{dbuser}'@'{host}' IDENTIFIED BY '{value}'; "
                   f"FLUSH PRIVILEGES;\n")
            return self._run(["docker", "exec", "-i", "-e", f"MYSQL_PWD={rootpw}",
                              ctr, "mariadb", "-u", "root"], inp=sql.encode())

        r = alter("localhost" if dbuser == "root" else "%")
        if r.returncode != 0 and dbuser == "root":
            r = alter("%")               # root may only exist as 'root'@'%'
        return r.returncode == 0

    def _apply_cmd(self, arg: str, value: str, eff: dict) -> bool:
        # {value} kept literal then substituted: REF would otherwise resolve it to
        # "" since no secret bears that name.
        def sub(m):
            return m.group(0) if m.group(1) == "value" else self.value_of(m.group(1), eff)
        cmd = REF.sub(sub, arg).replace("{value}", value)
        return self._run(["sh", "-c", cmd]).returncode == 0

    def _verify_sink(self, sink: str, value: str, eff: dict) -> bool:
        typ, _, arg = sink.partition(":")
        if typ == "mysql":
            dbuser, _, ctr = arg.partition("@")
            return self._run(["docker", "exec", "-i", "-e", f"MYSQL_PWD={value}",
                              ctr, "mariadb", "-u", dbuser, "-e", "SELECT 1"]).returncode == 0
        return True                      # env/file/linux/cmd: no non-destructive check

    # ---- container recreation ----
    def affected_computed(self, names) -> list:
        return [cn for cn, c in self.cfg.items()
                if c["kind"] == "computed" and any(r in names for r in REF.findall(c["compute"]))]

    def services_to_recreate(self, names) -> list:
        """Services whose container must be recreated after apply.

        DERIVED from sinks, never declared by hand: an `env:<svc>#VAR` sink writes
        rendered/<svc>.env, which a container only re-reads at creation. `computed`
        secrets referencing a rotated one count too. `norestart` excludes services
        that read the var only at init (mariadb: the real password is set by mysql:).
        """
        svcs, skip = [], set()
        for n in list(names) + self.affected_computed(names):
            c = self.cfg.get(n, {})
            skip |= set(c.get("norestart", []))
            for sink in c.get("sinks", []):
                if sink.startswith("env:"):
                    svc = sink[4:].partition("#")[0]
                    if svc not in svcs:
                        svcs.append(svc)
        return [s for s in svcs if s not in skip]

    def recreate(self, names, dry: bool, log):
        for svc in self.services_to_recreate(names):
            if dry:
                log(f"    would recreate {svc}")
                continue
            # --force-recreate: a `restart` reuses the container and doesn't re-read
            # env_file, so the new value would never be picked up.
            self._run(["docker", "compose", "up", "-d", "--force-recreate", svc], cwd=COMPOSE_DIR)
            log(f"    recreate {svc}  ✓")

    # ---- encrypted mirror ----
    def seal(self, quiet=False):
        if not KEYFILE.exists():
            KEYFILE.write_bytes(pysecrets.token_bytes(32))
            os.chmod(KEYFILE, 0o600)
        payload = ("# bv-secrets encrypted mirror\n" + MASTER.read_text()
                   + "\n### .local ###\n" + (LOCAL.read_text() if LOCAL.exists() else "")).encode()
        r = self._run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt",
                       "-pass", f"file:{KEYFILE}", "-out", str(MIRROR)], inp=payload)
        if r.returncode:
            raise RuntimeError(r.stderr.decode())
        os.chmod(MIRROR, 0o600)
        if not quiet:
            print(f"sealed -> {MIRROR} ({MIRROR.stat().st_size} bytes)")

    # ---- meta: last-set dates ----
    @staticmethod
    def meta() -> dict:
        return parse_env(META)

    @staticmethod
    def touch_meta(names):
        import datetime
        m = parse_env(META)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        for n in names:
            m[n] = now
        write_env(META, m)

    # ---- doctor ----
    def probe_one(self, name: str):
        """-> (status, detail) with status 'ok' | 'fail' | 'none'."""
        c = self.cfg.get(name)
        if not c:
            return ("none", "secret inconnu")
        value = self.value_of(name)
        if not value:
            return ("fail", "valeur absente du store")
        if c["probe"]:
            def sub(m):
                return m.group(0) if m.group(1) == "value" else self.value_of(m.group(1))
            cmd = REF.sub(sub, c["probe"]).replace("{value}", value)
            rc = self._run(["sh", "-c", cmd]).returncode
            return ("ok", "probe") if rc == 0 else ("fail", f"probe exit {rc}")
        for sink in c["sinks"]:
            if sink.startswith("mysql:"):
                ok = self._verify_sink(sink, value, self.data)
                return ("ok", "login mysql") if ok else ("fail", "login mysql refusé")
        # fallback: store <-> rendered parity, catches a stale render
        for sink in c["sinks"]:
            if sink.startswith("env:"):
                svc, _, var = sink[4:].partition("#")
                if parse_env(RENDER_DIR / f"{svc}.env").get(var) != value:
                    return ("fail", f"rendered/{svc}.env en retard (re-render)")
        return ("none", "pas de probe défini")

    def doctor(self, names, log) -> int:
        meta = self.meta()
        tally = {"ok": 0, "fail": 0, "none": 0}
        for n in names:
            st, detail = self.probe_one(n)
            tally[st] += 1
            mark = {"ok": "✓", "fail": "✗", "none": "·"}[st]
            log(f"{mark} {n:34} {detail:36} (dernier set: {meta.get(n, 'inconnu')})")
        log(f"\n{tally['ok']} ok, {tally['fail']} KO, {tally['none']} sans probe.")
        return tally["fail"]

    # ---- selection ----
    def select(self, only) -> list:
        if only:
            names = [n.strip() for n in only.split(",") if n.strip()] \
                if isinstance(only, str) else list(only)
            unknown = [n for n in names if n not in self.cfg]
            if unknown:
                raise ConfigError(f"secret inconnu: {', '.join(unknown)}")
            return names
        return [n for n, c in self.cfg.items()
                if c["kind"] in GEN_KINDS and c["group"] == "auto"]

    def plan(self, names, log):
        for n in names:
            c = self.cfg[n]
            gen = "gen new" if c["kind"] in GEN_KINDS else f"({c['kind']})"
            log(f"• {n}  [{c['kind']}/{c['group']}]  {gen}")
            for s in c["sinks"]:
                log(f"    sink  {s}")
            for cn in self.affected_computed([n]):
                log(f"    ~> recompute {cn} -> {', '.join(self.cfg[cn]['sinks'])}")
            for svc in self.services_to_recreate([n]):
                log(f"    recreate  {svc}")

    # ---- rotate / apply ----
    def rotate(self, names, do_it: bool, log):
        targets = [n for n in names if self.cfg[n]["kind"] in GEN_KINDS]
        for n in (n for n in names if n not in targets):
            kind = self.cfg[n]["kind"]
            if kind == "apikey":
                log(f"skip {n}: CLE API — jamais générée. La régénérer dans l'app, "
                    f"puis `bv-secrets set {n} <valeur>`.")
            else:
                log(f"skip {n}: kind={kind} (non générable — `set` manuellement)")
        if not targets:
            log("rien à roter.")
            return
        self.plan(targets, log)
        if not do_it:
            log("\n(dry-run — rien appliqué. Ajouter --yes pour exécuter.)")
            return

        old = {n: self.data.get(n, "") for n in targets}
        new = {n: self.gen(self.cfg[n]["kind"], self.cfg[n]["length"]) for n in targets}
        self._apply_live_sinks(targets, old, new, log)

        m = parse_env(MASTER)
        m.update({n: new[n] for n in targets})
        write_env(MASTER, m)
        self.touch_meta(targets)
        self.data = self._combined()
        self.render()
        log("rendered/*.env mis à jour.")
        self.recreate(targets, False, log)
        self.seal(quiet=True)
        log(f"\n✓ rotate terminé : {', '.join(targets)}. (valeurs via `bv-secrets get <NAME>`)")

    def _apply_live_sinks(self, targets, old, new, log):
        """Apply non-env sinks with rollback. root last, so earlier ALTERs can still
        authenticate with the old root password."""
        order = sorted(targets, key=lambda n: 1 if n == "MARIADB_ROOT_PASSWORD" else 0)
        eff = dict(self.data)
        applied = []
        try:
            for n in order:
                for sink in self.cfg[n]["sinks"]:
                    if sink.startswith("env:"):
                        continue
                    log(f"apply {n} -> {sink}")
                    if not self._apply_sink(sink, new[n], eff, False, log):
                        raise RuntimeError(f"apply FAILED: {n} -> {sink}")
                    applied.append((n, sink, old[n]))
                    if not self._verify_sink(sink, new[n], eff):
                        raise RuntimeError(f"verify FAILED: {n} -> {sink}")
                eff[n] = new[n]
        except Exception as e:
            log(f"\n✗ {e}\nROLLBACK des sinks déjà appliqués…")
            reff = dict(self.data)
            for n, sink, previous in reversed(applied):
                self._apply_sink(sink, previous, reff, False, log)
            raise RotateAborted("rotate avorté — store inchangé.")

    def apply(self, names, do_it: bool, log):
        """Push CURRENT values to sinks without regenerating."""
        self.render()
        log("rendered/*.env réécrits.")
        if not do_it:
            log("(env appliqué. Ajouter --yes pour pousser aussi linux/mysql/cmd + restarts.)")
            return
        eff = dict(self.data)
        for n in names:
            for sink in self.cfg[n]["sinks"]:
                if sink.startswith("env:"):
                    continue
                log(f"apply {n} -> {sink}")
                self._apply_sink(sink, self.value_of(n), eff, False, log)
        self.recreate(names, False, log)
        log("✓ apply terminé.")

    # ---- reading locations: import + drift ----
    def read_at(self, sink: str):
        """In-place value at this location, best-effort. None if unreadable.

        An `env:svc#VAR` sink is read from rendered/<svc>.env where render()
        materialized the value. Write-only sinks (mysql, linux, cmd) -> None."""
        scheme = sink.split(":", 1)[0]
        if scheme == "env":
            svc, _, var = sink[4:].partition("#")
            return parse_env(RENDER_DIR / f"{svc}.env").get(var)
        if scheme in locations.readable_schemes():
            try:
                return locations.read_location(sink)
            except locations.LocationError:
                return None
        return None

    def read_current(self, name: str):
        """First readable value among a secret's locations: (value, sink)."""
        for sink in self.cfg.get(name, {}).get("sinks", []):
            value = self.read_at(sink)
            if value not in (None, ""):
                return value, sink
        return None, None

    def import_one(self, name: str, source: str = None, force: bool = False, log=print):
        """Adopt the in-place value: read where it lives, write to the store.

        Touches nothing outside; the inverse of apply. Without --force, a secret
        already in the store is left as-is."""
        if name not in self.cfg:
            raise ConfigError(f"secret inconnu: {name}")
        if self.data.get(name) and not force:
            log(f"· {name}: déjà en store (--force pour réimporter)")
            return None
        if source:
            value = self.read_at(source)
            sink = source
        else:
            value, sink = self.read_current(name)
        if value in (None, ""):
            log(f"· {name}: aucune localisation lisible (poser à la main avec `set`)")
            return None
        d = parse_env(MASTER)
        d[name] = value
        write_env(MASTER, d)
        self.touch_meta([name])
        self.data = self._combined()
        log(f"✓ {name}: importé depuis {sink.split('#')[0]} ({len(value)} c)")
        return value

    def import_all(self, log=print):
        adopted = 0
        for name in sorted(self.cfg):
            if not self.data.get(name) and self.cfg[name]["kind"] != "computed":
                if self.import_one(name, log=log) is not None:
                    adopted += 1
        log(f"\n{adopted} secret(s) adopté(s).")
        return adopted

    def _sink_readable(self, sink: str) -> bool:
        scheme = sink.split(":", 1)[0]
        return scheme == "env" or scheme in locations.readable_schemes()

    def status(self, names, log):
        """Compare store value to in-place. A secret with only write-only sinks
        (mysql/linux/cmd) is non verifiable ; a readable sink whose file/cle is
        absent = declare mais pas deploye (cas machine nue)."""
        counts = {"sync": 0, "drift": 0, "extern": 0, "absent": 0, "unknown": 0}
        for n in names:
            stored = self.value_of(n)
            found, where = self.read_current(n)
            readable = any(self._sink_readable(s) for s in self.cfg.get(n, {}).get("sinks", []))
            if found is not None and not stored:
                mark, detail, key = "+", f"présent dehors, absent du store ({where.split('#')[0]})", "extern"
            elif found is not None and found == stored:
                mark, detail, key = "=", "synchronisé", "sync"
            elif found is not None:
                mark, detail, key = "!", f"DÉRIVE vs {where.split('#')[0]}", "drift"
            elif readable:
                mark, detail, key = "-", "déclaré, non déployé", "absent"
            else:
                mark, detail, key = "?", "non vérifiable (sink write-only)", "unknown"
            counts[key] += 1
            log(f"{mark} {n:34} {detail}")
        log(f"\n{counts['sync']} synchronisés, {counts['drift']} dérives, "
            f"{counts['extern']} à importer, {counts['absent']} non déployés, "
            f"{counts['unknown']} non vérifiables.")
        return counts["drift"]

    def scan(self, location: str, log):
        """List a file's keys to help declare secrets."""
        target = location if ":" in location else f"envfile:{location}"
        scheme, path, _ = locations.split(target)
        if scheme != "envfile":
            raise ConfigError("scan ne gère pour l'instant que les fichiers env")
        keys = locations.env_keys(path)
        declared = {sk.rpartition("#")[2] for c in self.cfg.values() for sk in c["sinks"]}
        for key in keys:
            log(f"  {'✓' if key in declared else '+'} {key}")
        log(f"\n{len(keys)} clé(s) — ✓ déjà gérée, + à déclarer.")
        return keys

    # ---- consistency ----
    def check(self) -> list:
        """-> list of problems (strings). Empty = healthy config."""
        from .config import GROUPS, SINK_TYPES, looks_like_apikey
        problems = []
        valid_sinks = set(SINK_TYPES) | locations.writable_schemes()
        for n, c in self.cfg.items():
            if c["kind"] not in ALL_KINDS:
                problems.append(f"BAD kind on {n}: {c['kind']}")
            if c["group"] not in GROUPS:
                problems.append(f"BAD group on {n}: {c['group']}")
            if looks_like_apikey(n) and c["kind"] != "apikey":
                problems.append(f"NAME/KIND {n}: nom de clé d'app tierce mais kind={c['kind']}")
            if c["kind"] == "apikey" and not looks_like_apikey(n):
                problems.append(f"NAME/KIND {n}: kind=apikey mais le nom ne contient ni API ni TOKEN")
            if c["kind"] != "computed" and not self.data.get(n):
                problems.append(f"MISSING value: {n}")
            problems += [f"BAD sink on {n}: {s}" for s in c["sinks"]
                         if s.split(":", 1)[0] not in valid_sinks]
        for p in [MASTER, LOCAL] + list(RENDER_DIR.glob("*.env")):
            if p.exists() and oct(p.stat().st_mode & 0o777) != "0o600":
                problems.append(f"PERM {p} is {oct(p.stat().st_mode & 0o777)}, want 0o600")
        return problems

    def render_parity(self) -> list:
        """Differences between what render() would write and the current renders."""
        problems = []
        for svc, kv in self.service_map().items():
            cur = parse_env(RENDER_DIR / f"{svc}.env")
            problems += [f"{svc}: variable manquante {k}" for k in kv if k not in cur]
            problems += [f"{svc}: valeur différente pour {k}" for k in kv
                         if k in cur and cur[k] != kv[k]]
            problems += [f"{svc}: variable en trop {k} (absente de la config)" for k in cur if k not in kv]
        return problems
