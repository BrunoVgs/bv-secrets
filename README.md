<p align="center">
  <img src="docs/logo.png" alt="bv-secrets" width="180">
</p>

<h1 align="center">bv-secrets</h1>

<p align="center">
  Password rotation, access control, account management and an audit log,<br>
  built into a single server. No network, no database, no dependencies.
</p>

<p align="center">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-3776ab">
  <img alt="No dependencies" src="https://img.shields.io/badge/dependencies-none-3fbf5f">
  <img alt="MIT licence" src="https://img.shields.io/badge/licence-MIT-c0242c">
  <img alt="CI" src="https://github.com/BrunoVgs/bv-secrets/actions/workflows/ci.yml/badge.svg">
</p>

---

One file you own is the source of truth; one privileged process makes the running
system match it. It edits the files where secrets, access rules and accounts already
live, and it is the one place that can tell you what happened to them. Stdlib only,
runs on a bare box.

| What | Source of truth | Reaches |
|---|---|---|
| Secrets & rotation | `secrets.conf` | env & config files, SQL passwords, app commands |
| Accounts | your app's SQL database | user roles and deletion, from the tool |
| Access | `access.conf` | your reverse proxy (Caddy, nginx, Apache) |
| Audit | logs the box already writes | one read-only timeline |

## Quickstart

```sh
pipx install git+https://github.com/BrunoVgs/bv-secrets.git   # zero runtime deps

bv-secrets init              # store, starter config, worker service — one command
$EDITOR ~/.config/bv-secrets/secrets.conf                     # describe your secrets

bv-secrets list              # inventory, no values
bv-secrets status            # store vs what's deployed: synced / drift / not deployed
bv-secrets plan              # what a rotation would do
bv-secrets rotate --yes      # regenerate + apply the auto group, with rollback
bv-secrets doctor            # does each value actually WORK?
```

`init` is the whole install and every step of it is idempotent: it creates the
store (asking for root once, showing the exact command), writes the starter
config if there is none, and generates the worker's systemd or OpenRC unit for
the account you ran it from. `--dir` puts the store somewhere you own and needs
no root at all; `--no-service` skips the init system entirely.

From a clone instead, `git clone … && cd bv-secrets && bin/bv-secrets init` does
the same, with the config in the checkout.

`status`, `list`, `check` and `import` need nothing but the store and `secrets.conf`,
so you can declare and watch a box that has nothing deployed yet.

## Bootstrap a new box

`deploy/bootstrap.sh` installs docker, compose, caddy and bv-secrets on a fresh
machine. POSIX sh, idempotent, distro-aware (Alpine `apk`, Void `xbps`, Debian and
Ubuntu `apt`). It needs root only for the packages: without it the store falls back
under `$HOME` instead of `/opt`, so an unprivileged install still ends up working.

```sh
./deploy/bootstrap.sh                 # full install
./deploy/bootstrap.sh --check         # report what is missing, change nothing
./deploy/bootstrap.sh --no-packages   # already provisioned
./deploy/bootstrap.sh --store DIR     # store somewhere other than /opt/bv-secrets
```

The `Bootstrap` workflow runs this same file in clean Alpine, Void and Debian
containers, as a freshly created unprivileged account, then drives the result:
`list`, `check`, `adopt`, and a check that an adopted `API_TOKEN` lands in the
third-party-key family rather than among the rotatable passwords. The install path
is therefore tested as a stranger would meet it, not as the author remembers it.

## Rotation

`rotate` changes the string **and** everything using it: the SQL user is `ALTER`ed,
the `.env` and config files are rewritten, the affected containers are recreated so
they read the new value. It is all-or-nothing: every sink is applied and verified
before the store is written; if one fails, the rest roll back. The DB root password
goes last so earlier `ALTER USER` statements can still authenticate.

Which containers to recreate is derived from the `env:` sinks, never declared by hand.

## Connectors

A location is a two-way connector: bv-secrets reads a value where it lives and writes
it back. Writes are **surgical** — only the targeted value changes, comments and
formatting stay byte-for-byte. `status` re-reads everything and flags what drifted.

| Scheme | Target | read | write |
|---|---|:-:|:-:|
| `envfile:/path#KEY` | one key in a `KEY=VALUE` file | yes | yes |
| `json:/path#a.b.c` | a value at a JSON path | yes | yes |
| `yaml:/path#a.b.c` | a scalar at a YAML path | yes | yes |
| `ini:/path#section.key` | a key in an INI section | yes | yes |
| `toml:/path#a.b.c` | a key in a TOML table | yes | yes |
| `regex:/path#<pattern>` | group 1 of a pattern, any format | yes | yes |
| `file:/path` | the whole file as the value | yes | yes |
| `mysql:user@container` | a SQL password (`ALTER USER`) | no | yes |
| `cmd:…` | any command, `{value}` being the new value | no | yes |

Structured writers are zero-dependency: they anchor on the key and replace the value
in place, no library reserializes the file.

## Onboarding an app

```sh
bv-secrets adopt /srv/grafana/.env --prefix GRAFANA_
```
```
From /srv/grafana/.env — 3 secret(s) detected:
  + GRAFANA_GF_SECURITY_ADMIN_PASSWORD password  app     <- GF_SECURITY_ADMIN_PASSWORD (21 c)
  + GRAFANA_GF_DATABASE_PASSWORD       hex       app     <- GF_DATABASE_PASSWORD (32 c)
  + GRAFANA_GF_AUTH_JWT_API_TOKEN      apikey    manual  <- GF_AUTH_JWT_API_TOKEN (39 c)
  · ignored (config): GF_SERVER_HTTP_PORT, GF_SERVER_DOMAIN, GF_SECURITY_ADMIN_USER

Re-run with --yes to declare these secrets and import their values.
```

Nothing is written without `--yes`. A name with `API`/`TOKEN` becomes an `apikey`
(never generated). New secrets land in `app`, never `auto`.

## Audit

`audit` is a read-only lens over logs the box already writes. It stores nothing new.

| Source | From | Tells you |
|---|---|---|
| Access | your proxy's access log | who reached which service, allowed or denied |
| Trail | worker spool | rotations, access changes, account edits |
| Rotation | `meta.env` | when each secret was last set |
| Host | syslog or journald | SSH logins and `sudo`/`doas` elevations |

```sh
bv-secrets audit --since 24h                 # everything, last 24h, grouped by day
bv-secrets audit --source access --denied    # only refused accesses
bv-secrets audit --ip 10.8.0.5 --json        # one client, machine-readable
```

### Elevation trail

`elevation` answers a narrower question in far more detail: who became root, when,
through which command, and what surrounded it.

auditd is the authority here rather than syslog, because it also records elevation
from cron, scripts and containers, which no shell history sees. The history only
supplies the surrounding commands.

```sh
bv-secrets elevation --rules | sudo tee /etc/audit/rules.d/50-bv-elevation.rules
sudo augenrules --load                       # or: service auditd restart

bv-secrets elevation --since 24h             # the report
bv-secrets elevation --window 6 --json       # wider context, machine-readable
bv-secrets elevation --context atuin         # cwd and exit code, if atuin is installed
```

```
2026-08-02 22:36:14  bv -> root  doas  micro /opt/bv-secrets/pihole.env
    avant  22:35:51  cd /opt/bv-secrets
    avant  22:36:09  grep FTLCONF pihole.env
    ELEVATION  uid=1000 -> euid=0  pid=14822  ppid=14401  tty=pts3
    apres  22:37:30  docker compose up -d --force-recreate pihole
```

Reading needs no privilege: the log is group-readable (`adm` on Debian and Ubuntu,
`wheel` on Alpine once `log_group` says so). When it is not readable the command
fails loudly instead of reporting an empty result, since a lens that answers
"nothing happened" while blind is worse than no lens.

Context providers: `zsh-history` (default, no dependency, needs `EXTENDED_HISTORY`)
and `atuin` (adds exit code and directory). The atuin store is read through its CLI,
never through its SQLite file, whose schema is explicitly unstable upstream.

## Security model

Privileges are lopsided on purpose.

| Component | Where | Can do |
|---|---|---|
| CLI | host, interactive | store rw |
| Worker | host, service | docker + store rw, no inbound network |
| Dashboard | container | read the store, drop jobs in a spool, nothing else |

Nothing in the core elevates. `init` may ask for root once, from a terminal,
printing the exact command before running it; the worker never prompts and never
elevates.

Values are never logged. `get` and `open` are the only commands that print one.

**Where the store rests.** The store is a `0600` file outside the repo
(`$BV_SECRETS_DIR/bv-secrets.env`) — plaintext, like any `.env` on the box. The
trust model is the host's own: file permissions plus the privilege split above, not
encryption-at-rest. That is the deliberate trade for having no daemon, no unseal
step and no network — the opposite of Vault. If your threat model needs the store
encrypted at rest, this tool is not it (yet). `seal` covers the other case: an
encrypted `store.enc` mirror you can carry off the machine for backup.

**Host assumptions.** None beyond Python 3.11 and, for the container-facing sinks,
docker. The worker runs under the account that installed it, on systemd or OpenRC,
and `init` generates its unit rather than copying a template you have to edit
(`bv-secrets init --unit systemd` prints it without installing anything).

Setting a Linux account password is a `cmd:` sink, so the elevation is yours to
choose: `cmd:sudo chpasswd <<< 'deploy:{value}'`.

## Architecture

```
  you, at a shell            ┌──────────────────────────────────────────────┐
       │                     │  DASHBOARD   container, unprivileged          │
       │                     │  read-only view + a form that queues jobs     │
       ▼                     └───────────────────────┬──────────────────────┘
 ┌────────────────────┐                              │  writes a job file
 │ CLI  bin/bv-secrets │                             ▼
 │  ui.py     colour   │                       ┌───────────┐
 │  complete  bash/zsh │                       │  spool/   │   filesystem queue
 └─────────┬──────────┘                        └─────┬─────┘
           │  in-process                              │  drains
           │                                          ▼
           │                            ┌──────────────────────────┐
           │                            │ WORKER   host daemon      │
           │                            │ the only privileged part  │
           │                            │ docker + store write      │
           │                            └────────────┬─────────────┘
           ▼                                          ▼
    ╔══════════════════════════════════════════════════════════════════╗
    ║                            engine.py                               ║
    ║   resolve → render → plan → rotate → apply → status → doctor       ║
    ╚═════╤══════════════════════╤═══════════════════════════╤══════════╝
          │ reads                │ reads / writes            │ reads / writes
          ▼                      ▼                           ▼
 ┌─────────────────┐  ┌────────────────────┐  ┌──────────────────────────────┐
 │ CONFIG          │  │ DEFINITIONS         │  │ CONNECTORS   locations/       │
 │ bv-secrets.ini  │  │ secrets.conf        │  │ two-way, surgical, zero-dep   │
 │ env>file>default│  │ + store (values)    │  │                               │
 │                 │  │                     │  │ read+write  envfile regex     │
 │ paths, roles,   │  │ kind · group ·      │  │             file json yaml    │
 │ service names   │  │ sinks · probe       │  │             ini toml          │
 │                 │  │                     │  │ write-only  env mysql linux   │
 │                 │  │                     │  │             cmd               │
 └─────────────────┘  └────────────────────┘  └───────────────┬──────────────┘
                                                               │ apply / import
                                                               ▼
                                      the real system: .env & config files,
                                      SQL & Linux passwords, containers

 ── AUDIT ──────────────────────────────────────────────────────────────────
   audit.py   read-only lens, stores nothing new
   caddy access log · host log (syslog|journal) · worker spool · meta.env
        └─► audit/digest.json  (rebuilt every minute)  ─►  dashboard timeline
```

## Configuration

One file, `bv-secrets.ini`, sets everything. Any key can be overridden by the
matching environment variable (same name, upper-case, `BV_` prefix), so a container
or a service unit keeps working: **env > file > default**. A bare machine with
neither runs on defaults.

```ini
[bv-secrets]
secrets_dir   = /opt/bv-secrets   # store, renders, mirror, audit digest
compose_dir   = /srv/containers   # docker compose root
proxy_service = caddy             # recreated after an access change
roles         = admin,trusted,guest
auth_service  =                   # app CLI for accounts; empty = access-only
```

See [`bv-secrets.ini.example`](bv-secrets.ini.example) for every key. Left empty, a
feature turns off rather than aiming at a random service. The dashboard reads its own
password from `BV_DASH_PASSWORD` in the container (a secret, never committed).

`secrets.conf` and `bv-secrets.ini` are looked up in that order: `$BV_SECRETS_CONF`
/ `$BV_CONFIG`, then the current directory, then `~/.config/bv-secrets/`, then the
checkout. So a `pipx`-installed `bv-secrets` works from anywhere, with its config
in `~/.config/bv-secrets/` or in the directory you run it from.

## Shell completion

```sh
source completions/bv-secrets.bash                 # bash, this shell
# or install it:
cp completions/bv-secrets.bash /etc/bash_completion.d/bv-secrets
cp completions/_bv-secrets     ~/.zsh/completions/ # zsh: a dir in your $fpath
```

Completes subcommands, flags, and dynamically the secret names (`--only`, `get`, …).

## Commands

| Command | Effect |
|---|---|
| `init [--dir P]` | first install: store, starter config, worker unit |
| `migrate-conf [--in-place] --yes` | convert an old INI declaration file to the declarative format |
| `host [--show --write]` | declared machine posture vs reality: audit rules, egress zones |
| `list` | inventory: name, kind, group, presence, services |
| `check` | config consistency, values present, `0600` perms |
| `status [--only N]` | store vs deployed: synced / drift / not deployed |
| `plan` | dry run of a rotation |
| `rotate [--only N] --yes` | regenerate and apply everywhere, with rollback |
| `apply [--only N] --yes` | push current values without regenerating |
| `doctor [--only N]` | test each value against the real app |
| `adopt <file> [--prefix P_]` | onboard an app: detect, declare, import |
| `scan` / `import` | list a file's keys / pull in-place values into the store |
| `get` / `set` / `gen` / `add` | read, write, generate, register |
| `run [--svc S] -- <cmd>` | run a command with the secrets as env vars, nothing on disk |
| `render` / `verify-render` | write / check `rendered/<service>.env` |
| `seal` / `open` | encrypted store mirror for off-machine backup |
| `audit [--source --since --denied --ip --json]` | who reached what, when, what changed |
| `elevation [--since --window --context --rules --json]` | who became root, when, via what, and the commands around it |
| `leaks [--staged]` | find managed values in cleartext (tree, or the git index) |

Guard your commits: `--staged` scans what's about to be committed. Install the hook
with `cp deploy/git-hooks/pre-commit .git/hooks/ && chmod +x .git/hooks/pre-commit`,
and a commit that embeds a managed value in cleartext is refused.

## The declaration file

Declarative, in the shape a Compose file taught you to read: reusable `x-`
templates, `<<:` to pull one in, `include:` to split by domain.

```yaml
x-password: &password { kind: password, group: auto, length: 20 }
x-appkey:   &appkey   { kind: apikey,   group: manual }

include:
  - secrets.media.yaml          # only on the box that runs the media stack

secrets:
  PIHOLE_ADMIN_PASSWORD:
    <<: *password
    length: 14
    sinks:
      - env:pihole#FTLCONF_webserver_api_password
      - env:homepage#HOMEPAGE_VAR_PIHOLE_KEY

  JELLYFIN_API_KEY:
    <<: *appkey
    sinks: [ env:homepage#HOMEPAGE_VAR_JELLYFIN_KEY ]
```

Keys written in a secret beat the template, exactly as YAML says. Adopted files
are unchanged: a sink still names a place inside a file you already had.

The parser is a restricted subset, no dependency: block mappings, `-` lists,
one-line flow mappings, anchors, aliases, `<<`, comments. Anything else raises an
error naming the line instead of guessing. Its output is checked against PyYAML.

### Migrating from the old INI

```
bv-secrets migrate-conf              # shows the result, writes nothing
bv-secrets migrate-conf --in-place --yes
```

Nothing is written unless re-reading the result gives back the same config, field
by field. `--in-place` keeps the filename and the inode, so the dashboard's
single-file bind mount and its baked `BV_SECRETS_CONF` keep working; the format is
recognised by content, not by extension. The original is kept as
`<name>.ini.bak`. Both readers stay available, so an untouched install keeps
working.

### Extending the format? Rebuild the dashboard first

The dashboard image bakes `bvsecrets/`. A declaration file using a key its baked
copy does not know is a config it cannot parse, and it dies on the next request.
Rebuild and recreate it *before* writing the new key:

```
docker compose build bv-secrets-web && docker compose up -d bv-secrets-web
```

## The machine's posture

Two more top-level keys describe the host rather than a secret. bv-secrets does
not apply them: it renders them, and mechanisms your distribution already ships
and maintains do the enforcing.

```yaml
egress:
  osint:                                    # a container that may reach the
    subnet: 172.31.9.0/24                   # internet but not the LAN or tunnel
    block: [192.168.0.0/16, 10.0.0.0/8, 169.254.0.0/16]

audit:
  elevation:
    trace: [sudo, doas, su, execve-setuid]  # what `elevation` will have to read
    window: 4
```

```
bv-secrets host            # what is declared vs what the machine actually has
bv-secrets host --show     # print the rendered audit rules
```

Binaries are resolved on *this* machine: `su` is `bbsuid` on Alpine, `doas` does
not exist on Ubuntu. A rule pointing at an absent path is accepted by auditd and
never fires, so a name that resolves nowhere is reported instead of written.

Exit code is `0` conforming, `1` drifted, `2` could not be verified — because
"I cannot read the file" is not "everything is fine". No dormant privilege: rules
are rendered into the store the account already owns, and the one command that
needs root is printed, never run for you.

This is deliberately not a daemon. A single process able to rewrite your firewall
*and* your secrets *and* your adopted config files is one compromise away from
total, which is the opposite of the privilege asymmetry the rest of the tool is
built on. One declaration, several enforcers.

## Two axes, don't mix them

- `kind` is the FORMAT: `password`, `hex`, `b64`, `passphrase`, `userpass`,
  `opaque`, `computed`, `apikey`.
- `group` is the rotation POLICY: `auto`, `app`, `careful`, `manual`.

An `apikey` is issued by someone else's app, so it is never generated; the name rule
(`API`/`TOKEN`) makes turning it into a generatable kind fail in the UI, the API and
the worker.

## Value validation

A `validate` rule checks the *shape* of a value (distinct from `probe`, which tests
that it *works*). It is enforced at the entry points — `set` and `import` refuse a
malformed value — and reported by `check`.

```ini
[STRIPE_API_KEY]
kind     = apikey
validate = prefix:sk_live_

[DB_PORT]
validate = int:1..65535
```

Rules: `regex:` · `prefix:` · `suffix:` · `enum:a,b,c` · `len:<spec>` ·
`int[:<spec>]` · `url`, where `<spec>` is `>=N` `<=N` `>N` `<N` `N..M` `N`.

## Layout

```
bvsecrets/          engine shared by CLI, worker and web
  engine.py           resolution, render, rotation, doctor
  config.py           one config file (+ env override), domain vocabulary
  locations/          two-way value connectors, one module per format family
  ui.py               terminal colour + tables (TTY-aware)
  complete.py         bash/zsh completion candidates
  adopt.py            secret detection in a config file
  audit.py            audit lens over existing logs
  cli.py              command line
  service.py          host setup: store, starter config, generated unit
  secrets.conf.example  template `init` writes, shipped with the package
  worker/             privileged spool executor + audit digest
completions/        bash + zsh completion scripts
web/                dashboard (read-only)
```

## Development

Stdlib-only, so the test suite needs nothing installed:

```sh
python -m unittest discover -s tests    # surgical writes, rotate rollback, validation
```

CI (`.github/workflows/ci.yml`) runs it on Python 3.11-3.13 and builds the wheel on
every push and PR.

## Licence

MIT, see [LICENSE](LICENSE).
