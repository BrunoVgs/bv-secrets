<p align="center">
  <img src="docs/logo.png" alt="bv-secrets" width="180">
</p>

<h1 align="center">bv-secrets</h1>

<p align="center">
  A low-level manager that edits the files directly: secrets, permissions, accounts.<br>
  One declarative source, one privileged worker, and an audit lens to see who reached
  what, when, from where, and what changed.
</p>

<p align="center">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-3776ab">
  <img alt="No dependencies" src="https://img.shields.io/badge/dependencies-none-3fbf5f">
  <img alt="MIT licence" src="https://img.shields.io/badge/licence-MIT-c0242c">
</p>

---

## What it is

A low-level manager for a self-hosted box. It does not run a daemon that owns
your infrastructure; it edits the actual files where secrets, permissions and
accounts already live. Three things are administered here, and they turned out to
be the same problem: a declarative source of truth, and something privileged that
makes reality match it — plus one lens to observe all of it.

| Domain | Source of truth | Applied to |
|---|---|---|
| Secrets and rotation | `secrets.conf` | `.env` files, SQL users, Linux accounts, app commands |
| Access | `access.conf` | Caddy gates, homepage tiles per role, console tiles |
| Portal accounts | the auth service's database | roles, deletion, password reset |
| Audit | logs that already exist | a read-only timeline — who reached what, when, what changed |

The part that matters is that the loop is closed. A personal vault (Bitwarden,
Dashlane) stores passwords for a human to read back. Here, when a database
password is rotated, the SQL user is actually altered, the `.env` files are
rewritten, and the affected containers are recreated so they pick up the new
value. Without that last step, a "rotated" secret is just a new string in a file
while the service keeps authenticating with the old one.

The same reasoning pushed accounts in. Running a second web backoffice next to
this one, with its own session handling and its own database access, only added
attack surface for something the worker could already do through the app's own
console commands. So the backoffice went away and the accounts moved here.

Audit is the observing counterpart of all this: once the tool touches secrets,
access and accounts, it is also the right place to *look* — but as a lens over
logs that already exist, never a new collection or retention system.

## Onboarding an app

The central move: you install an application, it drops yet another `.env`, and you
bring it under management in one command. `adopt` scans the file, picks out the
secrets (hosts, ports, log levels are ignored), proposes a declaration, then writes
it to `secrets.conf` and imports the values in place.

```sh
bv-secrets adopt /srv/grafana/.env --prefix GRAFANA_
```
```
From /srv/grafana/.env — 3 secret(s) detected:
  + GRAFANA_GF_SECURITY_ADMIN_PASSWORD password  app     <- GF_SECURITY_ADMIN_PASSWORD (21 c)
  + GRAFANA_GF_DATABASE_PASSWORD       hex       app     <- GF_DATABASE_PASSWORD (32 c)
  + GRAFANA_GF_AUTH_JWT_API_TOKEN      apikey    manual  <- GF_AUTH_JWT_API_TOKEN (39 c)
  · ignored (config): GF_SERVER_HTTP_PORT, GF_SERVER_DOMAIN, GF_SECURITY_ADMIN_USER, GF_LOG_LEVEL

Re-run with --yes to declare these secrets and import their values.
```

That run is a dry run; nothing is written until you add `--yes`. The kind is
guessed (a hex value gives `hex`, a name containing `API` or `TOKEN` gives
`apikey`, which is never rotated) and the default group is `app`, never `auto` —
a third-party secret does not enter automatic rotation before someone has looked
at it. Everything stays editable afterwards, from the dashboard or by hand in
`secrets.conf`.

Once adopted, the secret behaves like any other: `rotate` regenerates the value and
writes it back into the app's `.env`, `status` watches for drift.

### Under the hood

`adopt` is three smaller commands composed together, each usable on its own:

```sh
bv-secrets scan /srv/app/.env          # which keys could I manage?
bv-secrets import --all                # pull in-place values into the store
bv-secrets status                      # in sync, drifted, or missing?
```

A location is a two-way connector: bv-secrets can read a value where it lives as
well as write it there. `status` re-reads every location and reports what changed
outside the tool. Writes are surgical — only the targeted value changes, comments,
ordering and indentation stay byte-for-byte identical.

Location schemes:

| Scheme | Target | reads | writes |
|---|---|:-:|:-:|
| `envfile:/path#KEY` | one key in a `KEY=VALUE` file | ✓ | ✓ |
| `regex:/path#<pattern>` | group 1 of a pattern, any format | ✓ | ✓ |
| `file:/path` | the whole file as the value | ✓ | ✓ |
| `json:/path#a.b.c` | a value at a JSON path | ✓ | — |
| `mysql:user@container` | a SQL account password (`ALTER USER`) | — | ✓ |
| `cmd:…` `linux:user` | app command · Linux account | — | ✓ |

To write a value inside YAML/TOML/INI, `regex:` is the catch-all until dedicated
resolvers exist (`api_password:\s*(\S+)`).

## What it isn't

Not a team vault, not a networked secret server (Vault, Infisical). No exposed
daemon, no database, no cluster. One config file, a `0600` store, and a Python
binary built on the standard library.

## Security model

This is the core of the project: privileges are asymmetric.

| Component | Where | Privileges |
|---|---|---|
| CLI | host, interactive | store rw, `doas` for Linux accounts |
| Worker | host, system service | docker + store rw, no inbound network |
| Web dashboard | container | store read-only, no docker access |

The dashboard performs no privileged action itself — not a rotation, not an access
change, not an account edit. It drops a job descriptor in a spool directory; the
worker picks it up, runs it, and writes back a log containing no values. That is
what makes it safe to put the UI behind a reverse proxy without granting it any
privilege: compromising the web container gives neither docker, nor write access to
the store, nor the database.

Values are never logged. The only commands that print one are `get` and `open`,
and only when asked. `audit` fits the same asymmetry: it only ever prints
metadata, and the two root-owned log sources (Caddy, syslog) are read
interactively through `doas` from the CLI, never granted to the worker or the
dashboard as a standing privilege.

## Two orthogonal axes

The distinction that holds the model together, not to be collapsed back:

- `kind` — the FORMAT of the value, what it *is*:
  `password`, `hex`, `b64`, `passphrase`, `userpass`, `opaque`, `computed`, `apikey`
- `group` — the rotation POLICY, *when* it gets regenerated:
  `auto`, `app`, `careful`, `manual`

An `apikey` is issued by a third-party application. It is never generated: writing
a random string there would produce a key the application rejects, and the service
goes down. A name containing `API` or `TOKEN` forces that kind, and switching it to
a generatable kind is refused in three independent places — the UI, the API and
the worker.

## Getting started

```sh
git clone https://github.com/<account>/bv-secrets.git
cd bv-secrets
cp secrets.conf.example secrets.conf     # describe your own secrets

export BV_SECRETS_DIR=/opt/bv-secrets    # store, renders, encrypted mirror
bin/bv-secrets list                      # inventory, no values
bin/bv-secrets plan                      # what a rotation would do
bin/bv-secrets rotate --yes              # regenerate and apply the auto group
bin/bv-secrets doctor                    # check that each value actually WORKS
```

`secrets.conf` is not versioned: it describes the infrastructure (services, SQL
users, probe commands). Only the template is.

### Dashboard

```sh
docker build -t bv-secrets-web .
docker run -d --name bv-secrets-web --read-only -u 1000:1000 -p 8000:8000 \
  -e BV_DASH_PASSWORD='<application password>' \
  -v "$PWD/secrets.conf:/app/secrets.conf:ro" \
  -v /opt/bv-secrets:/opt/bv-secrets:ro \
  -v /opt/bv-secrets/spool:/spool:rw \
  bv-secrets-web
```

The worker and the container must share the same `secrets.conf` file: the worker
rewrites it when a kind changes from the UI. Mount it, never rely on the copy baked
into the image.

An example compose service and the worker's OpenRC unit are in [`docs/`](docs/)
and [`deploy/`](deploy/).

## Access

`access.conf` answers one question — which role reaches which service — and every
consumer is generated from it: the Caddy gate snippets, the homepage tiles for each
role, the console tile visibility. Editing a generated file by hand is always
wrong; the next render overwrites it.

Roles are hierarchical (`guest < trusted < admin`), and admin passes every gate
whether it is listed or not. A service can drive up to three surfaces, and an empty
key means that surface simply does not exist for it. Unions are computed rather
than declared: the console's static gate is the union of the roles of the tiles it
contains.

The matrix and its renderer live with the deployment, not in this repository —
`$BV_COMPOSE_DIR/access/`, pointed at by `BV_ACCESS_CONF`. bv-secrets drives them:
the dashboard posts a change, the worker calls the renderer, then recreates the
proxy and restarts whatever consumes the matrix.

```sh
access/render-access.py show            # resolved matrix
access/render-access.py caddy --check   # is the Caddy region up to date?
```

The renderer only writes files. Reloading Caddy and restarting homepage are separate
steps the worker takes deliberately, so a render is never a deployment by accident.
The proxy is recreated rather than restarted: its configuration is mounted file by
file, and a plain restart would re-read the old one.

## Accounts

With `BV_AUTH_SERVICE` set, the dashboard lists the auth portal's accounts, changes
their roles and deletes them. It does this by running the application's own console
commands through the worker, so there is no second piece of code that knows the user
schema and no database credential in the web container. Passwords are never read.
The last-admin guard lives in the Symfony command, which is the only place that can
enforce it correctly.

Left empty, `BV_AUTH_SERVICE` disables the feature rather than pointing at some
arbitrary service.

## Audit

`audit` is a read-only lens, not a monitoring product. It reads logs the box
already writes, normalises them into one timeline, and answers a single question:
who reached what, when, from where, and what changed. It collects nothing new and
keeps no history of its own.

| Source | Where | Yields |
|---|---|---|
| Access | Caddy JSON access log | HTTP requests: IP, service, allowed / denied (403) |
| Trail | worker spool (`done/`, `results/`) | privileged actions: rotate, access change, account edit |
| Rotation dates | `meta.env` | when each secret was last set |
| Host | syslog (`sshd`, `doas`) | SSH logins and privilege elevations |

```sh
bv-secrets audit --since 24h            # everything, last 24h
bv-secrets audit --source access --denied   # only refused HTTP accesses (403)
bv-secrets audit --source trail --since 7d   # recent rotations, grants, account edits
bv-secrets audit --ip 10.8.0.5 --json        # one client, machine-readable
```

**No standing privilege.** The Caddy log is `root:0600` and the syslog is
root-owned; reading them is an interactive, `doas`-elevated act reserved to the
CLI on the host — exactly like a `linux:` sink. Nothing gains a `nopass` rule and
no root log is mounted into a container to make a dashboard "live".

That boundary shapes where each thing shows up. The worker builds a digest of the
parts it can read unprivileged (trail + rotation dates) into `$BV_SECRETS_DIR/audit/`,
which the read-only dashboard renders continuously. The access and host slices are
written to the same directory by the last CLI `audit` run and shown with an
`as of` marker, so the dashboard is honest about their freshness rather than
pretending to a liveness it cannot have safely. No value ever appears in either
face; URLs are logged without their query string.

Account *changes* surface through the trail (`source: trail`); the current account
roster stays in the **Accounts** view. One deliberate limitation: Caddy logs the
client request, so accesses are attributed by IP and service, not by portal user —
attaching the authenticated user needs an explicit `log_append` of `X-Auth-User`
in the Caddy `(logging)` snippet, not an implicit promise.

## Commands

| Command | Effect |
|---|---|
| `list` | inventory: name, kind, group, presence, services |
| `check` | config consistency, values present, `0600` permissions |
| `plan` | dry run of a rotation, no value touched |
| `rotate [--only N] --yes` | regenerate and apply everywhere, with rollback |
| `apply [--only N] --yes` | push current values without regenerating |
| `doctor [--only N]` | check each value against the real application |
| `render` | rewrite the `rendered/<service>.env` files |
| `adopt <file> [--prefix P_]` | onboard an app: detect its secrets, declare and import |
| `scan <file>` | list the keys of an existing `.env` to help declare them |
| `import [NAME\|--all]` | adopt values already in place: read them where they live → store |
| `status` | compare the store to in-place values, report drift |
| `get` / `set` / `gen` | read, write, generate a value |
| `add` | register a new secret and its targets |
| `seal` / `open` | encrypted mirror of the store, for off-machine backup |
| `audit [--source --since --denied --ip --service --json]` | timeline: who reached what, when, from where, what changed |
| `leaks` | look for managed values sitting in cleartext elsewhere |
| `verify-render` | check that `render()` reproduces the current renders |

## What rotation actually does

`rotate` writes to the store only after every live sink has been applied and
verified. If one fails, the previous ones are put back to their earlier value and
the store is left untouched. There is no half-rotated secret.

Order matters: the database root password is applied last, so that the preceding
`ALTER USER` statements can still authenticate with the old one.

Services to recreate are derived from the sinks, never declared by hand: a
container only re-reads its `env_file` at creation time, so any service targeted by
an `env:` sink gets recreated. `computed` secrets that reference a rotated value
also pull their own targets into the recreation set.

## Configuration

Every path has a default and can be overridden through the environment:

| Variable | Default | Role |
|---|---|---|
| `BV_SECRETS_DIR` | `/opt/bv-secrets` | store, renders, encrypted mirror |
| `BV_SECRETS_CONF` | `<project>/secrets.conf` | declarative source |
| `BV_SPOOL` | `$BV_SECRETS_DIR/spool` | web → worker job queue |
| `BV_ACCESS_CONF` | `<compose>/access/access.conf` | service × role matrix |
| `BV_COMPOSE_DIR` | project's parent directory | docker compose root |
| `BV_CADDY_LOG_DIR` | `/var/log/caddy` | Caddy access logs read by `audit` |
| `BV_HOST_SYSLOG` | `/var/log/messages` | host syslog (ssh/doas) read by `audit` |
| `BV_DASH_PASSWORD` | — | dashboard application password |
| `BV_PORT` | `8000` | dashboard listening port |

The worker also drives services whose names differ between installations. Left
empty, the matching features are disabled rather than acting on an arbitrary
service:

| Variable | Role |
|---|---|
| `BV_PROXY_SERVICE` | reverse proxy recreated after an access change |
| `BV_ACCESS_RELOAD_SERVICES` | services to restart afterwards, comma-separated |
| `BV_AUTH_SERVICE` | service hosting the account management console |

On an OpenRC system these live in `/etc/conf.d/bvsecrets-worker` — see
[`deploy/bvsecrets-worker.confd.example`](deploy/bvsecrets-worker.confd.example).
That keeps the repository generic; real service names are never versioned.

## Layout

```
bvsecrets/          engine shared by the three faces
  config.py           paths and domain vocabulary
  envfile.py          atomic .env read/write
  locations.py        two-way location connectors
  conffile.py         appending sections to secrets.conf
  adopt.py            secret detection in an existing config file
  engine.py           resolution, render, rotation, doctor
  audit.py            audit lens: normalised events from existing logs
  cli.py              command-line interface
  worker/             privileged spool executor (also builds the audit digest)
web/                dashboard
  server.py           HTTP transport, sessions, CSRF
  routes.py           API entry points
  audit_read.py       read-only merge of the audit digests
  static/css|js/      one sheet per layer, ES modules, no build
deploy/             worker OpenRC unit
docs/               example compose service
```

No dependencies: Python standard library on the server, native ES modules in the
browser, no build step.

## Licence

MIT — see [LICENSE](LICENSE).
