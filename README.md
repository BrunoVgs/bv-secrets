<p align="center">
  <img src="docs/logo.png" alt="bv-secrets" width="180">
</p>

<h1 align="center">bv-secrets</h1>

<p align="center">
  Drop it on a fresh box and you already have password rotation, access control,<br>
  account management and an audit log. Built into the server. No daemon, no database,
  no dependencies.
</p>

<p align="center">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-3776ab">
  <img alt="No dependencies" src="https://img.shields.io/badge/dependencies-none-3fbf5f">
  <img alt="MIT licence" src="https://img.shields.io/badge/licence-MIT-c0242c">
</p>

---

## Why

Every time you set up a server you end up bolting the same stuff onto it: somewhere
to keep passwords, some notion of who gets in, a backoffice for accounts, and if
you are lucky a vague idea of who did what. Each one a service, a database, a
dependency to keep alive.

bv-secrets is the opposite bet. One thing you drop on the box, and you already have
all of it: secret rotation, access control, account management and an audit log,
wired straight into the server. Nothing to install past Python.

Vault, Infisical and the rest are built for fleets: a networked daemon, a database,
a cluster to babysit. On a single host that is more moving parts than the thing
they protect. This stays small on purpose. It edits the files where secrets, access
rules and accounts already live, and it is the one place that can tell you what
happened to them.

Three jobs, one shape every time: a file you own is the source of truth, and one
privileged process makes the running system match it.

| Job | Source of truth | Made real in |
|---|---|---|
| Secrets & rotation | `secrets.conf` | `.env` files, SQL users, Linux accounts, app commands |
| Access | `access.conf` | Caddy gates, homepage tiles, console tiles |
| Accounts | the auth service's own DB | roles, deletion, password reset |
| Audit | logs the box already writes | one read-only timeline |

## Rotation that actually rotates

A password manager hands you a new string to copy. bv-secrets changes the string
**and** everything using it: the SQL user gets `ALTER`ed, the `.env` files get
rewritten, the affected containers get recreated so they pick up the new value.
Skip that last step and you have a "rotated" secret while the service keeps logging
in with the old one.

`rotate` is all or nothing. Every sink is applied and verified before the store is
written; if one fails, the rest roll back. No half-rotated secret. The database
root password goes last, so the earlier `ALTER USER` statements can still
authenticate with the old one.

Which containers to recreate is derived from the sinks, never declared by hand: a
container only re-reads its `env_file` at creation, so anything fed by an `env:`
sink gets recreated.

## Onboarding an app

Install something, it drops yet another `.env`, you bring it under management in
one line. `adopt` reads the file, keeps the secrets, ignores the config (hosts,
ports, log levels), and shows you the plan before writing anything.

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

Nothing is written without `--yes`. A name with `API` or `TOKEN` becomes an
`apikey`, which is never generated (a random value there just breaks the app). New
secrets land in `app`, never `auto`: a third-party secret does not enter automatic
rotation before you have looked at it.

Under the hood a location is a two-way connector, so bv-secrets reads a value where
it lives as well as writes it. `status` re-reads everything and tells you what
drifted outside the tool. Writes are surgical: only the targeted value changes,
comments and formatting stay byte-for-byte.

| Scheme | Target | read | write |
|---|---|:-:|:-:|
| `envfile:/path#KEY` | one key in a `KEY=VALUE` file | yes | yes |
| `regex:/path#<pattern>` | group 1 of a pattern, any format | yes | yes |
| `file:/path` | the whole file as the value | yes | yes |
| `json:/path#a.b.c` | a value at a JSON path | yes | no |
| `mysql:user@container` | a SQL password (`ALTER USER`) | no | yes |
| `cmd:…` / `linux:user` | app command / Linux account | no | yes |

## Security model

The whole point: privileges are lopsided.

| Component | Where | Can do |
|---|---|---|
| CLI | host, interactive | store rw, `doas` for Linux accounts |
| Worker | host, service | docker + store rw, no inbound network |
| Dashboard | container | read the store, nothing else |

The dashboard never does anything privileged. It drops a job in a spool; the worker
runs it and writes back a log with no values. So the UI can sit behind a proxy and
a full compromise of the web container still gets you nothing: no docker, no store
writes, no database.

Values are never logged. `get` and `open` are the only commands that print one, and
only when you ask.

## Audit

The tool already touches secrets, access and accounts, so it is the right place to
watch them. `audit` is a read-only lens over logs the box already writes. It stores
nothing new and keeps no history of its own.

| Source | From | Tells you |
|---|---|---|
| Access | Caddy access log | who reached which service, allowed or denied |
| Trail | worker spool | rotations, access changes, account edits |
| Rotation | `meta.env` | when each secret was last set |
| Host | syslog | SSH logins and `doas` elevations |

```sh
bv-secrets audit --since 24h                 # everything, last 24h
bv-secrets audit --source access --denied    # only refused accesses
bv-secrets audit --ip 10.8.0.5 --json        # one client, machine-readable
```

The worker builds the timeline with privileges it already has: it reads the Caddy
log (root, `0600`) through `docker exec`, and the host syslog directly because it
runs as a wheel user. No `doas`, no new privilege, no root log mounted into the web
container. The dashboard just reads the digest, refreshed every minute.

Two honest limits. Accesses are keyed by IP and service, not by portal user (Caddy
logs the client request; add a `log_append` of `X-Auth-User` if you want names).
And no secret value ever appears, query strings included.

## Access & accounts

`access.conf` answers one question, "which role reaches which service", and
everything downstream is generated from it: the Caddy gates, the homepage tiles per
role, the console tiles. Roles are hierarchical (`guest < trusted < admin`) and
admin passes every gate. Editing a generated file by hand is always wrong; the next
render overwrites it. The matrix and its renderer live with the deployment
(`$BV_COMPOSE_DIR/access/`), not in this repo.

Accounts work the same way without duplicating anything: the dashboard changes
roles and deletes users by running the auth app's own console commands through the
worker. No second copy of the user schema, no DB credential in the web container,
passwords never read. The last-admin guard stays in the app, the only place that
can enforce it right. Leave `BV_AUTH_SERVICE` empty and the feature is simply off.

## Getting started

```sh
git clone https://github.com/BrunoVgs/bv-secrets.git
cd bv-secrets
cp secrets.conf.example secrets.conf     # describe your own secrets

export BV_SECRETS_DIR=/opt/bv-secrets
bin/bv-secrets list                      # inventory, no values
bin/bv-secrets plan                      # what a rotation would do
bin/bv-secrets rotate --yes              # regenerate and apply the auto group
bin/bv-secrets doctor                    # does each value actually WORK?
```

`secrets.conf` is never versioned: it maps your infrastructure (services, SQL
users, probe commands). Only the template is.

Dashboard:

```sh
docker build -t bv-secrets-web .
docker run -d --name bv-secrets-web --read-only -u 1000:1000 -p 8000:8000 \
  -e BV_DASH_PASSWORD='<app password>' \
  -v "$PWD/secrets.conf:/app/secrets.conf:ro" \
  -v /opt/bv-secrets:/opt/bv-secrets:ro \
  -v /opt/bv-secrets/spool:/spool:rw \
  bv-secrets-web
```

Mount the same `secrets.conf` the worker uses (it rewrites the file when a format
changes from the UI); never rely on the copy baked into the image. An example
compose service and the worker's OpenRC unit are in [`docs/`](docs/) and
[`deploy/`](deploy/).

## Two axes, don't mix them

- `kind` is the FORMAT: `password`, `hex`, `b64`, `passphrase`, `userpass`,
  `opaque`, `computed`, `apikey`.
- `group` is the rotation POLICY: `auto`, `app`, `careful`, `manual`.

An `apikey` is issued by someone else's app, so it is never generated; the name
rule (`API`/`TOKEN`) makes turning it into a generatable kind fail in three
independent places: the UI, the API and the worker.

## Commands

| Command | Effect |
|---|---|
| `list` | inventory: name, kind, group, presence, services |
| `check` | config consistency, values present, `0600` perms |
| `plan` | dry run of a rotation |
| `rotate [--only N] --yes` | regenerate and apply everywhere, with rollback |
| `apply [--only N] --yes` | push current values without regenerating |
| `doctor [--only N]` | test each value against the real app |
| `adopt <file> [--prefix P_]` | onboard an app: detect, declare, import |
| `scan` / `import` / `status` | declare, pull in-place values, report drift |
| `get` / `set` / `gen` / `add` | read, write, generate, register |
| `render` / `verify-render` | write / check `rendered/<service>.env` |
| `seal` / `open` | encrypted store mirror for off-machine backup |
| `audit [--source --since --denied --ip --json]` | who reached what, when, what changed |
| `leaks` | find managed values sitting in cleartext elsewhere |

## Configuration

Every path has a default and takes an env override.

| Variable | Default | Role |
|---|---|---|
| `BV_SECRETS_DIR` | `/opt/bv-secrets` | store, renders, mirror, audit digest |
| `BV_SECRETS_CONF` | `<project>/secrets.conf` | declarative source |
| `BV_SPOOL` | `$BV_SECRETS_DIR/spool` | web to worker job queue |
| `BV_ACCESS_CONF` | `<compose>/access/access.conf` | service x role matrix |
| `BV_COMPOSE_DIR` | project's parent | docker compose root |
| `BV_CADDY_LOG_DIR` | `/var/log/caddy` | Caddy access log for `audit` |
| `BV_HOST_SYSLOG` | `/var/log/messages` | host syslog for `audit` |
| `BV_DASH_PASSWORD` | none | dashboard password |
| `BV_PORT` | `8000` | dashboard port |

Deployment-specific service names go in `/etc/conf.d/bvsecrets-worker`
(`BV_PROXY_SERVICE`, `BV_ACCESS_RELOAD_SERVICES`, `BV_AUTH_SERVICE`,
`BV_CADDY_CONTAINER`). Left empty, the matching feature is off rather than aimed at
a random service, so the repo stays generic and real names are never versioned. See
[`deploy/bvsecrets-worker.confd.example`](deploy/bvsecrets-worker.confd.example).

## Layout

```
bvsecrets/          engine shared by all three faces
  engine.py           resolution, render, rotation, doctor
  locations.py        two-way value connectors
  adopt.py            secret detection in a config file
  audit.py            audit lens over existing logs
  cli.py              command line
  worker/             privileged spool executor + audit digest
web/                dashboard (read-only)
  server.py           HTTP, sessions, CSRF
  routes.py           API
  static/             one CSS sheet per layer, ES modules, no build
```

Python standard library on the server, native ES modules in the browser, no build
step, nothing to install.

## Licence

MIT, see [LICENSE](LICENSE).
</content>
