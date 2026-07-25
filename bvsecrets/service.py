"""Host setup: create the store, install the worker as a service.

The only place in bv-secrets allowed to ask for root, and only from a TTY. The core
never elevates and the worker never prompts: elevation belongs to setup, not to
operation. A setup command prints the exact command first, asks, then runs it
through sudo or doas; with neither installed it prints the command and stops, so
elevation stays a convenience and never a dependency. The password is read by
sudo/doas on their own TTY, never by us.

The unit is generated, not a template to fill in: the account is whoever installs,
the paths and the interpreter are the ones in use.
"""
import getpass
import grp
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import locations
from .config import CONFIG_FILE, PROJECT_DIR, SECRETS_DIR
from .engine import ConfigError

SERVICE = "bvsecrets-worker"
UNIT_PATH = {"systemd": Path(f"/etc/systemd/system/{SERVICE}.service"),
             "openrc": Path(f"/etc/init.d/{SERVICE}")}
# Site variables (BV_*) live outside the unit, where each init system expects them.
ENV_FILE = {"systemd": Path(f"/etc/default/{SERVICE}"),
            "openrc": Path(f"/etc/conf.d/{SERVICE}")}


def detect_init() -> str:
    """'systemd' | 'openrc' | '' — /run/systemd/system is the canonical test for a
    systemd-booted machine (what sd_booted() looks at)."""
    if Path("/run/systemd/system").is_dir():
        return "systemd"
    if Path("/run/openrc").is_dir() or shutil.which("rc-service"):
        return "openrc"
    return ""


def account() -> tuple:
    user = getpass.getuser()
    return user, grp.getgrgid(os.getgid()).gr_name


def _systemd_unit() -> str:
    user, group = account()
    spool = SECRETS_DIR / "spool"
    # systemd wants an absolute path here; `+` runs this one step as root, which is
    # what OpenRC's checkpath does. No coreutils `install` -> skip it, the worker
    # creates the spool itself when it can.
    installer = shutil.which("install")
    pre = (f"ExecStartPre=+{installer} -d -m 0700 -o {user} -g {group} {spool}\n"
           if installer else "")
    # docker is wanted, not required: a box using only file/config connectors has
    # none, and `Requires=` on a missing unit refuses to start at all.
    return f"""[Unit]
Description=bv-secrets spool worker
Wants=docker.service
After=docker.service network-online.target

[Service]
User={user}
Group={group}
WorkingDirectory={PROJECT_DIR}
Environment=PYTHONPATH={PROJECT_DIR}
EnvironmentFile=-{ENV_FILE['systemd']}
{pre}ExecStart={sys.executable} -u -m bvsecrets.worker.loop
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""


def _openrc_unit() -> str:
    user, group = account()
    spool = SECRETS_DIR / "spool"
    return f"""#!/sbin/openrc-run
# Worker bv-secrets — le seul composant privilégié du système.
# Tourne sous {user} (docker + store rw), sans réseau entrant. Il vide le spool
# alimenté par l'UI web read-only et exécute rotate/apply/doctor.
# Généré par `bv-secrets install-service` : ne pas éditer, régénérer.

name="{SERVICE}"
description="bv-secrets spool worker (rotate/apply executor)"

command="{sys.executable}"
command_args="-u -m bvsecrets.worker.loop"
command_user="{user}:{group}"
command_background="yes"
directory="{PROJECT_DIR}"
pidfile="/run/{SERVICE}.pid"

export PYTHONPATH="{PROJECT_DIR}"
# OpenRC sources conf.d, but a shell assignment does not reach the daemon's
# environment. Re-sourcing under `set -a` exports every site variable without
# listing them one by one, so a new config key needs no change here.
if [ -f {ENV_FILE['openrc']} ]; then
	set -a
	. {ENV_FILE['openrc']}
	set +a
fi

depend() {{
	use docker
	after net
}}

start_pre() {{
	checkpath -d -m 0700 -o {user}:{group} {spool}
}}
"""


def unit_text(init: str) -> str:
    if init == "systemd":
        return _systemd_unit()
    if init == "openrc":
        return _openrc_unit()
    raise ConfigError("init système non reconnu (ni systemd ni OpenRC) : "
                      "lancer le worker à la main avec "
                      f"`{sys.executable} -u -m bvsecrets.worker.loop`")


def enable_commands(init: str) -> list:
    if init == "systemd":
        return ["systemctl daemon-reload",
                f"systemctl enable --now {SERVICE}"]
    return [f"chmod +x {UNIT_PATH['openrc']}",
            f"rc-update add {SERVICE} default",
            f"rc-service {SERVICE} start"]


# --- elevation -------------------------------------------------------------- #
def elevator() -> str:
    for binary in ("sudo", "doas"):
        found = shutil.which(binary)
        if found:
            return found
    return ""


def confirm(question: str) -> bool:
    """A setup prompt exists only for a human at a terminal. Anything else (a
    script, the worker, a container) gets a refusal instead of a hanging read."""
    if not sys.stdin.isatty():
        raise ConfigError(f"{question}\nPas de terminal : lancer la commande "
                          "ci-dessus manuellement.")
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes", "o", "oui")


def run_as_root(argv: list, log=print) -> int:
    """Show the exact command, then run it as root. Already root: straight through.
    Otherwise sudo/doas, after a confirmation. Neither available: print and stop."""
    shown = " ".join(str(a) for a in argv)
    if os.geteuid() == 0:
        return subprocess.run(argv).returncode
    tool = elevator()
    if not tool:
        log(f"\nNi sudo ni doas ici. Lancer en root :\n    {shown}\n")
        return 1
    log(f"\n    {Path(tool).name} {shown}\n")
    if not confirm("Lancer cette commande ?"):
        return 1
    return subprocess.run([tool] + [str(a) for a in argv]).returncode


# --- store ------------------------------------------------------------------ #
def pin_secrets_dir(path: Path):
    """Write secrets_dir into bv-secrets.ini. An existing key is rewritten in place
    by the ini connector (comments and order untouched); a missing one is inserted
    under its section, the file being created if needed."""
    selector = f"ini:{CONFIG_FILE}#bv-secrets.secrets_dir"
    try:
        locations.write_location(selector, str(path))
        return
    except locations.LocationError:
        pass                                  # no file, no section, or no key yet
    lines = CONFIG_FILE.read_text().splitlines(keepends=True) if CONFIG_FILE.exists() else []
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    head = next((i for i, ln in enumerate(lines) if ln.strip() == "[bv-secrets]"), None)
    if head is None:
        lines.append("[bv-secrets]\n")
        head = len(lines) - 1
    lines.insert(head + 1, f"secrets_dir = {path}\n")
    CONFIG_FILE.write_text("".join(lines))


def create_store(path: Path, log=print) -> int:
    """Create the store directory, 0700, owned by the current account. Needs root
    once for a system path like /opt; nothing at all under $HOME."""
    user, group = account()
    if path.is_dir():
        log(f"store déjà présent : {path}")
    else:
        try:
            path.mkdir(mode=0o700, parents=True)      # under $HOME: no root at all
        except PermissionError:
            log(f"\nLe store va contenir tes valeurs en clair, en 0700, hors du dépôt :"
                f"\n    {path}\n\nCréer ce dossier demande les droits root une fois :")
            if run_as_root(["install", "-d", "-m", "700", "-o", user, "-g", group,
                            str(path)], log) != 0:
                return 1
        else:
            os.chmod(path, 0o700)                     # mkdir's mode goes through umask
    for sub in ("rendered", "audit", "spool"):
        (path / sub).mkdir(mode=0o700, exist_ok=True)
    log(f"✓ store prêt : {path} ({user}:{group}, 0700)")
    return 0
