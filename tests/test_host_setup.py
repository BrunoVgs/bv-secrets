"""Portabilite hote : generation de l'unite, refus du sink supprime, et lecture
du log hote quelle que soit la distribution.

Ce qui casse silencieusement quand on change de machine, c'est justement ca : une
unite ecrite pour un seul compte, un sink qui suppose doas, un chemin de log qui
n'existe que sur Alpine."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bvsecrets import audit, config, service          # noqa: E402


def run_cli(*args, **env_extra):
    env = {**os.environ, "PYTHONPATH": str(ROOT), "NO_COLOR": "1", **env_extra}
    return subprocess.run([sys.executable, "-m", "bvsecrets.cli", *args],
                          env=env, capture_output=True, text=True)


class TestUnitGeneration(unittest.TestCase):
    """L'unite est derivee, pas un modele a editer : compte courant, chemins
    resolus, interpreteur en cours."""

    def unit(self, init, store="/tmp/bv-store"):
        r = run_cli("init", "--unit", init, BV_SECRETS_DIR=store)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_systemd_unit_runs_as_the_current_account(self):
        text = self.unit("systemd")
        user, group = service.account()
        self.assertIn(f"User={user}\n", text)
        self.assertIn(f"Group={group}\n", text)
        self.assertIn(f"ExecStart={sys.executable} -u -m bvsecrets.worker.loop", text)
        self.assertIn(f"WorkingDirectory={ROOT}", text)

    def test_docker_is_a_soft_dependency(self):
        # A box using only file/config connectors has no docker; a hard dependency
        # would keep the unit from starting at all.
        self.assertNotIn("Requires=docker", self.unit("systemd"))
        self.assertIn("Wants=docker.service", self.unit("systemd"))
        self.assertNotIn("need docker", self.unit("openrc"))
        self.assertIn("use docker", self.unit("openrc"))

    def test_systemd_spool_follows_the_configured_store(self):
        self.assertIn("/tmp/elsewhere/spool", self.unit("systemd", store="/tmp/elsewhere"))

    def test_openrc_unit_is_a_runnable_shell_script(self):
        text = self.unit("openrc")
        user, group = service.account()
        self.assertTrue(text.startswith("#!/sbin/openrc-run"))
        self.assertIn(f'command_user="{user}:{group}"', text)
        # Le conf.d est re-source sous `set -a` : aucune liste de variables a
        # maintenir quand une cle de config apparait.
        self.assertIn("set -a", text)
        subprocess.run(["sh", "-n"], input=text, text=True, check=True)


class TestInitIsTheWholeInstall(unittest.TestCase):
    """Une seule commande pour une premiere installation : store, config de
    depart, service. Idempotente, et sans root quand rien ne l'exige."""

    def test_creates_store_and_config_in_one_go(self):
        with tempfile.TemporaryDirectory() as d:
            store, conf = Path(d) / "store", Path(d) / "secrets.conf"
            r = run_cli("init", "--dir", str(store), "--no-service",
                        BV_SECRETS_CONF=str(conf), BV_CONFIG=str(Path(d) / "bv.ini"))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((store / "spool").is_dir())
            self.assertTrue(conf.exists())
            self.assertIn("[APP_ADMIN_PASSWORD]", conf.read_text())   # bien le modele
            # secrets_dir epingle : la commande suivante retrouve le store seule
            self.assertIn(str(store), (Path(d) / "bv.ini").read_text())

            again = run_cli("init", "--dir", str(store), "--no-service",
                            BV_SECRETS_CONF=str(conf), BV_CONFIG=str(Path(d) / "bv.ini"))
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertIn("déjà présent", again.stdout)

    def test_never_overwrites_an_existing_config(self):
        with tempfile.TemporaryDirectory() as d:
            conf = Path(d) / "secrets.conf"
            conf.write_text("[MINE]\nkind = password\n")
            run_cli("init", "--dir", str(Path(d) / "store"), "--no-service",
                    BV_SECRETS_CONF=str(conf), BV_CONFIG=str(Path(d) / "bv.ini"))
            self.assertEqual(conf.read_text(), "[MINE]\nkind = password\n")


class TestPrintedCommandsFitTheBox(unittest.TestCase):
    """Les commandes affichees doivent etre copiables telles quelles : une machine
    sans sudo (Alpine, doas seul) recevait `command not found`."""

    def test_elevation_shown_is_the_one_installed(self):
        tool = service.elevator()
        out = []
        service.install_unit("openrc", yes=False, log=out.append)
        printed = "\n".join(out)
        if tool:
            name = Path(tool).name
            self.assertIn(f"{name} tee ", printed)
            self.assertIn(f"{name} rc-update", printed)
        else:
            self.assertIn("en root", printed)
            self.assertNotIn("sudo ", printed)

    def test_a_closed_pipe_is_not_an_error(self):
        # `bv-secrets init --unit openrc | head -1`
        with subprocess.Popen([sys.executable, "-m", "bvsecrets.cli", "init", "--unit", "openrc"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env={**os.environ, "PYTHONPATH": str(ROOT)}) as unit:
            head = subprocess.run(["head", "-1"], stdin=unit.stdout, capture_output=True, text=True)
            unit.stdout.close()
            stderr = unit.stderr.read().decode()
        self.assertEqual(head.stdout.strip(), "#!/sbin/openrc-run")
        self.assertNotIn("BrokenPipeError", stderr)


class TestRemovedLinuxSink(unittest.TestCase):
    """Un sink supprime doit se voir tout de suite, avec son remplacant : sinon la
    valeur n'est plus appliquee la ou on croit qu'elle l'est."""

    def test_config_with_linux_sink_is_refused_with_its_replacement(self):
        with tempfile.TemporaryDirectory() as d:
            conf = Path(d) / "secrets.conf"
            conf.write_text("[LINUX_PW]\nkind = password\nsinks =\n    linux:deploy\n")
            r = run_cli("list", BV_SECRETS_DIR=d, BV_SECRETS_CONF=str(conf))
        self.assertEqual(r.returncode, 1)
        self.assertIn("linux:", r.stderr)
        self.assertIn("cmd:sudo chpasswd <<< 'deploy:{value}'", r.stderr)

    def test_linux_is_no_longer_a_sink_type(self):
        self.assertNotIn("linux", config.SINK_TYPES)


class TestHostLogSource(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.pop("BV_HOST_SYSLOG", None)

    def tearDown(self):
        os.environ.pop("BV_HOST_SYSLOG", None)
        if self._env is not None:
            os.environ["BV_HOST_SYSLOG"] = self._env

    def test_explicit_path_wins(self):
        os.environ["BV_HOST_SYSLOG"] = "/var/log/auth.log"
        self.assertEqual(config.host_log_source(), ("file", Path("/var/log/auth.log")))

    def test_journal_keyword_selects_journalctl(self):
        os.environ["BV_HOST_SYSLOG"] = "journal"
        self.assertEqual(config.host_log_source(), ("journal", None))

    def test_auto_resolves_to_something_readable_or_nothing(self):
        kind, path = config.host_log_source()
        self.assertIn(kind, ("file", "journal", None))
        if kind == "file":
            self.assertTrue(os.access(path, os.R_OK))


class TestPinSecretsDir(unittest.TestCase):
    """`init --dir` doit pouvoir ecrire la cle sans abimer un ini existant : c'est
    la sortie de secours quand on n'a pas root du tout."""

    def pin(self, initial, value="/srv/store"):
        with tempfile.TemporaryDirectory() as d:
            ini = Path(d) / "bv-secrets.ini"
            if initial is not None:
                ini.write_text(initial)
            original = service.CONFIG_FILE
            service.CONFIG_FILE = ini
            try:
                service.pin_secrets_dir(Path(value))
                return ini.read_text()
            finally:
                service.CONFIG_FILE = original

    def test_creates_the_file_when_absent(self):
        self.assertEqual(self.pin(None), "[bv-secrets]\nsecrets_dir = /srv/store\n")

    def test_rewrites_an_existing_key_in_place(self):
        out = self.pin("[bv-secrets]\n# garder\nsecrets_dir = /old\nroles = a,b\n")
        self.assertIn("secrets_dir = /srv/store\n", out)
        self.assertNotIn("/old", out)
        self.assertIn("# garder", out)
        self.assertIn("roles = a,b", out)

    def test_inserts_under_the_section_when_the_key_is_missing(self):
        out = self.pin("[bv-secrets]\nroles = a,b\n")
        self.assertEqual(out.splitlines()[1], "secrets_dir = /srv/store")


class TestElevationEvents(unittest.TestCase):
    """`journalctl -o short` sort le meme format RFC 3164 que syslog : une seule
    passe d'analyse pour les deux, et sudo compte autant que doas."""

    def parse(self, *lines):
        original = audit._host_lines
        audit._host_lines = lambda since: iter(lines)
        try:
            return audit.host_events(0)
        finally:
            audit._host_lines = original

    def test_sudo_line_is_an_elevation(self):
        ev, = self.parse("Jul 25 10:01:00 host sudo: alice : TTY=pts/0 ; COMMAND=/bin/ls")
        self.assertEqual((ev["source"], ev["actor"], ev["outcome"]), ("host", "alice", "change"))
        self.assertIn("sudo", ev["target"])

    def test_doas_line_still_works(self):
        ev, = self.parse("Jul 25 10:01:00 host doas: bv ran command /bin/ls")
        self.assertEqual((ev["actor"], ev["outcome"]), ("bv", "change"))

    def test_sudo_refusal_is_a_denial(self):
        ev, = self.parse("Jul 25 10:02:00 host sudo: mallory : user NOT in sudoers ; TTY=pts/1")
        self.assertEqual((ev["actor"], ev["outcome"]), ("mallory", "deny"))

    def test_pam_failure_names_the_account_not_the_module(self):
        ev, = self.parse("Jul 25 10:03:00 host sudo: pam_unix(sudo:auth): "
                         "authentication failure; logname=bob user=bob")
        self.assertEqual((ev["actor"], ev["outcome"]), ("bob", "deny"))

    def test_ssh_login_from_the_same_stream(self):
        ev, = self.parse("Jul 25 10:00:00 host sshd[123]: "
                         "Accepted publickey for bv from 10.8.0.5 port 1 ssh2")
        self.assertEqual((ev["actor"], ev["target"], ev["outcome"]), ("10.8.0.5", "bv", "login"))


class TestSetupNeverPromptsWithoutATty(unittest.TestCase):
    """Le prompt d'elevation n'existe que pour un humain devant un terminal : un
    script, un conteneur ou le worker doivent etre refuses, pas bloques."""

    def test_confirm_refuses_without_a_terminal(self):
        code = (f"import sys; sys.path.insert(0, {str(ROOT)!r}); "
                "from bvsecrets import service; service.confirm('go?')")
        r = subprocess.run([sys.executable, "-c", code],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Pas de terminal", r.stderr)


if __name__ == "__main__":
    unittest.main()
