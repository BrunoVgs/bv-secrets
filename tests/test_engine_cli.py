"""Bout-en-bout via la CLI, sur un store temporaire isole (aucun docker requis).

Couvre le coeur risque : machine nue (list/check/status sans rien deploye),
rotation reelle sur un sink fichier, et surtout le ROLLBACK quand un sink echoue —
le store doit rester intact et la valeur en place revenir a l'ancienne."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class CLITestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.base = Path(self.dir.name)
        self.store = self.base / "store"
        self.store.mkdir()
        self.conf = self.base / "secrets.conf"
        self.app_env = self.base / "app.env"

    def tearDown(self):
        self.dir.cleanup()

    def run_cli(self, *args):
        env = {
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "BV_SECRETS_DIR": str(self.store),
            "BV_SECRETS_CONF": str(self.conf),
            "NO_COLOR": "1",
        }
        return subprocess.run([sys.executable, "-m", "bvsecrets.cli", *args],
                              env=env, capture_output=True, text=True)

    def master(self):
        from bvsecrets.envfile import parse_env
        return parse_env(self.store / "bv-secrets.env")


class TestBareMachine(CLITestCase):
    """secrets.conf declare, rien de deploye, aucun docker : les commandes de
    lecture tournent proprement et status dit 'non deploye'."""

    def setUp(self):
        super().setUp()
        self.conf.write_text(
            "[APP_SECRET]\nkind = password\nlength = 16\ngroup = auto\n"
            f"sinks =\n    envfile:{self.app_env}#APP_SECRET\n")

    def test_list_runs(self):
        r = self.run_cli("list")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("APP_SECRET", r.stdout)

    def test_status_reports_not_deployed(self):
        r = self.run_cli("status")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("non déployé", r.stdout)

    def test_check_flags_missing_value(self):
        r = self.run_cli("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("MISSING value", r.stdout)


class TestRotate(CLITestCase):
    def setUp(self):
        super().setUp()
        self.conf.write_text(
            "[APP_SECRET]\nkind = password\nlength = 16\ngroup = auto\n"
            f"sinks =\n    envfile:{self.app_env}#APP_SECRET\n")
        self.app_env.write_text("APP_SECRET=initial\nOTHER=keep\n")

    def test_rotate_updates_store_and_sink(self):
        r = self.run_cli("rotate", "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        new = self.master().get("APP_SECRET")
        self.assertTrue(new and new != "initial")
        from bvsecrets.envfile import parse_env
        self.assertEqual(parse_env(self.app_env).get("APP_SECRET"), new)
        self.assertEqual(parse_env(self.app_env).get("OTHER"), "keep")

    def test_dry_run_changes_nothing(self):
        r = self.run_cli("rotate")            # sans --yes
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIsNone(self.master().get("APP_SECRET"))
        from bvsecrets.envfile import parse_env
        self.assertEqual(parse_env(self.app_env).get("APP_SECRET"), "initial")


class TestRollback(CLITestCase):
    """Un sink qui echoue apres un sink deja applique : rollback du premier,
    store inchange, exit non-zero."""

    def setUp(self):
        super().setUp()
        self.conf.write_text(
            "[ROLL]\nkind = password\nlength = 12\ngroup = auto\n"
            f"sinks =\n    envfile:{self.app_env}#ROLL\n    cmd:false\n")
        self.app_env.write_text("ROLL=oldvalue\n")
        (self.store / "bv-secrets.env").write_text("ROLL=oldvalue\n")
        os.chmod(self.store / "bv-secrets.env", 0o600)

    def test_failed_sink_rolls_back(self):
        r = self.run_cli("rotate", "--only", "ROLL", "--yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ROLLBACK", r.stdout)
        self.assertEqual(self.master().get("ROLL"), "oldvalue")
        from bvsecrets.envfile import parse_env
        self.assertEqual(parse_env(self.app_env).get("ROLL"), "oldvalue")


class TestImport(CLITestCase):
    def setUp(self):
        super().setUp()
        self.conf.write_text(
            "[EXISTING]\nkind = password\ngroup = app\n"
            f"sinks =\n    envfile:{self.app_env}#EXISTING\n")
        self.app_env.write_text("EXISTING=already-here\n")

    def test_import_adopts_in_place_value(self):
        r = self.run_cli("import", "EXISTING")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.master().get("EXISTING"), "already-here")

    def test_status_synced_after_import(self):
        self.run_cli("import", "EXISTING")
        r = self.run_cli("status")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("synchronisé", r.stdout)


if __name__ == "__main__":
    unittest.main()
