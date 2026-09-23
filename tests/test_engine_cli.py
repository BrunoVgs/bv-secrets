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


class TestApplyPushesFixedKinds(CLITestCase):
    """`apply` nu doit pousser TOUT ce qui a une valeur, pas seulement ce qu'un
    `rotate` nu regenererait. Les deux partageaient `select()`, donc un `apikey`
    -- jamais dans GEN_KINDS -- n'etait ni rendu ni recree : le conteneur gardait
    son ancienne valeur indefiniment, sans le moindre message."""

    def setUp(self):
        super().setUp()
        self.conf.write_text(
            f"[THIRD_PARTY_KEY]\nkind = apikey\n"
            f"sinks =\n    envfile:{self.app_env}#THIRD_PARTY_KEY\n")
        self.app_env.write_text("THIRD_PARTY_KEY=stale\n")
        (self.store / "bv-secrets.env").write_text("THIRD_PARTY_KEY=current\n")

    def test_bare_apply_reaches_a_third_party_key(self):
        r = self.run_cli("apply", "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        from bvsecrets.envfile import parse_env
        self.assertEqual(parse_env(self.app_env).get("THIRD_PARTY_KEY"), "current")

    def test_a_key_without_value_is_left_alone(self):
        (self.store / "bv-secrets.env").write_text("")
        r = self.run_cli("apply", "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        from bvsecrets.envfile import parse_env
        self.assertEqual(parse_env(self.app_env).get("THIRD_PARTY_KEY"), "stale")


class TestApplyIsIdempotent(CLITestCase):
    """Un `apply` qui ne change rien ne doit RIEN toucher. render() reecrivait
    chaque rendered/<svc>.env sans condition et services_to_recreate() derivait
    des sinks seuls : sur cette stack, un apply nu recreait 17 conteneurs pour
    des valeurs parfois inchangees depuis des mois."""

    def setUp(self):
        super().setUp()
        self.conf.write_text(
            "[APP_SECRET]\nkind = password\nlength = 16\n"
            "sinks =\n    env:demo#APP_SECRET\n")
        (self.store / "bv-secrets.env").write_text("APP_SECRET=value\n")
        self.rendered = self.store / "rendered" / "demo.env"

    def test_first_apply_renders(self):
        r = self.run_cli("apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 modifié", r.stdout)
        self.assertTrue(self.rendered.exists())

    def test_second_apply_rewrites_nothing(self):
        self.run_cli("apply")
        stamp = self.rendered.stat().st_mtime_ns
        r = self.run_cli("apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("aucun changement", r.stdout)
        self.assertEqual(self.rendered.stat().st_mtime_ns, stamp)

    def test_a_new_value_renders_again(self):
        self.run_cli("apply")
        (self.store / "bv-secrets.env").write_text("APP_SECRET=other\n")
        r = self.run_cli("apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 modifié", r.stdout)


class TestLeaksSurvivesBinaryFiles(CLITestCase):
    """`leaks --staged` lisait les blobs indexes en UTF-8 et levait des qu'un
    fichier binaire etait indexe -- une police, une image. Le hook pre-commit
    mourait avec la commande, donc il ne protegeait plus rien au moment ou on
    en avait le plus besoin."""

    def setUp(self):
        super().setUp()
        self.conf.write_text(
            "[APP_SECRET]\nkind = password\nlength = 16\n"
            f"sinks =\n    envfile:{self.app_env}#APP_SECRET\n")
        (self.store / "bv-secrets.env").write_text("APP_SECRET=valeursecrete\n")
        self.repo = self.base / "repo"
        self.repo.mkdir()
        for argv in (["init", "-q"], ["config", "user.email", "t@t"],
                     ["config", "user.name", "t"]):
            subprocess.run(["git", *argv], cwd=self.repo, capture_output=True)

    def _stage(self, name, data):
        path = self.repo / name
        path.write_bytes(data)
        subprocess.run(["git", "add", name], cwd=self.repo, capture_output=True)

    def run_cli(self, *args):
        env = {
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "BV_SECRETS_DIR": str(self.store),
            "BV_SECRETS_CONF": str(self.conf),
            "NO_COLOR": "1",
        }
        return subprocess.run([sys.executable, "-m", "bvsecrets.cli", *args],
                              env=env, cwd=self.repo, capture_output=True, text=True)

    def test_a_staged_binary_does_not_abort_the_scan(self):
        self._stage("police.woff2", bytes([0x00, 0xf4, 0x9d, 0x01]) * 64)
        r = self.run_cli("leaks", "--staged")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Clean", r.stdout)

    def test_a_real_leak_is_still_caught_beside_it(self):
        self._stage("police.woff2", bytes([0x00, 0xf4, 0x9d, 0x01]) * 64)
        self._stage("config.yml", b"token: valeursecrete\n")
        r = self.run_cli("leaks", "--staged")
        self.assertEqual(r.returncode, 1)
        self.assertIn("APP_SECRET", r.stdout)
        self.assertIn("config.yml", r.stdout)
