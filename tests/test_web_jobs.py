"""Jobs declenches depuis l'UI web : ajout d'un secret et adoption d'un fichier.

Ce sont les seuls chemins ou le tier web fait ecrire le worker, et le seul job qui
transporte une valeur en clair. On verifie donc surtout ce qui doit etre REFUSE :
un nom de cle API rendu generable, un sink inconnu, un chemin hors des racines
adoptables — et qu'aucune valeur ne ressort dans le log ou le resultat.

Le store et la config sont isoles par variables d'environnement ; aucun docker,
aucun spool reel.
"""
import importlib
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class JobsTestCase(unittest.TestCase):
    """Recharge config + jobs sous un store temporaire : les chemins du module sont
    resolus a l'import, un simple monkeypatch ne suffirait pas."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.base = Path(self.dir.name)
        self.store = self.base / "store"
        self.store.mkdir()
        self.conf = self.base / "secrets.conf"
        self.app_env = self.base / "adoptable" / "app.env"
        self.app_env.parent.mkdir()
        self.conf.write_text(
            "[APP_SECRET]\nkind = password\ngroup = auto\n"
            f"sinks =\n    envfile:{self.app_env}#APP_SECRET\n")

        self._env = dict(os.environ)
        os.environ.update({
            "BV_SECRETS_DIR": str(self.store),
            "BV_SECRETS_CONF": str(self.conf),
            "BV_ADOPT_ROOTS": str(self.app_env.parent),
        })
        # `conffile` et `adopt` font `from .config import CONF` : la valeur est
        # capturee a l'import, donc recharger config seul laisserait ces modules
        # pointer sur le store du test precedent. On recharge la chaine, dans
        # l'ordre des dependances.
        for name in ("bvsecrets.config", "bvsecrets.conffile", "bvsecrets.adopt",
                     "bvsecrets.engine", "bvsecrets.worker.jobs"):
            importlib.reload(importlib.import_module(name))
        self.jobs = importlib.import_module("bvsecrets.worker.jobs")
        self.log = []

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        self.dir.cleanup()

    def emit(self, message=""):
        self.log.append(str(message))

    def conf_text(self):
        return self.conf.read_text()


class TestAdd(JobsTestCase):
    def add(self, **fields):
        return self.jobs.do_add({"action": "add", **fields}, self.emit)

    def test_generated_secret_lands_in_conf_and_store(self):
        result = self.add(name="NEW_PASSWORD", kind="password", group="app",
                          sinks=[f"envfile:{self.app_env}#NEW_PASSWORD"])
        self.assertEqual(result["name"], "NEW_PASSWORD")
        self.assertGreater(result["len"], 0)
        self.assertIn("[NEW_PASSWORD]", self.conf_text())
        from bvsecrets.envfile import parse_env
        self.assertTrue(parse_env(self.store / "bv-secrets.env").get("NEW_PASSWORD"))

    def test_supplied_value_is_never_logged_or_returned(self):
        secret = "s3cr3t-de-test-tres-reconnaissable"
        result = self.add(name="VENDOR_API_KEY", kind="apikey", group="manual",
                          sinks=[f"envfile:{self.app_env}#VENDOR_API_KEY"], value=secret)
        self.assertEqual(result, {"name": "VENDOR_API_KEY", "len": len(secret)})
        self.assertNotIn(secret, "\n".join(self.log))
        self.assertNotIn(secret, repr(result))

    def test_apikey_name_cannot_be_generatable(self):
        with self.assertRaises(RuntimeError) as ctx:
            self.add(name="VENDOR_API_KEY", kind="password", group="app",
                     sinks=[f"envfile:{self.app_env}#K"])
        self.assertIn("clé API", str(ctx.exception))
        self.assertNotIn("VENDOR_API_KEY", self.conf_text())

    def test_apikey_kind_requires_api_in_name(self):
        with self.assertRaises(RuntimeError):
            self.add(name="PLAIN_SECRET", kind="apikey", group="manual",
                     sinks=[f"envfile:{self.app_env}#K"])

    def test_unknown_sink_type_is_refused(self):
        with self.assertRaises(RuntimeError) as ctx:
            self.add(name="NEW_PASSWORD", kind="password", group="app",
                     sinks=["carrier-pigeon:/tmp/x#K"])
        self.assertIn("sink invalide", str(ctx.exception))

    def test_duplicate_name_is_refused(self):
        with self.assertRaises(RuntimeError):
            self.add(name="APP_SECRET", kind="password", group="app",
                     sinks=[f"envfile:{self.app_env}#APP_SECRET"])

    def test_lowercase_name_is_refused(self):
        with self.assertRaises(RuntimeError):
            self.add(name="minuscule", kind="password", group="app",
                     sinks=[f"envfile:{self.app_env}#K"])

    def test_non_generatable_without_value_is_refused(self):
        with self.assertRaises(RuntimeError):
            self.add(name="OPAQUE_SEED", kind="opaque", group="manual",
                     sinks=[f"envfile:{self.app_env}#OPAQUE_SEED"])

    def test_sink_is_required(self):
        with self.assertRaises(RuntimeError):
            self.add(name="NEW_PASSWORD", kind="password", group="app", sinks=[])


class TestCreateUser(JobsTestCase):
    """Creation d'un compte du portail : l'autre job qui transporte une valeur.

    Le console du portail n'est pas lance (pas de docker ici) : on capture l'appel
    pour verifier ou passe le mot de passe."""

    def setUp(self):
        super().setUp()
        self.calls = []

        def fake_console(args, log, timeout=120, stdin=None):
            self.calls.append({"args": list(args), "stdin": stdin})
            log(f"$ console {' '.join(args)}")
            return '[{"username": "bob", "role": "guest", "created": "2026-01-01 00:00"}]'

        self.jobs._console = fake_console

    def create(self, **fields):
        return self.jobs.do_user({"action": "user", "op": "create", **fields}, self.emit)

    def test_password_goes_to_stdin_not_argv(self):
        secret = "mot-de-passe-de-test-reconnaissable"
        self.create(username="bob", role="guest", value=secret)
        call = self.calls[0]
        self.assertEqual(call["stdin"], secret)
        self.assertNotIn(secret, " ".join(call["args"]))
        self.assertNotIn(secret, "\n".join(self.log))

    def test_created_account_is_returned_in_the_fresh_list(self):
        users = self.create(username="bob", role="guest", value="assez-long")
        self.assertEqual([u["username"] for u in users], ["bob"])

    def test_invalid_username_is_refused(self):
        for bad in ("b", "bob;rm -rf /", "bob bob", "a" * 65, ""):
            with self.assertRaises(RuntimeError):
                self.create(username=bad, role="guest", value="assez-long")
        self.assertEqual(self.calls, [])

    def test_unknown_role_is_refused(self):
        with self.assertRaises(RuntimeError):
            self.create(username="bob", role="root", value="assez-long")
        self.assertEqual(self.calls, [])

    def test_short_password_is_refused(self):
        with self.assertRaises(RuntimeError):
            self.create(username="bob", role="guest", value="court")
        self.assertEqual(self.calls, [])


class TestAdopt(JobsTestCase):
    def setUp(self):
        super().setUp()
        self.app_env.write_text(
            "DB_PASSWORD=un-mot-de-passe-de-base\n"
            "VENDOR_API_KEY=cle-emise-par-le-vendeur\n"
            "DB_HOST=localhost\nLOG_LEVEL=debug\n")

    def test_plan_proposes_secrets_and_ignores_config(self):
        data = self.jobs.do_adopt_plan({"file": str(self.app_env)}, self.emit)
        names = {p["name"] for p in data["proposals"]}
        self.assertEqual(names, {"DB_PASSWORD", "VENDOR_API_KEY"})
        self.assertIn("DB_HOST", data["ignored"])
        self.assertIn("LOG_LEVEL", data["ignored"])

    def test_plan_returns_lengths_not_values(self):
        data = self.jobs.do_adopt_plan({"file": str(self.app_env)}, self.emit)
        blob = repr(data) + "\n".join(self.log)
        self.assertNotIn("un-mot-de-passe-de-base", blob)
        self.assertNotIn("cle-emise-par-le-vendeur", blob)
        proposal = next(p for p in data["proposals"] if p["name"] == "DB_PASSWORD")
        self.assertEqual(proposal["len"], len("un-mot-de-passe-de-base"))

    def test_apply_declares_and_imports_selected_keys_only(self):
        self.jobs.do_adopt({"file": str(self.app_env), "only": ["DB_PASSWORD"]}, self.emit)
        self.assertIn("[DB_PASSWORD]", self.conf_text())
        self.assertNotIn("[VENDOR_API_KEY]", self.conf_text())
        from bvsecrets.envfile import parse_env
        stored = parse_env(self.store / "bv-secrets.env")
        self.assertEqual(stored.get("DB_PASSWORD"), "un-mot-de-passe-de-base")

    def test_path_outside_adopt_roots_is_refused(self):
        outside = self.base / "outside.env"
        outside.write_text("SOME_PASSWORD=x\n")
        for action in (self.jobs.do_adopt_plan, self.jobs.do_adopt):
            with self.assertRaises(RuntimeError) as ctx:
                action({"file": str(outside), "only": ["SOME_PASSWORD"]}, self.emit)
            self.assertIn("hors des racines", str(ctx.exception))

    def test_traversal_out_of_root_is_refused(self):
        # le chemin est resolu AVANT d'etre compare aux racines
        sneaky = str(self.app_env.parent / ".." / "outside.env")
        (self.base / "outside.env").write_text("SOME_PASSWORD=x\n")
        with self.assertRaises(RuntimeError) as ctx:
            self.jobs.do_adopt_plan({"file": sneaky}, self.emit)
        self.assertIn("hors des racines", str(ctx.exception))

    def test_unselected_key_is_refused(self):
        with self.assertRaises(RuntimeError):
            self.jobs.do_adopt({"file": str(self.app_env), "only": ["ABSENTE"]}, self.emit)


if __name__ == "__main__":
    unittest.main()
