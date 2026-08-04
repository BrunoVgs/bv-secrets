import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bvsecrets.config import (OBJ_COMPUTED, OBJ_ORDER, OBJ_PASSWORD, OBJ_TOKEN,
                              ROT_AUTO, ROT_NEVER, ROT_ONDEMAND, ROT_ORDER,
                              secret_object, secret_rotation)


class TestTwoAxesStaySeparate(unittest.TestCase):
    """Deux questions distinctes, jamais fusionnees. A QUI la valeur appartient
    decide si on peut la regenerer ; QUAND elle est rotee est autre chose. Les
    melanger disait deux fois la meme chose et cachait la premiere."""

    def test_a_password_is_mine_whatever_its_rotation(self):
        for group in ("auto", "app", "careful", "manual"):
            self.assertEqual(secret_object("password", "X_PASSWORD"), OBJ_PASSWORD)

    def test_rotation_is_read_off_the_group(self):
        self.assertEqual(secret_rotation("password", "auto", "A"), ROT_AUTO)
        self.assertEqual(secret_rotation("password", "app", "A"), ROT_ONDEMAND)
        self.assertEqual(secret_rotation("password", "careful", "A"), ROT_ONDEMAND)
        self.assertEqual(secret_rotation("password", "manual", "A"), ROT_NEVER)

    def test_a_third_party_key_is_its_own_object(self):
        self.assertEqual(secret_object("apikey", "JELLYFIN_API_KEY"), OBJ_TOKEN)

    def test_the_name_alone_makes_it_a_third_party_key(self):
        # la roter ecrirait une chaine que l'app refuse, quel que soit le kind
        self.assertEqual(secret_object("password", "SOME_API_KEY"), OBJ_TOKEN)
        self.assertEqual(secret_object("password", "FIREFLY_IMPORTER_TOKEN"), OBJ_TOKEN)

    def test_a_third_party_key_is_never_rotated_from_here(self):
        self.assertEqual(secret_rotation("password", "auto", "SOME_API_KEY"), ROT_NEVER)
        self.assertEqual(secret_rotation("apikey", "auto", "X_API_KEY"), ROT_NEVER)

    def test_computed_outranks_the_name_rule(self):
        self.assertEqual(secret_object("computed", "REDIS_TOKEN"), OBJ_COMPUTED)
        self.assertEqual(secret_rotation("computed", "auto", "REDIS_TOKEN"), ROT_NEVER)

    def test_an_ungeneratable_kind_is_never_rotated(self):
        self.assertEqual(secret_rotation("opaque", "auto", "TTYD_CRED"), ROT_NEVER)

    def test_every_value_appears_in_its_display_order(self):
        for v in (OBJ_PASSWORD, OBJ_TOKEN, OBJ_COMPUTED):
            self.assertIn(v, OBJ_ORDER)
        for v in (ROT_AUTO, ROT_ONDEMAND, ROT_NEVER):
            self.assertIn(v, ROT_ORDER)


class TestFrontEndsAgree(unittest.TestCase):
    """Le CLI et le dashboard doivent nommer et colorer les memes choses ; une
    divergence ici se voit en production, pas dans les tests."""

    def _js(self):
        return (Path(__file__).resolve().parent.parent
                / "web" / "static" / "js" / "labels.js").read_text(encoding="utf-8")

    def test_labels_js_covers_both_axes(self):
        js = self._js()
        for v in OBJ_ORDER:
            self.assertIn(f"{v}:", js, f"{v} absent de labels.js")
        for v in ROT_ORDER:
            self.assertIn(f"{v}:", js, f"{v} absent de labels.js")

    def test_ui_covers_both_axes(self):
        from bvsecrets import ui
        for v in OBJ_ORDER:
            self.assertIn(v, ui.OBJECT_STYLE, f"{v} absent de ui.OBJECT_STYLE")
        for v in ROT_ORDER:
            self.assertIn(v, ui.ROTATION_STYLE, f"{v} absent de ui.ROTATION_STYLE")

    def test_the_dashboard_row_carries_both(self):
        src = (Path(__file__).resolve().parent.parent
               / "web" / "inventory.py").read_text(encoding="utf-8")
        self.assertIn('"obj"', src)
        self.assertIn('"rot"', src)


class TestApikeyDeclarationIsOneWay(unittest.TestCase):
    """La regle de nommage n'a qu'un sens. Un nom en API/TOKEN impose kind=apikey,
    parce que generer une telle valeur casserait l'app tierce. L'inverse est faux :
    beaucoup de cles tierces s'appellent *_KEY (PORTAINER_KEY, SONARR_KEY), et
    autant de secrets generables aussi (WIREGUARD_PRIVATE_KEY, APP_SECRET_KEY).
    Le nom ne tranche pas ; la declaration, si."""

    def _check(self, name, kind):
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "secrets.conf").write_text(
                f"[{name}]\nkind  = {kind}\ngroup = manual\n", encoding="utf-8")
            env = dict(os.environ, PYTHONPATH=str(root),
                       BV_SECRETS_CONF=str(Path(d) / "secrets.conf"),
                       BV_SECRETS_DIR=d, BV_CONFIG=str(Path(d) / "absent.ini"))
            r = subprocess.run(
                [sys.executable, "-c",
                 "from bvsecrets import Engine; print(chr(10).join(Engine().check()))"],
                env=env, cwd=d, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            return r.stdout

    def test_a_third_party_key_named_key_may_be_declared_apikey(self):
        self.assertNotIn("NAME/KIND", self._check("HOMEPAGE_VAR_PORTAINER_KEY", "apikey"))

    def test_a_name_carrying_api_still_forces_apikey(self):
        self.assertIn("NAME/KIND", self._check("JELLYFIN_API_KEY", "password"))

    def test_a_generatable_key_named_key_stays_free(self):
        self.assertNotIn("NAME/KIND", self._check("WIREGUARD_PRIVATE_KEY", "opaque"))


if __name__ == "__main__":
    unittest.main()


class TestFileInventoryIsComplete(unittest.TestCase):
    """La vue Fichiers ne montrait que les sinks `file:` et `envfile:`, soit 4
    entrees sur une machine qui en ecrit vingt. Les fichiers rendus sont
    l'essentiel de ce que l'outil pose sur le disque : les cacher donnait une
    vue faussement vide."""

    def _data(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from web.files import data
        return data()

    def test_rendered_files_are_listed(self):
        d = self._data()
        self.assertGreater(d["by_mode"]["entier"], 0,
                           "les fichiers ecrits en entier doivent apparaitre")

    def test_every_file_says_how_it_is_written(self):
        for f in self._data()["files"]:
            self.assertIn(f["mode"], ("entier", "cle"), f["path"])

    def test_a_rendered_entry_shows_a_real_path_not_a_service_name(self):
        for f in self._data()["files"]:
            if f["scheme"] == "env":
                self.assertTrue(f["path"].startswith("/"), f["path"])
                self.assertTrue(f["path"].endswith(".env"), f["path"])
                return

    def test_the_front_end_names_every_write_mode(self):
        js = (Path(__file__).resolve().parent.parent
              / "web" / "static" / "js" / "labels.js").read_text(encoding="utf-8")
        for mode in ("entier", "cle"):
            self.assertIn(f"{mode}:", js, f"{mode} absent de labels.js")


class TestAdoptHandlesStructuredConfigs(unittest.TestCase):
    """Adopter, c'est confier UN fichier a bv-secrets, quel que soit son format.
    Le limiter aux `.env` laissait de cote les toml/yaml/json/ini dans lesquels
    l'outil sait pourtant deja ecrire : la capacite d'ecriture existait, pas
    l'enumeration qui permet de s'en servir."""

    def _plan(self, name, body):
        import tempfile
        from bvsecrets import adopt
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / name
            p.write_text(body, encoding="utf-8")
            return adopt.scheme_for(p), adopt.plan_file(p)

    def test_toml(self):
        scheme, (props, ignored, _) = self._plan(
            "c.toml", 'host = "0.0.0.0"\nsessionSecret = "%s"\n' % ("a" * 64))
        self.assertEqual(scheme, "toml")
        self.assertEqual([p.key for p in props], ["sessionSecret"])
        self.assertIn("host", ignored)

    def test_json_nested_key_becomes_a_dotted_selector(self):
        scheme, (props, _, _) = self._plan(
            "c.json", '{"db": {"password": "hunter2hunter2", "host": "x"}}')
        self.assertEqual(scheme, "json")
        self.assertEqual([p.key for p in props], ["db.password"])

    def test_ini_selector_carries_its_section(self):
        scheme, (props, _, _) = self._plan(
            "c.ini", "[security]\nadmin_password = hunter2hunter2\nport = 3000\n")
        self.assertEqual(scheme, "ini")
        self.assertEqual([p.key for p in props], ["security.admin_password"])

    def test_yaml_nested_key(self):
        scheme, (props, _, _) = self._plan(
            "c.yaml", "server:\n  host: x\n  api_token: abcdef0123456789abcdef\n")
        self.assertEqual(scheme, "yaml")
        self.assertEqual([p.key for p in props], ["server.api_token"])

    def test_the_secret_name_never_carries_a_dot(self):
        """Un nom de section dans secrets.conf ne peut pas contenir de point ; le
        chemin sert de selecteur, pas de nom."""
        _s, (props, _, _) = self._plan(
            "c.json", '{"db": {"password": "hunter2hunter2"}}')
        self.assertNotIn(".", props[0].name)
        self.assertEqual(props[0].name, "DB_PASSWORD")

    def test_the_sink_scheme_follows_the_file(self):
        from bvsecrets import adopt
        self.assertTrue(adopt.sink_for("/a/c.toml", "x").startswith("toml:"))
        self.assertTrue(adopt.sink_for("/a/.env", "X").startswith("envfile:"))


class TestCamelCaseNamesAreRead(unittest.TestCase):
    """Les toml/json/yaml nomment en camelCase. Sans decoupage, `sessionSecret`
    ne rendait qu'un mot qui ne matchait aucun token : il n'etait detecte que
    parce que sa valeur etait longue, et un secret court serait passe au travers."""

    def test_a_camel_case_secret_is_detected_by_its_name(self):
        from bvsecrets.adopt import looks_secret
        self.assertTrue(looks_secret("sessionSecret", "court"))
        self.assertTrue(looks_secret("apiToken", "court"))
        self.assertTrue(looks_secret("dbPassword", "court"))

    def test_camel_case_config_keys_stay_ignored(self):
        from bvsecrets.adopt import looks_secret
        self.assertFalse(looks_secret("logLevel", "info"))
        self.assertFalse(looks_secret("maxRetries", "3"))
