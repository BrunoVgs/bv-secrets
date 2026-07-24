"""Precedence de configuration : env > fichier projet > defaut. C'est ce qui
permet a Docker (env) de surcharger un bv-secrets.ini committe, et a une machine
nue de tourner sur les defauts."""
import os
import unittest

from bvsecrets import config


class TestPrecedence(unittest.TestCase):
    def setUp(self):
        self._file = dict(config._FILE)
        self._env = os.environ.pop("BV_COMPOSE_DIR", None)

    def tearDown(self):
        config._FILE = self._file
        os.environ.pop("BV_COMPOSE_DIR", None)
        if self._env is not None:
            os.environ["BV_COMPOSE_DIR"] = self._env

    def test_default_when_nothing_set(self):
        config._FILE = {}
        self.assertEqual(config._setting("BV_COMPOSE_DIR", "DEFAULT"), "DEFAULT")

    def test_file_overrides_default(self):
        config._FILE = {"compose_dir": "/from/file"}
        self.assertEqual(config._setting("BV_COMPOSE_DIR", "DEFAULT"), "/from/file")

    def test_env_overrides_file(self):
        config._FILE = {"compose_dir": "/from/file"}
        os.environ["BV_COMPOSE_DIR"] = "/from/env"
        self.assertEqual(config._setting("BV_COMPOSE_DIR", "DEFAULT"), "/from/env")

    def test_empty_env_string_wins_over_file(self):
        # An explicitly empty env var disables a feature; it must not fall through
        # to the file value.
        config._FILE = {"auth_service": "app"}
        os.environ["BV_COMPOSE_DIR"] = ""
        self.assertEqual(config._setting("BV_COMPOSE_DIR", "DEFAULT"), "")

    def test_file_key_is_env_name_without_bv_prefix(self):
        config._FILE = {"roles": "a,b,c"}
        self.assertEqual(config._setting("BV_ROLES", "x"), "a,b,c")


class TestApikeyHeuristic(unittest.TestCase):
    def test_detects_api_and_token_names(self):
        self.assertTrue(config.looks_like_apikey("MEDIA_API_KEY"))
        self.assertTrue(config.looks_like_apikey("GH_TOKEN"))
        self.assertTrue(config.looks_like_apikey("API_SECRET"))

    def test_ignores_plain_names(self):
        self.assertFalse(config.looks_like_apikey("DB_PASSWORD"))
        self.assertFalse(config.looks_like_apikey("CAPITALIZATION"))


if __name__ == "__main__":
    unittest.main()
