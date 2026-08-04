import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PROBE = """
import sys
sys.path.insert(0, %r)
from bvsecrets.config import CONF, COMPOSE_DIR
print(CONF)
print(COMPOSE_DIR)
"""


def _resolve_from(cwd, **env):
    """Resolve CONF/COMPOSE_DIR in a fresh interpreter run from `cwd`."""
    e = dict(os.environ, **env)
    e.pop("BV_SECRETS_CONF", None)
    e.pop("BV_COMPOSE_DIR", None)
    e.update(env)
    out = subprocess.run([sys.executable, "-c", PROBE % str(ROOT)],
                         cwd=cwd, env=e, capture_output=True, text=True, check=True)
    conf, compose = out.stdout.strip().splitlines()
    return Path(conf), Path(compose)


class TestRelativeConfIsAnchored(unittest.TestCase):
    """The shipped INI declares `secrets_conf = secrets.conf`. A bare filename must
    not resolve against whatever directory the caller happens to stand in: `list`
    would read nothing and `adopt` would write a second config there."""

    def test_relative_setting_resolves_to_the_project(self):
        conf, _ = _resolve_from("/tmp", BV_SECRETS_CONF="secrets.conf")
        self.assertTrue(conf.is_absolute(), conf)
        self.assertEqual(conf, ROOT / "secrets.conf")

    def test_same_answer_from_any_directory(self):
        a, _ = _resolve_from("/tmp", BV_SECRETS_CONF="secrets.conf")
        b, _ = _resolve_from(str(ROOT), BV_SECRETS_CONF="secrets.conf")
        self.assertEqual(a, b)

    def test_compose_dir_stays_the_stack_root(self):
        # COMPOSE_DIR derives from CONF.parent.parent; a relative CONF made it "."
        _, compose = _resolve_from("/tmp", BV_SECRETS_CONF="secrets.conf")
        self.assertEqual(compose, ROOT.parent)

    def test_an_absolute_setting_is_left_alone(self):
        conf, _ = _resolve_from("/tmp", BV_SECRETS_CONF="/etc/bv/secrets.conf")
        self.assertEqual(conf, Path("/etc/bv/secrets.conf"))


if __name__ == "__main__":
    unittest.main()
