import re
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path

from bvsecrets import engine


@unittest.skipUnless(shutil.which("openssl"), "openssl absent")
class TestSeal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.key, self.mirror = d / ".masterkey", d / "store.enc"
        master = d / "bv-secrets.env"
        master.write_text("SAMPLE_TOKEN=abc123\n")
        self.patches = [mock.patch.object(engine, "KEYFILE", self.key),
                        mock.patch.object(engine, "MIRROR", self.mirror),
                        mock.patch.object(engine, "MASTER", master),
                        mock.patch.object(engine, "LOCAL", d / "absent.local")]
        for p in self.patches:
            p.start()
        self.engine = types.SimpleNamespace(_run=lambda argv, inp=None, cwd=None:
                                            subprocess.run(argv, input=inp, capture_output=True))

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def seal(self):
        engine.Engine.seal(self.engine, quiet=True)

    def opened(self):
        return subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                               "-pass", f"file:{self.key}", "-in", str(self.mirror)],
                              capture_output=True, text=True).stdout

    def test_a_new_key_is_one_full_line_of_hex(self):
        self.seal()
        self.assertRegex(self.key.read_text(), r"^[0-9a-f]{64}\n$")

    def test_a_new_key_is_private_from_creation(self):
        self.seal()
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)

    def test_the_mirror_opens_with_the_key(self):
        self.seal()
        self.assertIn("SAMPLE_TOKEN=abc123", self.opened())

    def test_an_existing_key_is_kept(self):
        self.key.write_bytes(b"\x01\x02existing-key")
        self.key.chmod(0o600)
        self.seal()
        self.assertEqual(self.key.read_bytes(), b"\x01\x02existing-key")
        self.assertIn("SAMPLE_TOKEN=abc123", self.opened())


if __name__ == "__main__":
    unittest.main()
