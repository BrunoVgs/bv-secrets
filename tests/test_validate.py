"""Validation de forme : chaque regle accepte ce qui est conforme, rejette le
reste, et une regle vide ne contraint rien."""
import unittest

from bvsecrets import validate


class TestValidate(unittest.TestCase):
    def ok(self, rule, value):
        self.assertIsNone(validate.check(rule, value), f"{rule!r} devrait accepter {value!r}")

    def ko(self, rule, value):
        self.assertIsNotNone(validate.check(rule, value), f"{rule!r} devrait rejeter {value!r}")

    def test_empty_rule_accepts_anything(self):
        self.ok("", "whatever")
        self.ok(None, "whatever")

    def test_prefix_suffix(self):
        self.ok("prefix:sk_live_", "sk_live_abc")
        self.ko("prefix:sk_live_", "pk_test_abc")
        self.ok("suffix:.pem", "cert.pem")
        self.ko("suffix:.pem", "cert.key")

    def test_regex(self):
        self.ok("regex:^[0-9a-f]{8}$", "deadbeef")
        self.ko("regex:^[0-9a-f]{8}$", "nothex!!")

    def test_enum(self):
        self.ok("enum:dev,staging,prod", "prod")
        self.ko("enum:dev,staging,prod", "local")

    def test_url(self):
        self.ok("url", "https://example.com/x")
        self.ok("url", "postgres://u:p@host:5432/db")
        self.ko("url", "not a url")

    def test_len(self):
        self.ok("len:>=8", "abcdefgh")
        self.ko("len:>=8", "short")
        self.ok("len:16", "0123456789abcdef")
        self.ko("len:16", "tooshort")
        self.ok("len:8..12", "ninechars")
        self.ko("len:8..12", "x")

    def test_int(self):
        self.ok("int", "42")
        self.ko("int", "notanumber")
        self.ok("int:1..65535", "8080")
        self.ko("int:1..65535", "70000")
        self.ok("int:>0", "1")
        self.ko("int:>0", "0")

    def test_unknown_rule_is_error(self):
        self.ko("bogus:x", "value")

    def test_malformed_spec_is_error(self):
        self.ko("int:>=notanumber", "5")


if __name__ == "__main__":
    unittest.main()
