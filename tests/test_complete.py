"""La completion du shell : ce qu'elle propose, et comment elle retrouve un nom."""
import unittest

from bvsecrets import complete


class TestMatching(unittest.TestCase):
    NAMES = {"HERMES_DASHBOARD_PASSWORD": "password @vps1", "PIHOLE_ADMIN_PASSWORD": "password",
             "DASH": "hex"}

    def test_a_prefix_wins_over_a_fragment(self):
        self.assertEqual(list(complete.matching(self.NAMES, "DASH")), ["DASH"])

    def test_a_fragment_finds_the_name_whatever_the_case(self):
        self.assertEqual(list(complete.matching(self.NAMES, "dashb")), ["HERMES_DASHBOARD_PASSWORD"])
        self.assertEqual(list(complete.matching(self.NAMES, "admin")), ["PIHOLE_ADMIN_PASSWORD"])

    def test_nothing_typed_offers_everything(self):
        self.assertEqual(len(complete.matching(self.NAMES, "")), 3)

    def test_the_scripts_call_the_hidden_command(self):
        for shell, script in complete.SCRIPTS.items():
            self.assertIn("bv-secrets __complete", script, shell)
        self.assertIn("compdef _bv_secrets bv-secrets", complete.SCRIPTS["zsh"])


class TestCandidates(unittest.TestCase):
    def setUp(self):
        from bvsecrets.cli import build_parser
        self.parser = build_parser()

    def offered(self, *words):
        return complete.candidates(self.parser, ["bv-secrets", *words], len(words))

    def test_subcommands_come_first(self):
        self.assertIn("rotate", self.offered(""))
        self.assertNotIn("__complete", self.offered(""))

    def test_a_shell_is_offered_after_completion(self):
        self.assertEqual(sorted(self.offered("completion", "")), ["bash", "zsh"])

    def test_flags_are_offered_after_a_dash(self):
        self.assertIn("--deploy", self.offered("hosts", "-"))


if __name__ == "__main__":
    unittest.main()
