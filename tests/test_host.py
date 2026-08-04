import unittest
from pathlib import Path
from unittest import mock

from bvsecrets import host
from bvsecrets.config import ConfigError


class TestAuditRules(unittest.TestCase):
    def test_the_syscall_rule_catches_what_a_watch_cannot(self):
        """Une surveillance de binaire rate l'appelant qui n'est pas nomme :
        c'est la regle execve/uid!=euid qui attrape le reste."""
        text, _ = host.audit_rules({"trace": ["execve-setuid"]}, key="k")
        self.assertIn("-S execve -C uid!=euid -F euid=0 -k k", text)

    def test_a_binary_absent_from_the_box_is_reported_not_written(self):
        """Une regle posee sur un chemin inexistant est acceptee par auditd et ne
        declenche jamais : elle donnerait une trace vide qu'on croit complete."""
        with mock.patch.object(host.shutil, "which", lambda b: None):
            text, warn = host.audit_rules({"trace": ["sudo", "doas"]})
        self.assertNotIn("-w ", text)
        self.assertEqual(len(warn), 2)
        self.assertIn("sudo", warn[0])

    def test_the_real_path_is_used_not_the_conventional_one(self):
        # su est bbsuid sur Alpine ; ecrire /bin/su ne tracerait rien
        with mock.patch.object(host.shutil, "which", lambda b: "/bin/busybox"):
            text, _ = host.audit_rules({"trace": ["su"]}, key="k")
        self.assertIn("-p x -k k", text)
        self.assertNotIn("-w /bin/su ", text)

    def test_an_unknown_trace_name_is_refused(self):
        with self.assertRaises(ConfigError) as cm:
            host.audit_rules({"trace": ["sudo", "tcpdump"]})
        self.assertIn("tcpdump", str(cm.exception))

    def test_an_empty_spec_falls_back_to_the_full_trace(self):
        with mock.patch.object(host.shutil, "which", lambda b: f"/usr/bin/{b}"):
            text, _ = host.audit_rules({})
        for tool in ("sudo", "doas", "su"):
            self.assertIn(f"/usr/bin/{tool}", text)


class TestEgress(unittest.TestCase):
    def test_a_zone_yields_one_command(self):
        cmds = host.egress_commands({"osint": {"subnet": "172.31.9.0/24"}})
        self.assertEqual(len(cmds), 1)
        self.assertIn("172.31.9.0/24", cmds[0]["cmd"])

    def test_the_default_block_list_covers_lan_tunnel_and_link_local(self):
        z = host.egress_commands({"z": {"subnet": "172.31.9.0/24"}})[0]
        self.assertIn("192.168.0.0/16", z["block"])
        self.assertIn("10.0.0.0/8", z["block"])       # le tunnel WireGuard y est
        self.assertIn("169.254.0.0/16", z["block"])

    def test_a_subnet_that_is_not_a_cidr_is_refused(self):
        """Une regle iptables sur `172.22.0.1` ne protege qu'une IP : le declarer
        ainsi donnerait un cloisonnement decoratif."""
        with self.assertRaises(ConfigError) as cm:
            host.egress_commands({"z": {"subnet": "172.22.0.1"}})
        self.assertIn("CIDR", str(cm.exception))

    def test_a_missing_subnet_is_refused(self):
        with self.assertRaises(ConfigError):
            host.egress_commands({"z": {"block": ["10.0.0.0/8"]}})


class TestDiffIsHonest(unittest.TestCase):
    """Trois etats, pas deux. Confondre « je ne peux pas verifier » avec
    « conforme » est exactement le defaut qui rendrait cette commande nuisible."""

    def _plan(self, rules="X\n", target=Path("/nowhere/nope.rules")):
        return {"rules": rules, "rules_target": target,
                "rules_staged": Path("/tmp/x"), "warnings": [], "egress": []}

    def test_absent_target_is_its_own_state(self):
        state, msg = host.diff(self._plan())
        self.assertEqual(state, "absent")
        self.assertIn("aucune trace", msg)

    def test_identical_content_is_ok(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".rules", delete=False) as f:
            f.write("X\n")
        state, _ = host.diff(self._plan(target=Path(f.name)))
        self.assertEqual(state, "ok")

    def test_different_content_is_drift(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".rules", delete=False) as f:
            f.write("AUTRE\n")
        state, _ = host.diff(self._plan(target=Path(f.name)))
        self.assertEqual(state, "drift")

    def test_unreadable_target_is_not_reported_as_conforming(self):
        p = self._plan()

        class Boom(Path):
            def read_text(self, *a, **k):
                raise PermissionError

        p["rules_target"] = Boom("/etc/audit/rules.d/x.rules")
        state, msg = host.diff(p)
        self.assertEqual(state, "unknown")
        self.assertIn("non verifiable", msg)




class TestPrintedCommandsRun(unittest.TestCase):
    """Une consigne qui nomme l'outil de l'autre distribution ne s'execute pas :
    le Xeon n'a pas `doas`, l'Alpine n'a pas `sudo`."""

    def test_it_names_the_tool_this_box_actually_has(self):
        with mock.patch.object(host.shutil, "which", lambda b: "/usr/bin/sudo" if b == "sudo" else None):
            self.assertEqual(host.privilege_tool(), "sudo")
        with mock.patch.object(host.shutil, "which", lambda b: "/usr/bin/doas" if b == "doas" else None):
            self.assertEqual(host.privilege_tool(), "doas")

    def test_the_egress_command_uses_it(self):
        with mock.patch.object(host.shutil, "which", lambda b: "/usr/bin/sudo" if b == "sudo" else None):
            cmd = host.egress_commands({"z": {"subnet": "172.22.0.0/16"}})[0]["cmd"]
        self.assertTrue(cmd.startswith("sudo "), cmd)


if __name__ == "__main__":
    unittest.main()
