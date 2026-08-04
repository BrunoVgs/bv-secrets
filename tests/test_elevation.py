import os
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

from bvsecrets import elevation

# One real elevation as auditd writes it: three records sharing serial 4823.
AUDIT_SAMPLE = """\
type=DAEMON_START msg=audit(1782424500.001:1): op=start ver=3.1.2 res=successful
type=SYSCALL msg=audit(1782424574.123:4823): arch=c000003e syscall=59 success=yes exit=0 \
ppid=14401 pid=14822 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 tty=pts3 ses=5 \
comm="doas" exe="/usr/bin/doas" key="bv_elevation"
type=EXECVE msg=audit(1782424574.123:4823): argc=3 a0="doas" a1="micro" a2=2F6F70742F62762D736563726574732F7069686F6C652E656E76
type=PROCTITLE msg=audit(1782424574.123:4823): proctitle=646F617300
type=SYSCALL msg=audit(1782424999.500:4900): arch=c000003e syscall=59 success=no exit=-1 \
ppid=1 pid=15000 auid=1000 uid=1000 euid=0 tty=(none) comm="sudo" exe="/usr/bin/sudo" \
key="bv_elevation"
type=SYSCALL msg=audit(1782424600.000:4850): arch=c000003e syscall=59 success=yes exit=0 \
ppid=2 pid=2 auid=0 uid=0 euid=0 comm="cron" exe="/usr/sbin/cron" key="other_key"
"""

ZSH_SAMPLE = """\
: 1782424500:0;cd /opt/bv-secrets
: 1782424540:0;ls -la
: 1782424560:0;grep FTLCONF pihole.env
: 1782424700:0;docker compose up -d --force-recreate pihole
: 1782424800:0;docker logs pihole --tail 20
malformed line without timestamp
"""


class TestParsing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = Path(self.tmp.name) / "audit.log"
        self.audit.write_text(AUDIT_SAMPLE)
        self.zsh = Path(self.tmp.name) / ".zsh_history"
        self.zsh.write_text(ZSH_SAMPLE)

    def tearDown(self):
        self.tmp.cleanup()

    def rows(self, **kw):
        kw.setdefault("audit_log", self.audit)
        kw.setdefault("key", "bv_elevation")
        return elevation.elevations(**kw)

    def test_only_keyed_records_are_returned(self):
        # the cron record carries another key and must not appear
        self.assertEqual(len(self.rows()), 2)

    def test_records_are_ordered_oldest_first(self):
        rows = self.rows()
        self.assertLess(rows[0]["ts"], rows[1]["ts"])

    def test_identity_uses_loginuid_and_euid(self):
        r = self.rows()[0]
        self.assertEqual(r["uid"], "1000")
        self.assertEqual(r["euid"], "0")
        self.assertEqual(r["pid"], "14822")
        self.assertEqual(r["ppid"], "14401")
        self.assertEqual(r["tty"], "pts3")

    def test_hex_encoded_argument_is_decoded(self):
        # a2 is the hex form of the path; the report must show it readable
        self.assertIn("/opt/bv-secrets/pihole.env", self.rows()[0]["cmd"])
        self.assertTrue(self.rows()[0]["cmd"].startswith("doas micro"))

    def test_refused_elevation_is_kept_and_marked(self):
        refused = [r for r in self.rows() if r["success"] == "no"]
        self.assertEqual(len(refused), 1)
        self.assertIn("[REFUSE]", elevation.render(refused))

    def test_missing_audit_log_yields_nothing(self):
        self.assertEqual(self.rows(audit_log=Path(self.tmp.name) / "absent.log"), [])


class TestZshContext(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.zsh = Path(self.tmp.name) / ".zsh_history"
        self.zsh.write_text(ZSH_SAMPLE)

    def tearDown(self):
        self.tmp.cleanup()

    def test_window_splits_around_the_event(self):
        before, after = elevation._zsh_context(1782424574.123, 4, path=self.zsh)
        self.assertEqual([c["cmd"] for c in before],
                         ["cd /opt/bv-secrets", "ls -la", "grep FTLCONF pihole.env"])
        self.assertEqual([c["cmd"] for c in after],
                         ["docker compose up -d --force-recreate pihole",
                          "docker logs pihole --tail 20"])

    def test_window_is_honoured(self):
        before, _ = elevation._zsh_context(1782424574.123, 1, path=self.zsh)
        self.assertEqual(len(before), 1)
        self.assertEqual(before[0]["cmd"], "grep FTLCONF pihole.env")

    def test_untimestamped_lines_are_skipped(self):
        before, after = elevation._zsh_context(time.time(), 10, path=self.zsh)
        self.assertNotIn("malformed line without timestamp",
                         [c["cmd"] for c in before + after])

    def test_missing_history_is_not_fatal(self):
        self.assertEqual(elevation._zsh_context(0, 4, path="/nonexistent"), ([], []))


class TestRules(unittest.TestCase):
    def test_rules_cover_execve_and_the_three_tools(self):
        out = elevation.render_rules("k1")
        self.assertIn("-S execve -C uid!=euid -F euid=0 -k k1", out)
        for tool in ("/usr/bin/sudo", "/usr/bin/doas", "/bin/su"):
            self.assertIn(f"-w {tool} -p x -k k1", out)

    def test_key_is_substituted_everywhere(self):
        self.assertNotIn("{key}", elevation.render_rules("custom"))


class TestSourceError(unittest.TestCase):
    """A blind lens must say so instead of reporting an empty, reassuring result."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_absent_log_is_reported(self):
        err = elevation.source_error(Path(self.tmp.name) / "absent.log")
        self.assertIn("absent", err)

    def test_unreadable_directory_is_not_mistaken_for_missing_auditd(self):
        d = Path(self.tmp.name) / "audit"
        d.mkdir()
        (d / "audit.log").write_text("x")
        d.chmod(0o700 if os.getuid() == 0 else 0o600)   # 0600: present but not traversable
        try:
            err = elevation.source_error(d / "audit.log")
            if os.getuid() == 0:
                self.skipTest("root traverse tout, le cas ne se produit pas")
            self.assertIn("traversable", err)
            self.assertNotIn("pas installe", err)
        finally:
            d.chmod(0o700)

    def test_unreadable_log_names_the_group_fix(self):
        p = Path(self.tmp.name) / "audit.log"
        p.write_text("x")
        p.chmod(0o000)
        try:
            err = elevation.source_error(p)
            if os.getuid() == 0:
                self.skipTest("root lit tout, le cas ne se produit pas")
            self.assertIn("log_group", err)
        finally:
            p.chmod(0o600)

    def test_readable_log_reports_no_error(self):
        p = Path(self.tmp.name) / "audit.log"
        p.write_text("x")
        self.assertIsNone(elevation.source_error(p))


class TestRender(unittest.TestCase):
    def test_empty_report_points_at_the_likely_cause(self):
        out = elevation.render([])
        self.assertIn("auditctl -l", out)

    def test_unknown_context_is_rejected(self):
        with self.assertRaises(ValueError):
            elevation.elevations(context="nope")


if __name__ == "__main__":
    unittest.main()


class TestContextIsActuallyContext(unittest.TestCase):
    """Une commande a trois heures de l'elevation n'est pas son contexte. Sans
    borne temporelle, une elevation lancee par cron se voit entouree des
    dernieres commandes interactives et le rapport suggere une proximite qui
    n'existe pas -- ce qu'il est precisement cense etablir."""

    def test_rows_outside_the_window_are_dropped(self):
        ts = 1_000_000.0
        rows = [{"ts": ts - 30, "cmd": "proche"}, {"ts": ts - 7200, "cmd": "loin"}]
        kept = [r["cmd"] for r in elevation._near(rows, ts, max_gap=900)]
        self.assertEqual(kept, ["proche"])

    def test_a_row_without_a_timestamp_is_kept(self):
        kept = elevation._near([{"ts": None, "cmd": "x"}], 0.0, max_gap=1)
        self.assertEqual(len(kept), 1)

    def test_both_sides_are_bounded(self):
        ts = 1_000_000.0
        rows = [{"ts": ts + 60, "cmd": "apres proche"}, {"ts": ts + 9999, "cmd": "apres loin"}]
        self.assertEqual([r["cmd"] for r in elevation._near(rows, ts, max_gap=900)],
                         ["apres proche"])


class TestAtuinFailsLoudly(unittest.TestCase):
    """Un contexte vide affiche comme un contexte reel ferait croire qu'il ne
    s'est rien passe autour de l'elevation. Meme regle que la lentille aveugle."""

    def test_a_missing_atuin_is_reported_not_swallowed(self):
        with mock.patch.object(elevation.shutil, "which", lambda b: None):
            with self.assertRaises(elevation.AtuinUnavailable):
                elevation._atuin_context(0.0, 4)

    def test_no_result_is_not_a_failure(self):
        """atuin sort en code 1 quand la recherche ne trouve rien, ce qui arrive
        normalement pour la fenetre `apres` de l'elevation la plus recente."""
        class R:
            returncode, stdout, stderr = 1, "", ""
        with mock.patch.object(elevation.subprocess, "run", lambda *a, **k: R()):
            self.assertEqual(elevation._atuin_rows(["--limit", "1"]), [])

    def test_an_error_on_stderr_is_a_failure(self):
        class R:
            returncode, stdout = 1, ""
            stderr = "ERROR: Failed to find $ATUIN_SESSION in the environment.\n"
        with mock.patch.object(elevation.subprocess, "run", lambda *a, **k: R()):
            with self.assertRaises(elevation.AtuinUnavailable) as cm:
                elevation._atuin_rows(["--limit", "1"])
        self.assertIn("ATUIN_SESSION", str(cm.exception))

    def test_the_session_is_supplied_because_atuin_demands_it(self):
        seen = {}

        class R:
            returncode, stdout, stderr = 0, "", ""

        def fake(cmd, **kw):
            seen.update(kw.get("env") or {})
            return R()
        with mock.patch.object(elevation.subprocess, "run", fake):
            elevation._atuin_rows(["--limit", "1"])
        self.assertIn("ATUIN_SESSION", seen)
