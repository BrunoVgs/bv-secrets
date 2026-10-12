import collections
import gzip
import json
import os
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

from bvsecrets import audit


def _line(ts, user, host="secrets.bv-servers.dev", status=200, ip="10.0.0.9"):
    return json.dumps({"ts": ts, "status": status,
                       "request": {"host": host, "uri": "/page", "remote_ip": ip,
                                   "headers": {"X-Auth-User": [user] if user else []}}}) + "\n"


class TestDigestAccess(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "access.log").write_text(_line(300, "bv"))
        self.rolled = self.dir / "access-2026-10-09T00-00-00.000-size.log.gz"
        self.write_gz(self.rolled, _line(100, "bv") + _line(200, "bv")
                      + _line(150, "", host="www.bv-servers.dev", ip="203.0.113.7")
                      + _line(160, "", status=403, ip="203.0.113.8"))
        self.reads = collections.Counter()
        real = audit._read_caddy

        def counting(path):
            self.reads[path.name] += 1
            return real(path)

        audit._ROLLED.clear()
        self.patches = [mock.patch.object(audit, "CADDY_LOG_DIR", self.dir),
                        mock.patch.object(audit, "_read_caddy", counting),
                        mock.patch.object(audit, "_service_roles",
                                          return_value={"secrets": ["admin"]})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        audit._ROLLED.clear()
        self.tmp.cleanup()

    @staticmethod
    def write_gz(path, text):
        with gzip.open(path, "wt") as f:
            f.write(text)
        now = time.time()
        os.utime(path, (now, now))

    def triples(self, since=0.0):
        return sorted((e["actor"], e["target"], e["outcome"], e["ts"])
                      for e in audit._digest_access(since))

    def test_a_rolled_log_is_read_once_the_live_log_every_time(self):
        self.triples()
        self.triples()
        self.assertEqual(self.reads[self.rolled.name], 1)
        self.assertEqual(self.reads["access.log"], 2)

    def test_rolled_log_keeps_the_latest_of_each_triple(self):
        rows = [t for t in self.triples() if t[3] < 300]
        self.assertIn(("bv", "secrets", "allow", 200.0), rows)
        self.assertNotIn(("bv", "secrets", "allow", 100.0), rows)

    def test_denials_stay_and_ungated_allows_go(self):
        rows = self.triples()
        self.assertIn(("203.0.113.8", "secrets", "deny", 160.0), rows)
        self.assertFalse([t for t in rows if t[1] == "www"])

    def test_since_applies_to_the_cached_reduction(self):
        self.triples()
        self.assertEqual([t[3] for t in self.triples(since=250)], [300.0])

    def test_a_new_rotation_is_read_and_a_vanished_one_evicted(self):
        self.triples()
        newer = self.dir / "access-2026-10-10T00-00-00.000-size.log.gz"
        self.write_gz(newer, _line(250, "alice"))
        self.rolled.unlink()
        rows = self.triples()
        self.assertIn(("alice", "secrets", "allow", 250.0), rows)
        self.assertEqual([k[0] for k in audit._ROLLED], [str(newer)])

    def test_digest_matches_the_uncached_reading(self):
        cached = {(t[0], t[1], t[2]): t[3] for t in self.triples()}
        raw = {}
        for e in audit.caddy_events(0.0):
            if e["outcome"] != "deny" and e["target"] != "secrets":
                continue
            k = (e["actor"], e["target"], e["outcome"])
            raw[k] = max(raw.get(k, 0), e["ts"])
        self.assertEqual(raw, cached)


if __name__ == "__main__":
    unittest.main()
