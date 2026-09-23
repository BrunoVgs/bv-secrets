"""La signature des requetes entre instances, sans reseau.

Ce qui compte n'est pas qu'une bonne cle passe -- c'est que tout le reste soit
refuse : une requete rejouee, un corps modifie apres coup, une methode ou un
chemin changes, une horloge trop decalee. Chacun de ces cas a son test, parce
qu'ils se cassent independamment.
"""
import threading
import time
import unittest

from bvsecrets import sign

KEY = "clef-partagee"


def headers_for(method="POST", path="/v1/jobs", body=b"{}", key=KEY):
    return sign.headers(key, method, path, body)


def verify(headers, method="POST", path="/v1/jobs", body=b"{}", key=KEY,
           guard=None, skew=300):
    return sign.verify(key, method, path, headers.get, body,
                       guard or sign.ReplayGuard(skew), skew)


class TestSignature(unittest.TestCase):
    def test_a_fresh_request_passes(self):
        ok, reason = verify(headers_for())
        self.assertTrue(ok, reason)

    def test_the_key_never_travels(self):
        joined = " ".join(headers_for().values())
        self.assertNotIn(KEY, joined)

    def test_another_key_is_refused(self):
        ok, _ = verify(headers_for(key="autre"))
        self.assertFalse(ok)

    def test_a_modified_body_is_refused(self):
        ok, reason = verify(headers_for(body=b"{}"), body=b'{"action":"rotate"}')
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_a_moved_path_is_refused(self):
        # la signature couvre le chemin : un job signe pour /v1/jobs ne vaut
        # pas pour une autre route
        ok, _ = verify(headers_for(path="/v1/jobs"), path="/v1/health")
        self.assertFalse(ok)

    def test_a_changed_method_is_refused(self):
        ok, _ = verify(headers_for(method="GET"), method="POST")
        self.assertFalse(ok)

    def test_an_old_request_is_refused(self):
        headers = headers_for()
        headers[sign.TS_HEADER] = str(int(time.time()) - 1000)
        ok, reason = verify(headers)
        self.assertFalse(ok)
        self.assertIn("fenêtre", reason)

    def test_a_missing_scheme_is_refused(self):
        headers = headers_for()
        headers["Authorization"] = "Bearer " + KEY
        ok, reason = verify(headers)
        self.assertFalse(ok)
        self.assertIn("schéma", reason)

    def test_no_key_configured_refuses_everyone(self):
        # sans cle, l'ecouteur ne doit accepter personne, pas tout le monde
        ok, _ = sign.verify("", "POST", "/v1/jobs", headers_for().get, b"{}",
                            sign.ReplayGuard(300), 300)
        self.assertFalse(ok)


class TestReplayGuard(unittest.TestCase):
    def test_the_same_request_twice_is_refused(self):
        guard = sign.ReplayGuard(300)
        headers = headers_for()
        self.assertTrue(verify(headers, guard=guard)[0])
        ok, reason = verify(headers, guard=guard)
        self.assertFalse(ok)
        self.assertIn("rejeu", reason)

    def test_a_bad_signature_does_not_consume_the_nonce(self):
        """Sinon n'importe qui sature la memoire des nonces sans connaitre la
        cle -- et peut invalider d'avance un nonce qu'il a vu passer."""
        guard = sign.ReplayGuard(300)
        headers = headers_for()
        verify(headers, body=b"autre chose", guard=guard)   # refuse
        self.assertTrue(verify(headers, guard=guard)[0])     # toujours valable

    def test_expired_nonces_are_dropped(self):
        guard = sign.ReplayGuard(10)
        guard.remember("n1", 1000)
        guard.remember("n2", 1000)
        guard.remember("n3", 2000)          # bien apres l'expiration des deux
        self.assertNotIn("n1", guard.seen)
        self.assertIn("n3", guard.seen)


class TestRateLimiter(unittest.TestCase):
    def test_failures_below_the_bar_do_not_block(self):
        limiter = sign.RateLimiter(3, 60)
        for _ in range(2):
            self.assertFalse(limiter.record_failure("10.8.0.4", now=1000))
        self.assertEqual(limiter.blocked_for("10.8.0.4", now=1000), 0)

    def test_the_bar_blocks_for_the_whole_window(self):
        limiter = sign.RateLimiter(3, 60)
        for _ in range(3):
            last = limiter.record_failure("10.8.0.4", now=1000)
        self.assertTrue(last)
        self.assertEqual(limiter.blocked_for("10.8.0.4", now=1000), 60)
        self.assertEqual(limiter.blocked_for("10.8.0.4", now=1061), 0)

    def test_a_success_clears_the_tally(self):
        """Une instance legitime qui pousse cinquante secrets ne doit jamais
        approcher la barre : seuls les ECHECS comptent, et un succes remet a zero."""
        limiter = sign.RateLimiter(3, 60)
        limiter.record_failure("10.8.0.4", now=1000)
        limiter.record_failure("10.8.0.4", now=1000)
        limiter.record_success("10.8.0.4")
        self.assertFalse(limiter.record_failure("10.8.0.4", now=1000))

    def test_sources_are_counted_apart(self):
        limiter = sign.RateLimiter(2, 60)
        limiter.record_failure("10.8.0.4", now=1000)
        limiter.record_failure("10.8.0.4", now=1000)
        self.assertTrue(limiter.blocked_for("10.8.0.4", now=1000))
        self.assertEqual(limiter.blocked_for("10.8.0.5", now=1000), 0)


class TestGuardsUnderConcurrency(unittest.TestCase):
    """L'ecouteur est un ThreadingHTTPServer : ces deux structures sont touchees
    par plusieurs threads a la fois. Un compteur qui perd des increments est
    ennuyeux ; un anti-rejeu qui accepte deux fois le meme nonce ne sert a rien."""

    def test_only_one_thread_wins_the_same_nonce(self):
        guard = sign.ReplayGuard(300)
        wins, start = [], threading.Barrier(16)

        def race():
            start.wait()
            if guard.remember("le-meme-nonce", 1000):
                wins.append(1)

        threads = [threading.Thread(target=race) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(wins), 1)

    def test_no_failure_is_lost(self):
        limiter = sign.RateLimiter(1000, 60)   # barre hors d'atteinte : on compte
        start = threading.Barrier(16)

        def race():
            start.wait()
            for _ in range(20):
                limiter.record_failure("10.8.0.4", now=1000)

        threads = [threading.Thread(target=race) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(limiter.fails["10.8.0.4"]), 16 * 20)


class TestProbeTellsClockFromKey(unittest.TestCase):
    """Un ecart d'horloge met la signature hors fenetre, donc un hote a l'heure
    fausse repond exactement comme un hote dont la cle differe. Les confondre
    envoie chercher une cle pendant des heures au lieu de regarder ntpd."""

    def setUp(self):
        from bvsecrets import hosts, remote
        self.remote, self.hosts = remote, hosts
        self._names, self._health = hosts.names, remote.health
        hosts.names = lambda: ["agent"]

    def tearDown(self):
        self.hosts.names, self.remote.health = self._names, self._health

    def _probe_with(self, payload):
        self.remote.health = lambda host: payload
        return self.remote.probe("agent")

    def test_a_large_skew_is_reported_as_a_clock_problem(self):
        from bvsecrets.config import WORKER_SKEW
        far = int(time.time()) - (WORKER_SKEW + 600)
        result = self._probe_with({"ok": True, "time": far})
        self.assertEqual(result["state"], "clock")
        self.assertIn("horloge", result["detail"])

    def test_a_good_clock_without_version_is_a_key_problem(self):
        result = self._probe_with({"ok": True, "time": int(time.time())})
        self.assertEqual(result["state"], "badkey")

    def test_a_reachable_host_reports_its_version(self):
        result = self._probe_with({"ok": True, "time": int(time.time()),
                                   "version": "1.1.1", "actions": ["set_value"]})
        self.assertEqual(result["state"], "ok")
        self.assertIn("1.1.1", result["detail"])

    def test_an_old_agent_without_time_still_works(self):
        # compatibilite : un hote qui ne publie pas encore son heure
        result = self._probe_with({"ok": True, "version": "1.1.1"})
        self.assertEqual(result["state"], "ok")
        self.assertIsNone(result["skew"])
