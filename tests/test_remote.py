"""Deux instances, pour de vrai : l'une pousse une valeur, l'autre l'applique.

Le worker distant est le MEME worker. L'ecouteur HTTP authentifie l'appelant et
depose le job dans le spool local ; la boucle le draine comme n'importe quel job
du dashboard. Ce test monte les deux bouts et verifie que la valeur atterrit dans
le fichier declare par l'hote distant -- jamais par celui qui pousse.

Aucun docker : le sink est un `envfile:`, donc rien ne demande de recreer un
service, et la suite reste portable sur les trois distributions de la CI.
"""
import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEY = "clef-de-test-partagee-entre-les-deux-instances"
BOOT_TIMEOUT = 20
JOB_TIMEOUT = 30


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TwoInstances(unittest.TestCase):
    """`agent` applique ses propres sinks ; `control` ne connait que la valeur."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.port = free_port()

        # ---- l'agent : son store, ses declarations, son worker ----
        self.agent_store = base / "agent-store"
        self.agent_store.mkdir()
        self.target = base / "app.env"
        self.target.write_text("APP_SECRET=ancienne\nAUTRE=garde\n")
        self.agent_conf = base / "agent.conf"
        self.agent_conf.write_text(
            "[APP_SECRET]\nkind = password\nlength = 16\n"
            f"sinks =\n    envfile:{self.target}#APP_SECRET\n")

        self.agent_env = {
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "BV_SECRETS_DIR": str(self.agent_store),
            "BV_SECRETS_CONF": str(self.agent_conf),
            "BV_WORKER_BIND": "127.0.0.1",
            "BV_WORKER_PORT": str(self.port),
            "BV_WORKER_KEY": KEY,
            # Bas exprès : un blocage se teste en trois échecs, pas en dix.
            "BV_WORKER_MAX_FAILS": "3",
            "BV_WORKER_BLOCK_SECONDS": "60",
            "NO_COLOR": "1",
        }
        self.worker = subprocess.Popen(
            [sys.executable, "-m", "bvsecrets.worker"], env=self.agent_env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self._wait_until_up()

        # ---- le plan de controle : il ne declare PAS de sink ----
        self.control_store = base / "control-store"
        self.control_store.mkdir()
        self.control_conf = base / "control.conf"
        self.control_conf.write_text(
            "[APP_SECRET]\nkind = password\nlength = 16\nhost = agent\n")
        (self.control_store / "bv-secrets.env").write_text("APP_SECRET=valeur-poussee\n")
        self.control_ini = base / "bv-secrets.ini"
        self.control_ini.write_text(
            f"[bv-secrets]\n\n[hosts]\nagent = http://127.0.0.1:{self.port}\n")
        self.control_env = {
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "BV_SECRETS_DIR": str(self.control_store),
            "BV_SECRETS_CONF": str(self.control_conf),
            "BV_CONFIG": str(self.control_ini),
            "BV_HOST_KEY_AGENT": KEY,
            "NO_COLOR": "1",
        }

    def tearDown(self):
        self.worker.terminate()
        try:
            self.worker.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.worker.kill()
            self.worker.wait(timeout=5)
        if self.worker.stdout:
            self.worker.stdout.close()
        self.tmp.cleanup()

    # ---- outils ----
    def _wait_until_up(self):
        deadline = time.time() + BOOT_TIMEOUT
        while time.time() < deadline:
            if self.worker.poll() is not None:
                self.fail(f"worker mort au démarrage:\n{self.worker.stdout.read()}")
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{self.port}/v1/health", timeout=1) as r:
                    if json.loads(r.read().decode())["ok"]:
                        return
            except (urllib.error.URLError, OSError, ValueError):
                time.sleep(0.2)
        self.fail("l'écouteur du worker n'a jamais répondu")

    @staticmethod
    def _auth(method, path, body, key):
        """Les en-tetes signes, ou rien du tout si on veut tester l'absence."""
        from bvsecrets import sign
        return sign.headers(key, method, path, body) if key else {}

    def _get(self, path, key=KEY, headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        for name, value in (self._auth("GET", path, b"", key)
                            if headers is None else headers).items():
            req.add_header(name, value)
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())

    def _post(self, payload, key=KEY, headers=None):
        body = json.dumps(payload).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/jobs",
                                     data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        for name, value in (self._auth("POST", "/v1/jobs", body, key)
                            if headers is None else headers).items():
            req.add_header(name, value)
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())

    def control(self, *args):
        return subprocess.run([sys.executable, "-m", "bvsecrets.cli", *args],
                              env=self.control_env, capture_output=True, text=True)

    def env_value(self):
        from bvsecrets.envfile import parse_env
        return parse_env(self.target)

    # ---- la porte d'entree ----
    def test_no_key_is_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post({"action": "apply", "only": ["APP_SECRET"]}, key=None)
        self.assertEqual(cm.exception.code, 401)

    def test_a_wrong_key_is_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post({"action": "apply"}, key="pas-la-bonne")
        self.assertEqual(cm.exception.code, 401)

    def test_an_action_outside_the_whitelist_is_refused(self):
        # les comptes et l'adoption appartiennent au dashboard LOCAL de la machine
        for action in ("user", "adopt", "reveal", "n-importe-quoi"):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                self._post({"action": action})
            self.assertEqual(cm.exception.code, 403, action)

    def test_a_captured_request_cannot_be_replayed(self):
        """Le coeur de la signature : les MEMES en-tetes deux fois. Un porteur
        passerait indefiniment, une requete signee ne vaut qu'une fois."""
        from bvsecrets import sign
        body = json.dumps({"action": "doctor", "only": []}).encode()
        captured = sign.headers(KEY, "POST", "/v1/jobs", body)
        status, _ = self._post({"action": "doctor", "only": []}, headers=captured)
        self.assertEqual(status, 202)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post({"action": "doctor", "only": []}, headers=captured)
        self.assertEqual(cm.exception.code, 401)

    def test_a_tampered_body_breaks_the_signature(self):
        from bvsecrets import sign
        body = json.dumps({"action": "doctor", "only": []}).encode()
        headers = sign.headers(KEY, "POST", "/v1/jobs", body)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            # signature valide, mais pour un AUTRE corps
            self._post({"action": "rotate", "only": ["APP_SECRET"]}, headers=headers)
        self.assertEqual(cm.exception.code, 401)

    def test_repeated_failures_block_the_source(self):
        """Trois echecs (BV_WORKER_MAX_FAILS) et la source est ecartee : deviner
        une cle devient impraticable sans jamais gener une instance legitime,
        qui ne produit aucun echec."""
        for _ in range(3):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                self._post({"action": "doctor"}, key="pas-la-bonne")
            self.assertEqual(cm.exception.code, 401)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._post({"action": "doctor"}, key=KEY)   # même la BONNE clé
        self.assertEqual(cm.exception.code, 429)

    def test_health_reveals_only_liveness_and_the_clock_without_the_key(self):
        """L'heure est publiee sans signature EXPRES : elle n'est pas secrete, et
        sans elle un ecart d'horloge se presente comme une cle refusee. La
        version et la liste des actions, elles, attendent la signature."""
        _, anon = self._get("/v1/health", key=None)
        self.assertEqual(anon["ok"], True)
        self.assertIsInstance(anon["time"], int)
        self.assertNotIn("version", anon)
        self.assertNotIn("actions", anon)

    def test_a_signed_health_says_who_it_is(self):
        _, named = self._get("/v1/health")
        self.assertIn("version", named)
        self.assertIn("set_value", named["actions"])

    # ---- le chemin complet ----
    def test_a_value_pushed_from_the_control_plane_lands_in_the_agent_file(self):
        r = self.control("push", "--only", "APP_SECRET")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.env_value().get("APP_SECRET"), "valeur-poussee")
        self.assertEqual(self.env_value().get("AUTRE"), "garde")

    def test_the_value_never_appears_in_the_worker_log(self):
        self.control("push", "--only", "APP_SECRET")
        _, res = self._wait_job()
        self.assertNotIn("valeur-poussee", json.dumps(res))

    def test_pushing_twice_changes_nothing_the_second_time(self):
        self.control("push", "--only", "APP_SECRET")
        stamp = self.target.stat().st_mtime_ns
        r = self.control("push", "--only", "APP_SECRET")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("déjà en place", r.stdout)
        self.assertEqual(self.target.stat().st_mtime_ns, stamp)

    def test_the_agent_refuses_a_secret_it_does_not_declare(self):
        _, out = self._post({"action": "set_value", "name": "INCONNU", "value": "x"})
        jid = out["id"]
        res = self._poll(jid)
        self.assertEqual(res["status"], "error")
        self.assertTrue(any("non déclaré" in l for l in res["log"]), res["log"])

    # ---- ce que le dashboard affiche ----
    def _control_python(self, code):
        """Execute du python avec l'environnement du plan de controle : la config
        des hotes est lue a l'import, elle ne peut pas etre posee apres coup."""
        r = subprocess.run([sys.executable, "-c", code],
                           env=self.control_env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return json.loads(r.stdout)

    def test_the_dashboard_lists_the_host_without_touching_the_network(self):
        out = self._control_python(
            "import json;from web import hostsview;print(json.dumps(hostsview.data()))")
        self.assertEqual([h["name"] for h in out["hosts"]], ["agent"])
        self.assertTrue(out["hosts"][0]["hasKey"])
        self.assertEqual(out["hosts"][0]["secrets"], ["APP_SECRET"])
        self.assertEqual(out["orphans"], [])

    def test_the_dashboard_probe_reports_a_reachable_host(self):
        out = self._control_python(
            "import json;from web import hostsview;print(json.dumps(hostsview.probe('agent')))")
        self.assertEqual(out["state"], "ok")
        self.assertIn("set_value", out["actions"])

    def test_the_dashboard_probe_names_a_key_mismatch(self):
        env = dict(self.control_env, BV_HOST_KEY_AGENT="pas-la-bonne")
        r = subprocess.run(
            [sys.executable, "-c",
             "import json;from web import hostsview;print(json.dumps(hostsview.probe('agent')))"],
            env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        # joignable mais cle refusee : ca ne se repare pas comme une machine morte
        self.assertEqual(json.loads(r.stdout)["state"], "badkey")

    def test_an_undeclared_host_is_named_as_such(self):
        out = self._control_python(
            "import json;from web import hostsview;print(json.dumps(hostsview.probe('nsp')))")
        self.assertEqual(out["state"], "unknown")

    # ---- attente d'un job ----
    def _poll(self, jid):
        deadline = time.time() + JOB_TIMEOUT
        while time.time() < deadline:
            _, res = self._get(f"/v1/jobs/{jid}")
            if res.get("status") in ("done", "error"):
                return res
            time.sleep(0.3)
        self.fail(f"job {jid} jamais terminé")

    def _wait_job(self):
        deadline = time.time() + JOB_TIMEOUT
        while time.time() < deadline:
            results = sorted((self.agent_store / "spool" / "results").glob("*.json"))
            if results:
                return results[-1], json.loads(results[-1].read_text())
            time.sleep(0.3)
        self.fail("aucun résultat de job")


class WorkerSurvivesAnUnreachableBind(unittest.TestCase):
    """Au boot, le worker demarre avant que wg0 soit montee : l'adresse d'ecoute
    n'existe pas encore. Lever la ferait mourir le worker, qui a un autre travail
    -- drainer le spool local -- et la machine resterait muette jusqu'a une
    intervention manuelle. Il doit tourner quand meme, et se lier plus tard."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.store = base / "store"
        self.store.mkdir()
        conf = base / "s.conf"
        conf.write_text("[APP_SECRET]\nkind = password\nlength = 16\n")
        self.worker = subprocess.Popen(
            [sys.executable, "-m", "bvsecrets.worker"],
            env={**os.environ, "PYTHONPATH": str(ROOT),
                 "BV_SECRETS_DIR": str(self.store), "BV_SECRETS_CONF": str(conf),
                 # 203.0.113.0/24 est reserve a la documentation (RFC 5737) :
                 # cette adresse ne peut appartenir a aucune interface locale.
                 "BV_WORKER_BIND": "203.0.113.1", "BV_WORKER_PORT": "8765",
                 "BV_WORKER_KEY": KEY, "NO_COLOR": "1"},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def tearDown(self):
        self.worker.terminate()
        try:
            self.worker.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.worker.kill()
            self.worker.wait(timeout=5)
        if self.worker.stdout:
            self.worker.stdout.close()
        self.tmp.cleanup()

    def test_the_worker_stays_alive_and_drains_its_spool(self):
        from bvsecrets import spool
        requests = self.store / "spool" / "requests"
        deadline = time.time() + 20
        while not requests.is_dir() and time.time() < deadline:
            time.sleep(0.3)
        self.assertIsNone(self.worker.poll(), "le worker est mort au démarrage")

        jid = "aaaaaaaaaaaaaaaa"
        (requests / f"{jid}.json").write_text(json.dumps(
            {"id": jid, "action": "doctor", "only": []}))
        results = self.store / "spool" / "results" / f"{jid}.json"
        while not results.exists() and time.time() < deadline:
            time.sleep(0.3)
        self.assertTrue(results.exists(), "le spool local n'a pas été drainé")
        self.assertIsNone(self.worker.poll())
