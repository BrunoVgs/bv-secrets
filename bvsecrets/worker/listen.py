"""Ecouteur HTTP du worker : une seconde source de jobs, rien de plus.

Le worker local est alimente par un repertoire de spool. Un worker distant est le
MEME worker, alimente par cet ecouteur, qui authentifie l'appelant puis depose le
job dans ce meme spool. Aucun code d'execution ici : la boucle le draine comme
n'importe quel job local, avec les memes privileges et le meme archivage. On
generalise le transport, pas le modele de securite.

L'ecouteur ne demarre que si `BV_WORKER_BIND` est pose -- et on l'attache a
l'adresse wg0 de la machine, jamais a 0.0.0.0.

Les requetes sont SIGNEES (voir `bvsecrets.sign`), pas porteuses d'un jeton : la
cle ne circule pas, et une requete capturee ne peut pas etre rejouee. Les echecs
d'authentification sont comptes par source et finissent par la bloquer.
"""
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import hosts, sign, spool
from ..config import (WORKER_BIND, WORKER_BLOCK_SECONDS, WORKER_MAX_FAILS,
                      WORKER_PORT, WORKER_SKEW)

VERSION = "1.1.1"
ID_RE = re.compile(r"^[0-9a-f]{16}$")
JOB_RE = re.compile(r"^/v1/jobs/([0-9a-zA-Z]+)$")
# Ce qu'une autre instance a le droit de demander. Le reste (comptes, acces,
# adoption, revelation de valeur) appartient au dashboard local de CETTE machine
# et n'a aucune raison de traverser le reseau. Liste blanche : une action
# inconnue est refusee, jamais transmise.
REMOTE_ACTIONS = {"set_value", "apply", "rotate", "doctor"}
MAX_BODY = 64 * 1024
# L'adresse d'ecoute est celle de wg0, et l'interface n'existe pas encore quand
# le worker demarre au boot. On reessaie au lieu d'abandonner -- et surtout au
# lieu de tuer le worker, qui a un autre travail que celui-ci.
BIND_RETRY_SECONDS = 15


class Handler(BaseHTTPRequestHandler):
    server_version = "bv-secrets"
    sys_version = ""

    def log_message(self, fmt, *args):
        """Une ligne par requete sur stderr, sans corps : un job `set_value`
        porte une valeur en clair et ne doit jamais atterrir dans un log."""
        self.server.emit(f"{self.address_string()} {fmt % args}")

    # ---- primitives ----
    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        """-> les octets du corps, ou None si l'annonce est absurde. Toujours lu,
        meme quand la requete sera refusee : laisser des octets dans le tampon
        desynchronise la connexion suivante."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY:
            return None
        return self.rfile.read(length) if length else b""

    def _authorize(self, body: bytes):
        """-> (ok, code, message public). Le motif exact du refus reste dans le
        journal local : le dire au dehors apprendrait a un attaquant ou il en est."""
        source = self.client_address[0]
        left = self.server.limiter.blocked_for(source)
        if left:
            return False, 429, f"trop d'échecs, réessayer dans {left}s"
        ok, reason = sign.verify(hosts.local_key(), self.command, self.path,
                                 self.headers.get, body, self.server.guard, WORKER_SKEW)
        if ok:
            self.server.limiter.record_success(source)
            return True, 200, ""
        self.server.emit(f"{source}: refusé — {reason}")
        if self.server.limiter.record_failure(source):
            self.server.emit(f"{source}: bloqué {WORKER_BLOCK_SECONDS}s "
                             f"après {WORKER_MAX_FAILS} échecs")
        return False, 401, "authentification refusée"

    # ---- routes ----
    def do_GET(self):
        body = self._read_body()
        if body is None:
            return self._send(400, {"error": "corps invalide"})
        if self.path == "/v1/health":
            # Sans signature : uniquement de quoi dire « quelque chose ecoute ».
            # Signee : de quoi verifier qu'on parle a la bonne instance, avec la
            # bonne cle. Un health anonyme ne compte pas comme un echec, sinon un
            # simple check de disponibilite finirait par bloquer sa propre source.
            base = {"ok": True, "time": int(time.time())}
            if self._authorize_quiet(body)[0]:
                return self._send(200, {**base, "version": VERSION,
                                        "actions": sorted(REMOTE_ACTIONS)})
            return self._send(200, base)
        ok, code, message = self._authorize(body)
        if not ok:
            return self._send(code, {"error": message})
        m = JOB_RE.match(self.path)
        if m:
            return self._send(200, spool.job_result(m.group(1), ID_RE))
        self._send(404, {"error": "route inconnue"})

    def _authorize_quiet(self, body):
        """Comme `_authorize`, mais un echec ne compte pas. Reserve a /v1/health,
        qu'on interroge justement quand on ne sait pas encore si la cle est bonne."""
        source = self.client_address[0]
        if self.server.limiter.blocked_for(source):
            return False, 429, ""
        ok, _ = sign.verify(hosts.local_key(), self.command, self.path,
                            self.headers.get, body, self.server.guard, WORKER_SKEW)
        return ok, 200 if ok else 401, ""

    def do_POST(self):
        body = self._read_body()
        if body is None:
            return self._send(413, {"error": "corps absent ou trop gros"})
        ok, code, message = self._authorize(body)
        if not ok:
            return self._send(code, {"error": message})
        if self.path != "/v1/jobs":
            return self._send(404, {"error": "route inconnue"})
        try:
            job = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._send(400, {"error": "corps JSON attendu"})
        if not isinstance(job, dict):
            return self._send(400, {"error": "corps JSON attendu"})
        action = str(job.get("action") or "").strip()
        if action not in REMOTE_ACTIONS:
            return self._send(403, {"error": f"action refusée à distance: {action or '(vide)'}"})
        fields = {k: v for k, v in job.items() if k not in ("id", "ts", "src")}
        jid = spool.queue(src="remote", **fields)
        self.server.emit(f"job {action} accepté -> {jid}")
        self._send(202, {"id": jid})


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, emit):
        self.emit = emit
        self.guard = sign.ReplayGuard(WORKER_SKEW)
        self.limiter = sign.RateLimiter(WORKER_MAX_FAILS, WORKER_BLOCK_SECONDS)
        super().__init__(addr, Handler)


def _serve(server, emit):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    emit(f"bvsecrets-worker: écoute sur {WORKER_BIND}:{WORKER_PORT} "
         f"(requêtes signées, fenêtre {WORKER_SKEW}s)")


def _bind_when_available(emit):
    """Reessaie tant que l'adresse n'existe pas.

    Au boot, le worker demarre avant que wg0 soit montee : la liaison echoue
    avec EADDRNOTAVAIL. Abandonner laisserait la machine injoignable jusqu'au
    prochain redemarrage manuel du service, et lever tuerait le worker, qui a un
    autre travail que d'ecouter."""
    announced = False
    while True:
        try:
            _serve(Server((WORKER_BIND, WORKER_PORT), emit), emit)
            return
        except OSError as exc:
            if not announced:
                emit(f"bvsecrets-worker: {WORKER_BIND}:{WORKER_PORT} pas encore "
                     f"disponible ({exc.strerror or exc}) — nouvel essai toutes "
                     f"les {BIND_RETRY_SECONDS}s. Le reste du worker tourne.")
                announced = True
            time.sleep(BIND_RETRY_SECONDS)


def start(emit=print):
    """Demarre l'ecouteur, ou explique pourquoi il ne demarre pas.

    Ne leve jamais : le spool local doit continuer d'etre draine meme si
    l'ecouteur ne peut pas se lier."""
    if not WORKER_BIND:
        return None
    if not hosts.local_key():
        emit("bvsecrets-worker: BV_WORKER_BIND posé mais aucune clé "
             "(BV_WORKER_KEY ou <store>/hosts/self.key) — écouteur NON démarré.")
        return None
    try:
        server = Server((WORKER_BIND, WORKER_PORT), emit)
    except OSError as exc:
        emit(f"bvsecrets-worker: {WORKER_BIND}:{WORKER_PORT} indisponible "
             f"({exc.strerror or exc}) — attente en arrière-plan.")
        threading.Thread(target=_bind_when_available, args=(emit,), daemon=True).start()
        return None
    _serve(server, emit)
    return server
