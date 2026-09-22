"""Ecouteur HTTP du worker : une seconde source de jobs, rien de plus.

Le worker local est alimente par un repertoire de spool. Un worker distant est le
MEME worker, alimente par cet ecouteur, qui authentifie l'appelant puis depose le
job dans ce meme spool. Aucun code d'execution ici : la boucle le draine comme
n'importe quel job local, avec les memes privileges et le meme archivage. On
generalise le transport, pas le modele de securite.

L'ecouteur ne demarre que si `BV_WORKER_BIND` est pose — et on l'attache a
l'adresse wg0 de la machine, jamais a 0.0.0.0.
"""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import hosts, spool
from ..config import WORKER_BIND, WORKER_PORT

VERSION = "1.1.1"
ID_RE = re.compile(r"^[0-9a-f]{16}$")
JOB_RE = re.compile(r"^/v1/jobs/([0-9a-zA-Z]+)$")
# Ce qu'une autre instance a le droit de demander. Le reste (comptes, acces,
# adoption, revelation de valeur) appartient au dashboard local de CETTE machine
# et n'a aucune raison de traverser le reseau. Liste blanche : une action
# inconnue est refusee, jamais transmise.
REMOTE_ACTIONS = {"set_value", "apply", "rotate", "doctor"}
MAX_BODY = 64 * 1024


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

    def _authenticated(self) -> bool:
        header = self.headers.get("Authorization", "")
        presented = header[7:].strip() if header.lower().startswith("bearer ") else ""
        return hosts.key_matches(presented, hosts.local_key())

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            return None

    # ---- routes ----
    def do_GET(self):
        if self.path == "/v1/health":
            # Sans cle : uniquement de quoi dire « quelque chose ecoute ici ».
            # Avec la cle : de quoi verifier qu'on parle bien a la bonne instance.
            if self._authenticated():
                return self._send(200, {"ok": True, "version": VERSION,
                                        "actions": sorted(REMOTE_ACTIONS)})
            return self._send(200, {"ok": True})
        if not self._authenticated():
            return self._send(401, {"error": "clé absente ou invalide"})
        m = JOB_RE.match(self.path)
        if m:
            return self._send(200, spool.job_result(m.group(1), ID_RE))
        self._send(404, {"error": "route inconnue"})

    def do_POST(self):
        if not self._authenticated():
            return self._send(401, {"error": "clé absente ou invalide"})
        if self.path != "/v1/jobs":
            return self._send(404, {"error": "route inconnue"})
        job = self._body()
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
        super().__init__(addr, Handler)


def start(emit=print):
    """Demarre l'ecouteur dans un thread, ou explique pourquoi il ne demarre pas.
    -> le Server, ou None."""
    if not WORKER_BIND:
        return None
    if not hosts.local_key():
        emit("bvsecrets-worker: BV_WORKER_BIND posé mais aucune clé "
             "(BV_WORKER_KEY ou <store>/hosts/self.key) — écouteur NON démarré.")
        return None
    server = Server((WORKER_BIND, WORKER_PORT), emit)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    emit(f"bvsecrets-worker: écoute sur {WORKER_BIND}:{WORKER_PORT}")
    return server
