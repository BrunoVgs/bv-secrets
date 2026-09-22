"""Authentification des requetes entre instances.

Un jeton porte en clair dans un en-tete se REJOUE : qui capture une requete peut
la renvoyer telle quelle, indefiniment. Ici la cle partagee ne circule jamais --
elle signe la requete. La signature couvre la methode, le chemin, un horodatage,
un nonce et l'empreinte du corps, donc modifier n'importe lequel des cinq invalide
la signature.

Une requete n'est valable qu'une fois, et seulement dans une fenetre courte : le
nonce est memorise le temps de cette fenetre, ce qui borne la memoire sans avoir
a retenir quoi que ce soit plus longtemps.

Module pur, partage par le client et le serveur : une seule definition de ce qui
est signe, sinon les deux cotes finissent par ne pas signer la meme chose.
"""
import hashlib
import hmac
import secrets as pysecrets
import time

SCHEME = "BV1-HMAC-SHA256"
TS_HEADER = "X-BV-Timestamp"
NONCE_HEADER = "X-BV-Nonce"
NONCE_BYTES = 16


def canonical(method: str, path: str, ts: str, nonce: str, body: bytes) -> bytes:
    """La chaine signee. Les champs sont separes par des sauts de ligne et aucun
    n'en contient, donc deux requetes differentes ne peuvent pas produire la meme
    chaine en deplacant une frontiere."""
    digest = hashlib.sha256(body or b"").hexdigest()
    return "\n".join([SCHEME, method.upper(), path, str(ts), nonce, digest]).encode()


def sign(key: str, method: str, path: str, ts, nonce: str, body: bytes) -> str:
    return hmac.new(key.encode(), canonical(method, path, ts, nonce, body),
                    hashlib.sha256).hexdigest()


def headers(key: str, method: str, path: str, body: bytes) -> dict:
    """Les en-tetes d'authentification d'une requete sortante."""
    ts = str(int(time.time()))
    nonce = pysecrets.token_hex(NONCE_BYTES)
    return {"Authorization": f"{SCHEME} {sign(key, method, path, ts, nonce, body)}",
            TS_HEADER: ts, NONCE_HEADER: nonce}


def verify(key, method, path, get_header, body: bytes, guard, skew: int):
    """-> (True, "") ou (False, raison). La raison ne sort JAMAIS au client : elle
    sert au journal local. Dire au dehors ce qui cloche apprend a un attaquant ou
    il en est."""
    if not key:
        return False, "aucune clé configurée sur cette instance"
    header = (get_header("Authorization") or "").strip()
    prefix = SCHEME + " "
    if not header.startswith(prefix):
        return False, "schéma d'authentification absent ou inconnu"
    presented = header[len(prefix):].strip()
    ts = (get_header(TS_HEADER) or "").strip()
    nonce = (get_header(NONCE_HEADER) or "").strip()
    if not ts.isdigit() or not nonce:
        return False, "horodatage ou nonce absent"
    now = int(time.time())
    if abs(now - int(ts)) > skew:
        return False, f"hors fenêtre ({abs(now - int(ts))}s d'écart)"
    expected = sign(key, method, path, ts, nonce, body)
    if not hmac.compare_digest(presented, expected):
        return False, "signature invalide"
    # En dernier : ne consommer un nonce qu'une fois la signature prouvee, sinon
    # n'importe qui peut saturer la memoire des nonces sans connaitre la cle.
    if not guard.remember(nonce, now):
        return False, "nonce déjà utilisé (rejeu)"
    return True, ""


class ReplayGuard:
    """Les nonces vus dans la fenetre. Au-dela elle rejette deja sur l'horodatage,
    donc rien ne sert de les garder plus longtemps."""

    def __init__(self, window: int):
        self.window = window
        self.seen = {}

    def remember(self, nonce: str, now: int) -> bool:
        """-> False si ce nonce a deja servi."""
        self._prune(now)
        if nonce in self.seen:
            return False
        self.seen[nonce] = now + self.window
        return True

    def _prune(self, now):
        if len(self.seen) < 2048:
            expired = [n for n, exp in self.seen.items() if exp <= now]
        else:
            expired = [n for n, exp in list(self.seen.items()) if exp <= now]
        for n in expired:
            self.seen.pop(n, None)


class RateLimiter:
    """Blocage temporaire d'une source apres trop d'echecs.

    Compte les ECHECS, pas les requetes : une instance legitime qui pousse
    cinquante secrets d'affilee ne doit jamais etre genee, alors que quelqu'un
    qui devine une cle est arrete au bout de quelques essais."""

    def __init__(self, max_fails: int, block_seconds: int):
        self.max_fails = max_fails
        self.block_seconds = block_seconds
        self.fails = {}
        self.blocked = {}

    def blocked_for(self, source: str, now=None) -> int:
        """-> secondes de blocage restantes, 0 si la source peut parler."""
        now = int(time.time()) if now is None else now
        until = self.blocked.get(source, 0)
        if until <= now:
            self.blocked.pop(source, None)
            return 0
        return until - now

    def record_failure(self, source: str, now=None) -> bool:
        """-> True si cet echec vient de declencher un blocage."""
        now = int(time.time()) if now is None else now
        window = [t for t in self.fails.get(source, []) if t > now - self.block_seconds]
        window.append(now)
        self.fails[source] = window
        if len(window) >= self.max_fails:
            self.blocked[source] = now + self.block_seconds
            self.fails.pop(source, None)
            return True
        return False

    def record_success(self, source: str):
        self.fails.pop(source, None)
