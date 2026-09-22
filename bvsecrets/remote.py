"""Pousser un job chez une autre instance bv-secrets, et suivre son execution.

Symetrique de `worker/listen.py`. Chaque requete est signee (`bvsecrets.sign`) :
la cle partagee ne circule jamais et une requete capturee ne peut pas etre rejouee. Rien n'est execute ici : on depose un job dans
le spool de l'hote vise, puis on relit son resultat jusqu'a ce qu'il soit fini.
Le journal du worker distant est reemis tel quel dans le journal local, pour
qu'une poussee vers le Xeon se lise comme une operation locale.
"""
import json
import time
import urllib.error
import urllib.request

from . import hosts, sign
from .config import REMOTE_TIMEOUT, ConfigError

CONNECT_TIMEOUT = 10
POLL_SECONDS = 1.0


class RemoteError(RuntimeError):
    """L'hote distant est injoignable, refuse la cle, ou a rate le job."""


def _call(host: str, method: str, path: str, payload=None, timeout=CONNECT_TIMEOUT):
    base = hosts.url(host)          # leve ConfigError si l'hote n'est pas declare
    key = hosts.key(host)
    if not key:
        raise RemoteError(
            f"{host}: aucune clé partagée. La poser dans BV_HOST_KEY_{host.upper()} "
            f"ou {hosts.key_path(host)}")
    body = json.dumps(payload).encode("utf-8") if payload is not None else b""
    req = urllib.request.Request(base + path, data=body or None, method=method)
    # La cle ne part pas : elle signe. Un en-tete porteur se rejoue, une signature
    # couvrant methode, chemin, horodatage, nonce et corps ne se rejoue pas.
    for header, value in sign.headers(key, method, path, body).items():
        req.add_header(header, value)
    if body:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read().decode("utf-8")).get("error", "")
        except Exception:
            pass
        if e.code == 401:
            raise RemoteError(f"{host}: authentification refusée (clé différente "
                              f"des deux côtés, ou horloges trop écartées)") from None
        if e.code == 429:
            raise RemoteError(f"{host}: trop d'échecs, l'hôte bloque "
                              f"temporairement cette source") from None
        raise RemoteError(f"{host}: HTTP {e.code} {detail}".strip()) from None
    except urllib.error.URLError as e:
        raise RemoteError(f"{host}: injoignable ({e.reason})") from None
    except (ValueError, OSError) as e:
        raise RemoteError(f"{host}: réponse illisible ({e})") from None


def health(host: str) -> dict:
    return _call(host, "GET", "/v1/health")


def submit(host: str, **job) -> str:
    """Depose le job et rend son identifiant. Le contenu n'est jamais journalise :
    un `set_value` porte une valeur en clair."""
    out = _call(host, "POST", "/v1/jobs", payload=job)
    jid = out.get("id")
    if not jid:
        raise RemoteError(f"{host}: pas d'identifiant de job en réponse")
    return jid


def result(host: str, jid: str) -> dict:
    return _call(host, "GET", f"/v1/jobs/{jid}")


def run(host: str, log=print, timeout=None, **job) -> dict:
    """Depose, suit, et rend le resultat final. Leve RemoteError si le worker
    distant a echoue ou n'a pas repondu a temps."""
    deadline = time.time() + (timeout or REMOTE_TIMEOUT)
    jid = submit(host, **job)
    log(f"  {host}: job {job.get('action')} -> {jid}")
    seen = 0
    while True:
        res = result(host, jid)
        lines = res.get("log") or []
        for line in lines[seen:]:
            log(f"  {host}| {line}")
        seen = len(lines)
        status = res.get("status")
        if status == "done":
            return res
        if status == "error":
            raise RemoteError(f"{host}: job {jid} en échec")
        if time.time() >= deadline:
            raise RemoteError(f"{host}: job {jid} toujours '{status}' après "
                              f"{timeout or REMOTE_TIMEOUT}s")
        time.sleep(POLL_SECONDS)
