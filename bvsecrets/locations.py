"""Connecteurs de localisation : lire ET écrire une valeur là où elle vit.

Le pivot du modèle : une localisation n'est plus une destination en écriture seule
mais un connecteur symétrique — `read` extrait la valeur en place, `write` la
remplace. C'est ce qui permet d'ADOPTER un fichier existant, d'atteindre UNE valeur
dans un config structuré, et de détecter les dérives.

Écriture chirurgicale : seule la valeur ciblée est remplacée, le reste du fichier
(commentaires, ordre, indentation) reste identique octet pour octet. Aucun parseur
ne réécrit le fichier entier, donc aucune dépendance et aucune perte de forme.

Adressage : ``scheme:cible#sélecteur``
    envfile:/chemin/.env#CLE          une clé dans un fichier KEY=VALUE
    regex:/chemin/fichier#<motif>     groupe 1 d'une expression — passe-partout
    file:/chemin                      le fichier entier comme valeur unique
    json:/chemin/config.json#a.b.c    lecture d'un chemin JSON (écriture : voir reg:)
"""
import json
import os
import re
from pathlib import Path


class LocationError(RuntimeError):
    """Localisation mal formée, illisible ou non inscriptible."""


def split(location: str):
    """``scheme:cible#sélecteur`` -> (scheme, cible, sélecteur).

    Le sélecteur est découpé sur le PREMIER ``#`` : un motif regex peut en contenir
    d'autres ensuite sans être tronqué."""
    scheme, _, rest = location.partition(":")
    target, _, selector = rest.partition("#")
    return scheme, target, selector


def _atomic_write(path: Path, text: str):
    """Écrit en préservant le mode existant du fichier (0600 s'il est nouveau) :
    un config applicatif en 0644 ne doit pas être resserré par surprise."""
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    tmp = path.with_suffix(path.suffix + ".bvtmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    tmp.replace(path)


# --------------------------------------------------------------------------- #
# envfile : une clé dans un fichier KEY=VALUE
# --------------------------------------------------------------------------- #
def _env_pattern(key: str):
    return re.compile(rf"^(\s*(?:export\s+)?{re.escape(key)}\s*=)(.*?)(\r?\n?)$")


def env_read(target: str, key: str):
    path = Path(target)
    if not path.exists():
        return None
    pat = _env_pattern(key)
    for line in path.read_text().splitlines():
        m = pat.match(line + "\n")
        if m:
            return m.group(2)
    return None


def env_write(target: str, key: str, value: str):
    path = Path(target)
    lines = path.read_text().splitlines(keepends=True) if path.exists() else []
    pat = _env_pattern(key)
    for i, line in enumerate(lines):
        m = pat.match(line)
        if m:
            lines[i] = f"{m.group(1)}{value}{m.group(3) or os.linesep}"
            break
    else:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += os.linesep
        lines.append(f"{key}={value}{os.linesep}")
    _atomic_write(path, "".join(lines))


def env_keys(target: str):
    """Liste les clés d'un fichier env — utilisé par `scan` pour aider à déclarer."""
    path = Path(target)
    if not path.exists():
        raise LocationError(f"fichier absent: {target}")
    keys = []
    for line in path.read_text().splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in line:
            k = line.split("=", 1)[0].strip()
            if k.startswith("export "):
                k = k[len("export "):].strip()
            if k:
                keys.append(k)
    return keys


# --------------------------------------------------------------------------- #
# regex : le groupe 1 d'un motif — passe-partout pour tout format textuel
# --------------------------------------------------------------------------- #
def _regex_compile(pattern: str):
    try:
        rx = re.compile(pattern, re.MULTILINE)
    except re.error as e:
        raise LocationError(f"motif invalide: {e}")
    if rx.groups < 1:
        raise LocationError("le motif doit contenir un groupe capturant (la valeur)")
    return rx


def regex_read(target: str, pattern: str):
    path = Path(target)
    if not path.exists():
        return None
    m = _regex_compile(pattern).search(path.read_text())
    return m.group(1) if m else None


def regex_write(target: str, pattern: str, value: str):
    path = Path(target)
    if not path.exists():
        raise LocationError(f"fichier absent: {target}")
    text = path.read_text()
    m = _regex_compile(pattern).search(text)
    if not m:
        raise LocationError(f"motif sans correspondance dans {target}")
    start, end = m.span(1)
    _atomic_write(path, text[:start] + value + text[end:])


# --------------------------------------------------------------------------- #
# file : le fichier entier comme valeur
# --------------------------------------------------------------------------- #
def file_read(target: str, _selector: str):
    path = Path(target)
    return path.read_text() if path.exists() else None


def file_write(target: str, _selector: str, value: str):
    _atomic_write(Path(target), value)


# --------------------------------------------------------------------------- #
# json : lecture d'un chemin pointé. L'écriture structurée arrive plus tard ;
# en attendant, viser une valeur JSON précise se fait avec regex:.
# --------------------------------------------------------------------------- #
def json_read(target: str, dotted: str):
    path = Path(target)
    if not path.exists():
        return None
    try:
        node = json.loads(path.read_text())
    except ValueError as e:
        raise LocationError(f"JSON illisible: {e}")
    for part in filter(None, dotted.split(".")):
        if isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node if isinstance(node, str) else json.dumps(node)


_READERS = {
    "envfile": env_read,
    "regex": regex_read,
    "file": file_read,
    "json": json_read,
}
_WRITERS = {
    "envfile": env_write,
    "regex": regex_write,
    "file": file_write,
}


def readable_schemes():
    return set(_READERS)


def writable_schemes():
    return set(_WRITERS)


def read_location(location: str):
    """Valeur en place, ou None si absente. Lève si le schéma ne sait pas lire."""
    scheme, target, selector = split(location)
    reader = _READERS.get(scheme)
    if not reader:
        raise LocationError(f"schéma non lisible: {scheme}")
    return reader(target, selector)


def write_location(location: str, value: str):
    scheme, target, selector = split(location)
    writer = _WRITERS.get(scheme)
    if not writer:
        raise LocationError(f"schéma non inscriptible: {scheme}")
    writer(target, selector, value)
