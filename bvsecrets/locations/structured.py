"""Connecteurs formats structures : json, yaml, ini, toml.

Lecture via un parseur quand la stdlib en fournit un (json, configparser, tomllib) ;
ecriture toujours chirurgicale par ancrage sur la cle, jamais par re-serialisation.
Seule la valeur ciblee change ; commentaires, ordre et mise en forme restent
identiques octet pour octet. Aucune dependance externe (yaml inclus).
"""
import configparser
import json
import re
from pathlib import Path

from .base import LocationError, atomic_write

try:
    import tomllib
except ModuleNotFoundError:                  # < Python 3.11
    tomllib = None


# --- helpers d'edition ligne a ligne ---------------------------------------- #
def _nl(line: str) -> str:
    return line[len(line.rstrip("\r\n")):]


def _value_span(body: str, start: int):
    """(vstart, vend) du scalaire dans `body` a partir de `start`, espaces de tete
    ignores, arret avant un commentaire ` #` en ligne ou la fin. Un token entoure
    de guillemets est pris en entier."""
    i = start
    while i < len(body) and body[i] in " \t":
        i += 1
    if i < len(body) and body[i] in "\"'":
        q = body[i]
        j = i + 1
        while j < len(body):
            if body[j] == "\\":
                j += 2
                continue
            if body[j] == q:
                return i, j + 1
            j += 1
        return i, len(body)
    j = i
    while j < len(body):
        if body[j] == "#" and j > i and body[j - 1] in " \t":
            break
        j += 1
    while j > i and body[j - 1] in " \t":
        j -= 1
    return i, j


def _splice(line: str, start: int, token: str) -> str:
    """Remplace le scalaire de `line` a partir de `start` par `token`, en gardant
    fin de ligne et commentaire eventuel."""
    nl = _nl(line)
    body = line[:len(line) - len(nl)]
    vs, ve = _value_span(body, start)
    sep = "" if vs > 0 and body[vs - 1] in " \t" else " "
    return f"{body[:vs]}{sep}{token}{body[ve:]}{nl}"


def _unquote(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] in "\"'" and token[-1] == token[0]:
        inner = token[1:-1]
        if token[0] == '"':
            try:
                return json.loads(token)
            except ValueError:
                return inner
        return inner
    return token


def _parts(selector: str):
    segs = [s for s in selector.split(".") if s]
    if not segs:
        raise LocationError("selecteur vide")
    return segs


# --- json : lecture parseur, ecriture chirurgicale sur le token ------------- #
def _json_scalar_span(text: str, offset: int):
    i = offset
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    if i >= len(text):
        raise LocationError("valeur JSON introuvable")
    if text[i] in "{[":
        raise LocationError("cible JSON non scalaire (objet/tableau)")
    if text[i] == '"':
        j = i + 1
        while j < len(text):
            if text[j] == "\\":
                j += 2
                continue
            if text[j] == '"':
                return i, j + 1
            j += 1
        raise LocationError("chaine JSON non terminee")
    j = i
    while j < len(text) and text[j] not in ",}]\r\n \t":
        j += 1
    return i, j


def _json_navigate(text: str, parts):
    """Position juste apres le `"cle":` du dernier segment, en descendant le chemin."""
    pos = 0
    for part in parts:
        m = re.compile(r'"' + re.escape(part) + r'"\s*:').search(text, pos)
        if not m:
            raise LocationError(f"cle JSON absente: {part}")
        pos = m.end()
    return pos


def json_read(target: str, selector: str):
    path = Path(target)
    if not path.exists():
        return None
    try:
        node = json.loads(path.read_text())
    except ValueError as e:
        raise LocationError(f"JSON illisible: {e}")
    for part in filter(None, selector.split(".")):
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


def json_write(target: str, selector: str, value: str):
    path = Path(target)
    if not path.exists():
        raise LocationError(f"fichier absent: {target}")
    text = path.read_text()
    try:
        json.loads(text)
    except ValueError as e:
        raise LocationError(f"JSON illisible: {e}")
    pos = _json_navigate(text, _parts(selector))
    start, end = _json_scalar_span(text, pos)
    atomic_write(path, text[:start] + json.dumps(value) + text[end:])


# --- yaml : pas de stdlib, ancrage par indentation -------------------------- #
def _yaml_locate(lines, parts):
    """(index de ligne, position apres `cle:`) du dernier segment du chemin."""
    idx, min_indent = 0, -1
    for i, line in enumerate(lines):
        body = line[:len(line) - len(_nl(line))]
        s = body.lstrip()
        if not s or s.startswith("#"):
            continue
        indent = len(body) - len(s)
        m = re.match(re.escape(parts[idx]) + r"[ \t]*:", s)
        if m and indent > min_indent:
            if idx == len(parts) - 1:
                return i, indent + m.end()
            idx += 1
            min_indent = indent
    raise LocationError(f"chemin YAML absent: {'.'.join(parts)}")


def yaml_read(target: str, selector: str):
    path = Path(target)
    if not path.exists():
        return None
    lines = path.read_text().splitlines(keepends=True)
    try:
        i, colon_end = _yaml_locate(lines, _parts(selector))
    except LocationError:
        return None
    body = lines[i][:len(lines[i]) - len(_nl(lines[i]))]
    vs, ve = _value_span(body, colon_end)
    return _unquote(body[vs:ve]) if vs < ve else ""


def yaml_write(target: str, selector: str, value: str):
    path = Path(target)
    if not path.exists():
        raise LocationError(f"fichier absent: {target}")
    lines = path.read_text().splitlines(keepends=True)
    i, colon_end = _yaml_locate(lines, _parts(selector))
    lines[i] = _splice(lines[i], colon_end, json.dumps(value))
    atomic_write(path, "".join(lines))


# --- ini : lecture configparser, ecriture chirurgicale ---------------------- #
def _ini_parts(selector: str):
    section, _, key = selector.partition(".")
    if not key:
        raise LocationError("selecteur ini attendu: section.key")
    return section, key


def _section_span(lines, section: str):
    start = next((i for i, ln in enumerate(lines) if ln.strip() == f"[{section}]"), None)
    if start is None:
        raise LocationError(f"section absente: [{section}]")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        s = lines[i].strip()
        if s.startswith("[") and s.endswith("]"):
            end = i
            break
    return start, end


def ini_read(target: str, selector: str):
    section, key = _ini_parts(selector)
    path = Path(target)
    if not path.exists():
        return None
    cp = configparser.ConfigParser(interpolation=None)
    cp.optionxform = str
    try:
        cp.read(path, encoding="utf-8")
    except configparser.Error as e:
        raise LocationError(f"INI illisible: {e}")
    return cp.get(section, key) if cp.has_option(section, key) else None


def _kv_write(path: Path, lines, start: int, end: int, key: str, token: str, selector: str):
    pat = re.compile(rf"^(\s*{re.escape(key)}\s*=[ \t]*)(.*)$")
    for i in range(start + 1, end):
        body = lines[i][:len(lines[i]) - len(_nl(lines[i]))]
        m = pat.match(body)
        if m:
            lines[i] = f"{m.group(1)}{token}{_nl(lines[i])}"
            atomic_write(path, "".join(lines))
            return
    raise LocationError(f"cle absente: {selector}")


def ini_write(target: str, selector: str, value: str):
    section, key = _ini_parts(selector)
    path = Path(target)
    if not path.exists():
        raise LocationError(f"fichier absent: {target}")
    lines = path.read_text().splitlines(keepends=True)
    start, end = _section_span(lines, section)
    _kv_write(path, lines, start, end, key, value, selector)


# --- toml : lecture tomllib, ecriture chirurgicale -------------------------- #
def _toml_parts(selector: str):
    segs = _parts(selector)
    return ".".join(segs[:-1]), segs[-1]     # (table, key) ; table "" = racine


def _toml_table_span(lines, table: str):
    if not table:
        end = next((i for i, ln in enumerate(lines) if ln.lstrip().startswith("[")), len(lines))
        return -1, end
    start = next((i for i, ln in enumerate(lines) if ln.strip() == f"[{table}]"), None)
    if start is None:
        raise LocationError(f"table absente: [{table}]")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].lstrip().startswith("["):
            end = i
            break
    return start, end


def toml_read(target: str, selector: str):
    if tomllib is None:
        raise LocationError("toml: Python 3.11+ requis (tomllib)")
    path = Path(target)
    if not path.exists():
        return None
    try:
        node = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as e:
        raise LocationError(f"TOML illisible: {e}")
    for part in filter(None, selector.split(".")):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    if isinstance(node, (dict, list)):
        return None
    return node if isinstance(node, str) else json.dumps(node)


def toml_write(target: str, selector: str, value: str):
    table, key = _toml_parts(selector)
    path = Path(target)
    if not path.exists():
        raise LocationError(f"fichier absent: {target}")
    lines = path.read_text().splitlines(keepends=True)
    start, end = _toml_table_span(lines, table)
    _kv_write(path, lines, start, end, key, json.dumps(value), selector)
