"""Location connectors: read AND write a value where it lives.

Two-way, not write-only: `read` extracts the in-place value, `write` replaces it.
This is what lets us adopt an existing file, target one value in a structured
config, and detect drift.

Surgical writes: only the targeted value changes; comments, order and indentation
stay byte-for-byte identical. No parser rewrites the whole file.

Addressing: ``scheme:target#selector``
    envfile:/path/.env#KEY            one key in a KEY=VALUE file
    regex:/path/file#<pattern>        group 1 of a pattern (catch-all)
    file:/path                        the whole file as the value
    json:/path/config.json#a.b.c      read a JSON path (write: use regex:)
"""
import json
import os
import re
from pathlib import Path


class LocationError(RuntimeError):
    """Malformed, unreadable, or non-writable location."""


def split(location: str):
    """``scheme:target#selector`` -> (scheme, target, selector). Split on the FIRST
    ``#`` so a regex pattern may contain more without being truncated."""
    scheme, _, rest = location.partition(":")
    target, _, selector = rest.partition("#")
    return scheme, target, selector


def _atomic_write(path: Path, text: str):
    """Write, preserving the file's existing mode (0600 if new): a 0644 app config
    must not be silently tightened."""
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    tmp = path.with_suffix(path.suffix + ".bvtmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    tmp.replace(path)


# --- envfile: one key in a KEY=VALUE file ----------------------------------- #
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
    """List a .env file's keys, used by `scan`."""
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


# --- regex: group 1 of a pattern; catch-all for any text format ------------- #
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


# --- file: whole file as the value ------------------------------------------ #
def file_read(target: str, _selector: str):
    path = Path(target)
    return path.read_text() if path.exists() else None


def file_write(target: str, _selector: str, value: str):
    _atomic_write(Path(target), value)


# --- json: read a dotted path. Structured write via regex: for now ---------- #
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
    """In-place value, or None if absent. Raises if the scheme can't read."""
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
