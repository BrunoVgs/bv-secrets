"""envfile: une cle dans un fichier KEY=VALUE."""
import os
import re
from pathlib import Path

from .base import LocationError, atomic_write


def _pattern(key: str):
    return re.compile(rf"^(\s*(?:export\s+)?{re.escape(key)}\s*=)(.*?)(\r?\n?)$")


def read(target: str, key: str):
    path = Path(target)
    if not path.exists():
        return None
    pat = _pattern(key)
    for line in path.read_text().splitlines():
        m = pat.match(line + "\n")
        if m:
            return m.group(2)
    return None


def write(target: str, key: str, value: str):
    path = Path(target)
    lines = path.read_text().splitlines(keepends=True) if path.exists() else []
    pat = _pattern(key)
    for i, line in enumerate(lines):
        m = pat.match(line)
        if m:
            lines[i] = f"{m.group(1)}{value}{m.group(3) or os.linesep}"
            break
    else:
        if lines and not lines[-1].endswith(("\n", "\r")):
            lines[-1] += os.linesep
        lines.append(f"{key}={value}{os.linesep}")
    atomic_write(path, "".join(lines))


def keys(target: str):
    """Liste les cles d'un fichier .env, utilise par `scan`."""
    path = Path(target)
    if not path.exists():
        raise LocationError(f"fichier absent: {target}")
    out = []
    for line in path.read_text().splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in line:
            k = line.split("=", 1)[0].strip()
            if k.startswith("export "):
                k = k[len("export "):].strip()
            if k:
                out.append(k)
    return out
