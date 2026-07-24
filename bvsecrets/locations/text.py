"""regex: groupe 1 d'un motif (catch-all tout format texte). file: le fichier entier."""
import re
from pathlib import Path

from .base import LocationError, atomic_write


def _compile(pattern: str):
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
    m = _compile(pattern).search(path.read_text())
    return m.group(1) if m else None


def regex_write(target: str, pattern: str, value: str):
    path = Path(target)
    if not path.exists():
        raise LocationError(f"fichier absent: {target}")
    text = path.read_text()
    m = _compile(pattern).search(text)
    if not m:
        raise LocationError(f"motif sans correspondance dans {target}")
    start, end = m.span(1)
    atomic_write(path, text[:start] + value + text[end:])


def file_read(target: str, _selector: str):
    path = Path(target)
    return path.read_text() if path.exists() else None


def file_write(target: str, _selector: str, value: str):
    atomic_write(Path(target), value)
