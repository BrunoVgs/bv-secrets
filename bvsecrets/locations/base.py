"""Primitives partagees par les connecteurs de localisation."""
import os
from pathlib import Path


class LocationError(RuntimeError):
    """Localisation malformee, illisible ou non inscriptible."""


def split(location: str):
    """``scheme:target#selector`` -> (scheme, target, selector). Coupe sur le PREMIER
    ``#`` pour qu'un motif regex puisse en contenir d'autres sans etre tronque."""
    scheme, _, rest = location.partition(":")
    target, _, selector = rest.partition("#")
    return scheme, target, selector


def atomic_write(path: Path, text: str):
    """Ecrit en preservant le mode existant (0600 si nouveau) : une conf app en 0644
    ne doit pas etre silencieusement resserree."""
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    tmp = path.with_suffix(path.suffix + ".bvtmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    tmp.replace(path)
