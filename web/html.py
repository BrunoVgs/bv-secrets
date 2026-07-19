"""Gabarits et assets statiques.

Un gabarit reste du HTML valide : les parties dynamiques sont des marqueurs
<!--BV:NOM--> substitués ici. Pas de .format(), le HTML contient des accolades.
"""
import hashlib
from pathlib import Path

STATIC = (Path(__file__).resolve().parent / "static")
ASSET_TYPES = {".css": "text/css; charset=utf-8",
               ".js": "text/javascript; charset=utf-8",
               ".png": "image/png",
               ".svg": "image/svg+xml"}


def _asset_files():
    return sorted(p for p in STATIC.rglob("*") if p.suffix in ASSET_TYPES)


# Empreinte du contenu de tous les assets. Elle est injectée comme SEGMENT d'URL
# (static/<v>/js/boot.js) et non comme query : les imports ES relatifs héritent
# ainsi de la version, donc un module importé ne peut pas rester en cache périmé.
ASSET_V = "v" + hashlib.sha256(
    b"".join(p.read_bytes() for p in _asset_files())).hexdigest()[:8]


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def page(name, **marks):
    html = (STATIC / name).read_text(encoding="utf-8").replace("__V__", ASSET_V)
    for key, val in marks.items():
        html = html.replace(f"<!--BV:{key}-->", val)
    return html


def asset(url_path):
    """Résout `<version>/css/base.css` -> chemin sur disque, ou None si refusé.

    Le segment de version est purement cosmétique et ignoré ; seule compte la
    partie sous static/, validée pour interdire toute traversée."""
    _, _, rel = url_path.partition("/")
    if not rel or ".." in rel.split("/"):
        return None
    path = (STATIC / rel).resolve()
    if not path.is_file() or not path.is_relative_to(STATIC) or path.suffix not in ASSET_TYPES:
        return None
    return path
