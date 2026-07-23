"""Templates and static assets.

A template stays valid HTML: dynamic parts are <!--BV:NAME--> markers substituted
here. No .format(), since the HTML contains braces.
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


# Content hash of all assets, injected as a URL SEGMENT (static/<v>/js/boot.js),
# not a query: relative ES imports inherit the version, so an imported module can't
# stay stale in cache.
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
    """Resolve `<version>/css/base.css` -> disk path, or None if refused.

    The version segment is cosmetic and ignored; only the part under static/
    matters, validated to forbid any traversal."""
    _, _, rel = url_path.partition("/")
    if not rel or ".." in rel.split("/"):
        return None
    path = (STATIC / rel).resolve()
    if not path.is_file() or not path.is_relative_to(STATIC) or path.suffix not in ASSET_TYPES:
        return None
    return path
