"""Build the served pages: login and dashboard."""
import json

from bvsecrets.config import ALL_KINDS, GEN_KINDS

from . import access, inventory
from .html import page

NAV_ITEMS = [
    ("overview", "Vue d'ensemble", None),
    ("coffre", "Coffre", "secrets"),
    ("rotation", "Rotation", "auto"),
    ("comptes", "Comptes", None),
    ("acces", "Accès &amp; rôles", "services"),
    ("audit", "Audit", None),
    ("docs", "Docs", None),
]


def login(configured: bool) -> str:
    warn = "" if configured else (
        '<p class="err">⚠ BV_DASH_PASSWORD non configuré côté serveur — '
        '<code>bv-secrets set SECRETS_DASHBOARD_PASSWORD …</code> puis re-render.</p>')
    return page("login.html", WARN=warn)


def _nav(counts) -> str:
    out = []
    for vid, label, count_key in NAV_ITEMS:
        count = counts.get(count_key) if count_key else None
        badge = f'<span class="ct">{count}</span>' if count is not None else ""
        out.append(f'<button class="nav" data-view="{vid}"><span class="dot"></span>'
                   f'<span class="lb">{label}</span>{badge}</button>')
    return "".join(out)


def dashboard(csrf: str) -> str:
    rows = inventory.list_data()
    auto = inventory.auto_targets()
    services = access.matrix()["services"]
    # "<" is escaped: the payload can't close the <script> tag carrying it.
    boot = json.dumps({
        "csrf": csrf,
        "secrets": rows,
        "auto": auto,
        "kinds": {"all": sorted(ALL_KINDS - {"manual"}), "gen": sorted(GEN_KINDS)},
        "groups": ["auto", "app", "careful", "manual"],
    }).replace("<", "\\u003c")
    counts = {"secrets": len(rows), "auto": len(auto), "services": len(services)}
    return page("index.html", NAV=_nav(counts), AUTOCOUNT=str(len(auto)),
                ACCESS=access.rows_html(), BOOT=boot)
