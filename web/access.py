"""Service x role matrix, read from access/access.conf (mounted read-only).

Writes go through an `access` job: the worker re-renders, then recreates the
reverse proxy and restarts the services that consume the matrix.
"""
import configparser

from bvsecrets.config import ACCESS_CONF, ROLES

from .html import esc


def matrix():
    cp = configparser.ConfigParser()
    cp.optionxform = str
    cp.read(ACCESS_CONF, encoding="utf-8")
    rank = {r: i for i, r in enumerate(reversed(ROLES))}
    services = []
    for section in cp.sections():
        if section == "meta":
            continue
        raw = cp.get(section, "roles", fallback="")
        services.append({
            "id": section,
            "roles": sorted({r.strip() for r in raw.split(",") if r.strip()},
                            key=lambda r: rank.get(r, 99)),
            "gate": cp.get(section, "gate", fallback=""),
            "tile": cp.get(section, "tile", fallback=""),
            "group": cp.get(section, "group", fallback=""),
            "console": cp.get(section, "console", fallback=""),
            "override": cp.has_option(section, "tile_roles"),
        })
    return {"roles": ROLES, "services": services}


def _surfaces(svc):
    chips = []
    if svc["gate"]:
        chips.append('<span class="chip">gate</span>')
    if svc["tile"]:
        chips.append(f'<span class="chip">tuile · {esc(svc["group"] or "—")}</span>')
    if svc["console"]:
        chips.append(f'<span class="chip">console · {esc(svc["console"])}</span>')
    if svc["override"]:
        chips.append('<span class="chip" title="tile_roles : visibilité tuile ≠ accès gate">'
                     'tuile≠gate</span>')
    return " ".join(chips) or '<span class="dim">—</span>'


def rows_html():
    rows = []
    for svc in matrix()["services"]:
        cells = []
        for role in ROLES:
            checked = "checked" if role in svc["roles"] else ""
            # admin is superuser: always checked, never uncheckable
            disabled = "disabled" if role == "admin" else ""
            cells.append(f'<td class="chk"><input type="checkbox" data-role="{role}" '
                         f'{checked} {disabled}></td>')
        orig = ",".join(sorted(svc["roles"]))
        rows.append(f'<tr data-svc="{esc(svc["id"])}" data-orig="{esc(orig)}">'
                    f'<td class="name">{esc(svc["id"])}</td>{"".join(cells)}'
                    f'<td>{_surfaces(svc)}</td></tr>')
    return "".join(rows)


def validate_changes(changes):
    """-> error message, or None if the change list is acceptable."""
    known = {s["id"] for s in matrix()["services"]}
    for ch in changes:
        svc, roles = ch.get("service"), ch.get("roles")
        if svc not in known or not isinstance(roles, list) or any(r not in ROLES for r in roles):
            return f"changement invalide: {ch}"
        if "admin" not in roles:
            return "admin requis (superutilisateur)"
    return None
