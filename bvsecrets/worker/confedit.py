"""Réécriture chirurgicale de secrets.conf.

Seules les lignes `kind =` / `group =` de la section visée sont remplacées :
commentaires, ordre et mise en forme du reste du fichier sont préservés. Aucune
valeur de secret ne transite par ce module.
"""
import re

from ..config import CONF


def _section_bounds(lines, name):
    start = next((i for i, ln in enumerate(lines) if ln.strip() == f"[{name}]"), None)
    if start is None:
        raise RuntimeError(f"section absente: {name}")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        stripped = lines[i].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            end = i
            break
    return start, end


def rewrite_section(lines, name, kind, group, log):
    """Remplace kind/group dans [name] ; ajoute la clé si elle est absente."""
    start, end = _section_bounds(lines, name)
    out = list(lines)
    for key, val in (("kind", kind), ("group", group)):
        if val is None:
            continue
        pat = re.compile(rf"^(\s*{key}\s*=\s*)(\S+)\s*$")
        for i in range(start + 1, end):
            m = pat.match(out[i])
            if not m:
                continue
            if m.group(2) == val:
                log(f"{name}: {key} déjà {val}")
            else:
                out[i] = f"{m.group(1)}{val}\n"
                log(f"{name}: {key} {m.group(2)} -> {val}")
            break
        else:
            out.insert(start + 1, f"{key}   = {val}\n")
            end += 1
            log(f"{name}: {key} = {val} (ajouté)")
    return out


def read_conf_lines():
    return CONF.read_text(encoding="utf-8").splitlines(keepends=True)


def write_conf_lines(lines):
    tmp = CONF.with_suffix(".conf.tmp")
    tmp.write_text("".join(lines), encoding="utf-8")
    tmp.replace(CONF)
