"""Surgical rewrite of the declaration file. Only the `kind` / `group` lines of the
target section change; comments, order and layout elsewhere are preserved. No
secret value passes through this module.

Les deux formats sont traites ici. En YAML, un secret peut tenir son `kind` d'un
gabarit (`<<: *apikey`) : ecrire `kind:` en propre dans le bloc le surcharge,
exactement comme YAML le prevoit, et le gabarit reste intact pour les autres.
"""
import re

from .. import conffile
from ..config import CONF, is_yaml


def _yaml_bounds(lines, name):
    pat = re.compile(rf"^(\s+){re.escape(name)}:\s*$")
    start = indent = None
    for i, ln in enumerate(lines):
        m = pat.match(ln)
        if m:
            start, indent = i, len(m.group(1))
            break
    if start is None:
        raise RuntimeError(f"section missing: {name}")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if not lines[i].strip():
            continue
        if len(lines[i]) - len(lines[i].lstrip()) <= indent:
            end = i
            break
    return start, end, indent


def _rewrite_yaml(lines, name, kind, group, log):
    start, end, indent = _yaml_bounds(lines, name)
    field = " " * (indent + 2)
    out = list(lines)
    for key, val in (("kind", kind), ("group", group)):
        if val is None:
            continue
        pat = re.compile(rf"^(\s*{key}\s*:\s*)(\S+)\s*$")
        for i in range(start + 1, end):
            m = pat.match(out[i])
            if not m:
                continue
            if m.group(2) == val:
                log(f"{name}: {key} already {val}")
            else:
                out[i] = f"{m.group(1)}{val}\n"
                log(f"{name}: {key} {m.group(2)} -> {val}")
            break
        else:
            # Absent du bloc : la valeur venait d'un gabarit, on la surcharge en
            # propre. YAML donne raison a la cle explicite quelle que soit sa
            # position, mais la poser juste apres le `<<:` se lit dans l'ordre ou
            # on la comprend : le gabarit, puis ce qui s'en ecarte.
            at = next((i for i in range(start + 1, end)
                       if out[i].lstrip().startswith("<<:")), start) + 1
            out.insert(at, f"{field}{key}: {val}\n")
            end += 1
            log(f"{name}: {key} = {val} (surcharge du gabarit)")
    return out


def _section_bounds(lines, name):
    start = next((i for i, ln in enumerate(lines) if ln.strip() == f"[{name}]"), None)
    if start is None:
        raise RuntimeError(f"section missing: {name}")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        stripped = lines[i].strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            end = i
            break
    return start, end


def rewrite_section(lines, name, kind, group, log):
    """Replace kind/group in the section; add the key if absent."""
    if is_yaml():
        return _rewrite_yaml(lines, name, kind, group, log)
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
                log(f"{name}: {key} already {val}")
            else:
                out[i] = f"{m.group(1)}{val}\n"
                log(f"{name}: {key} {m.group(2)} -> {val}")
            break
        else:
            out.insert(start + 1, f"{key}   = {val}\n")
            end += 1
            log(f"{name}: {key} = {val} (added)")
    return out


def read_conf_lines():
    return CONF.read_text(encoding="utf-8").splitlines(keepends=True)


def write_conf_lines(lines):
    # Un seul écrivain de secrets.conf, partagé avec `add`/`adopt` : c'est lui qui
    # garantit la conservation de l'inode dont dépend le mount du dashboard.
    conffile.write_text("".join(lines))
