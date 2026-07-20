"""Ajout de sections à secrets.conf.

Partagé par `add` (une section à la main) et `adopt` (plusieurs, déduites d'un
fichier). L'écriture est atomique ; la mise en forme reste lisible et stable pour
que le fichier survive à une relecture par un humain.
"""
from .config import CONF


def render_section(name, kind, group, sinks, length=0, note=""):
    block = [f"[{name}]", f"kind  = {kind}", f"group = {group}"]
    if length:
        block.append(f"length = {length}")
    block.append("sinks =")
    block += [f"    {s}" for s in sinks]
    if note:
        block.append(f"note  = {note}")
    return "\n".join(block)


def append_sections(rendered_blocks):
    """Ajoute un ou plusieurs blocs à la fin de secrets.conf, séparés par une ligne."""
    existing = CONF.read_text(encoding="utf-8") if CONF.exists() else ""
    tail = "\n\n".join(rendered_blocks)
    tmp = CONF.with_suffix(".conf.tmp")
    sep = "" if existing.endswith("\n\n") or not existing else ("\n" if existing.endswith("\n") else "\n\n")
    tmp.write_text(existing + sep + tail + "\n", encoding="utf-8")
    tmp.replace(CONF)
