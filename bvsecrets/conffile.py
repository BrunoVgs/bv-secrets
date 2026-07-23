"""Append sections to secrets.conf.

Shared by `add` (one section by hand) and `adopt` (several, inferred from a file).
Atomic write; formatting stays readable and stable so the file survives a human
re-read.
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
    """Append one or more blocks to the end of secrets.conf, blank-line separated."""
    existing = CONF.read_text(encoding="utf-8") if CONF.exists() else ""
    tail = "\n\n".join(rendered_blocks)
    tmp = CONF.with_suffix(".conf.tmp")
    sep = "" if existing.endswith("\n\n") or not existing else ("\n" if existing.endswith("\n") else "\n\n")
    tmp.write_text(existing + sep + tail + "\n", encoding="utf-8")
    tmp.replace(CONF)
