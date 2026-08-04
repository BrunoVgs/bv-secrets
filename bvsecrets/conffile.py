"""Write the declaration file, whichever format it is in.

`append_sections` serves `add` (one section by hand) and `adopt` (several, inferred
from a file); `write_text` is the single primitive every writer goes through,
including the worker's surgical rewrite. Formatting stays readable and stable so the
file survives a human re-read.

Deux formats coexistent : l'INI historique et `secrets.yaml`. L'aiguillage vit ici
plutot que chez les appelants -- `add`, `adopt` et l'edition depuis le dashboard
passent tous par ces trois fonctions, et aucun n'a a savoir dans quoi il ecrit.
"""
import os

from . import conf_yaml
from .config import CONF, is_yaml


def write_text(text: str) -> None:
    """Rewrite secrets.conf IN PLACE, keeping the inode.

    Not a tmp-file + rename: rename swaps the inode, and secrets.conf is bind-mounted
    file-by-file into the dashboard container, which stays pinned to the inode it saw
    at start — it would serve a frozen config forever (same trap as the Caddyfile
    mount). One write() of the whole buffer keeps the exposure to a torn read down to
    the syscall itself, and the only reader re-reads on the next request."""
    data = text.encode("utf-8")
    fd = os.open(CONF, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def render_section(name, kind, group, sinks, length=0, note="", validate=""):
    if is_yaml():
        return conf_yaml.render_section(name, kind, group, sinks, length, note, validate)
    block = [f"[{name}]", f"kind  = {kind}", f"group = {group}"]
    if length:
        block.append(f"length = {length}")
    block.append("sinks =")
    block += [f"    {s}" for s in sinks]
    if validate:
        block.append(f"validate = {validate}")
    if note:
        block.append(f"note  = {note}")
    return "\n".join(block)


def append_sections(rendered_blocks):
    """Append one or more blocks to the end of the file, blank-line separated."""
    if is_yaml():
        return conf_yaml.append_sections(rendered_blocks)
    existing = CONF.read_text(encoding="utf-8") if CONF.exists() else ""
    tail = "\n\n".join(rendered_blocks)
    sep = "" if existing.endswith("\n\n") or not existing else ("\n" if existing.endswith("\n") else "\n\n")
    write_text(existing + sep + tail + "\n")
