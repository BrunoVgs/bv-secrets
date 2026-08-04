"""Presentation terminal : couleur et tables. Aucune logique metier.

Couleur seulement si stdout est un TTY, NO_COLOR absent et TERM != dumb ; sinon
texte brut, colonnes conservees (sortie pipee saine pour le scripting). Codes ANSI
bruts, aucune dependance.
"""
import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"


def _color_enabled() -> bool:
    return (sys.stdout.isatty()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb")


ON = _color_enabled()


def paint(text: str, *styles: str) -> str:
    if not ON or not styles:
        return text
    return "".join(styles) + text + RESET


def heading(text: str) -> str:
    return paint(text, BOLD)


# Cellule = str, ou (texte, style) pour la couleur.
def _text(cell) -> str:
    return str(cell[0] if isinstance(cell, tuple) else cell)


def _render(cell, width: int) -> str:
    t = _text(cell)
    padded = t.ljust(width) if width else t
    return paint(padded, cell[1]) if isinstance(cell, tuple) and cell[1] else padded


def table(rows, headers=None, gap: int = 2) -> str:
    """Colonnes alignees. La largeur se calcule sur le texte visible, la couleur
    est posee apres le padding pour ne pas fausser l'alignement."""
    grid = ([headers] if headers else []) + list(rows)
    ncol = max((len(r) for r in grid), default=0)
    widths = [0] * ncol
    for r in grid:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(_text(cell)))
    sep = " " * gap
    lines = []
    if headers:
        lines.append(paint(sep.join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip(), BOLD))
    for r in rows:
        cells = [_render(r[i] if i < len(r) else "", widths[i] if i < ncol - 1 else 0)
                 for i in range(ncol)]
        lines.append(sep.join(cells).rstrip())
    return "\n".join(lines)


# Classes of secret, coloured so the two families never have to be told apart by
# reading: API/token in yellow, auto-rotated passwords in red.
# Deux tables, parce qu'il y a deux questions. L'objet dit A QUI appartient la
# valeur -- c'est ce qui decide si tu peux la regenerer. La rotation dit QUAND.
OBJECT_STYLE = {
    "password": (RED, "MOTS DE PASSE", "les tiens : generables et rotables ici"),
    "token":    (YELLOW, "TOKENS / CLES API", "emis par l'app tierce : regenerer dedans, puis `set`"),
    "computed": (CYAN, "CALCULES", "derives d'autres secrets, jamais stockes"),
}

ROTATION_STYLE = {
    "auto":     (GREEN, "auto"),
    "ondemand": (MAGENTA, "sur demande"),
    "never":    (DIM, "jamais"),
}


def object_style(name: str):
    return OBJECT_STYLE.get(name, (DIM, name, ""))


def rotation_tag(name: str, width: int = 0):
    style, label = ROTATION_STYLE.get(name, (DIM, name))
    return (label.ljust(width) if width else label), style


def section(name: str) -> str:
    """Titre d'un bloc objet : le libelle colore, puis ce qu'il veut dire."""
    style, label, help_text = object_style(name)
    return paint(f"-- {label} ", style, BOLD) + paint(f"({help_text})", DIM)


_OUTCOME = {
    "allow": ("ok", GREEN),
    "deny": ("DENY", RED),
    "change": ("chg", YELLOW),
    "login": ("login", CYAN),
    "check": ("chk", DIM),
    "info": ("info", DIM),
}


def outcome(name: str, width: int = 5) -> str:
    """Libelle colore d'un outcome d'audit, pad a largeur fixe."""
    label, style = _OUTCOME.get(name, (name, DIM))
    return paint(label.ljust(width), style)
