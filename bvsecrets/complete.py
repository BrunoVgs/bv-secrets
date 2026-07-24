"""Candidats d'autocompletion pour bash et zsh.

Un seul point de verite : les sous-commandes et leurs flags sont introspectes
depuis le parser argparse ; les valeurs dynamiques (noms de secrets, kinds, groups)
viennent de la config. Les deux shells appellent la commande cachee `__complete`.
"""
import argparse

from .config import GEN_KINDS, GROUPS


def _secret_names():
    from .engine import Engine
    try:
        return sorted(Engine().cfg)
    except Exception:
        return []


def _subcommands(parser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return {name: sp for name, sp in action.choices.items()
                    if not name.startswith("__")}
    return {}


def _options(subparser):
    out = []
    for action in subparser._actions:
        out += action.option_strings
    return out


def candidates(parser, words, cword):
    subs = _subcommands(parser)
    if cword <= 1:
        return list(subs)
    sub = words[1] if len(words) > 1 else ""
    cur = words[cword] if cword < len(words) else ""
    prev = words[cword - 1] if 0 < cword <= len(words) else ""

    if prev in ("--only", "--service"):
        return _secret_names()
    if prev == "--kind":
        return sorted(GEN_KINDS)
    if prev == "--group":
        return sorted(GROUPS)
    if prev == "--source" and sub == "audit":
        return ["all", "access", "trail", "host", "rotdate"]

    sp = subs.get(sub)
    if cur.startswith("-") and sp is not None:
        return _options(sp)
    if sub in ("get", "gen", "import"):
        return _secret_names()
    return []


def run(argv):
    """argv = [cword, word0, word1, ...] fourni par le script shell."""
    if not argv:
        return
    try:
        cword = int(argv[0])
    except ValueError:
        return
    words = argv[1:]
    from .cli import build_parser
    cur = words[cword] if cword < len(words) else ""
    for cand in candidates(build_parser(), words, cword):
        if cand.startswith(cur):
            print(cand)
