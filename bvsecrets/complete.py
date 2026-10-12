"""Candidats d'autocompletion pour bash et zsh.

Un seul point de verite : les sous-commandes et leurs flags sont introspectes
depuis le parser argparse ; les valeurs dynamiques (noms de secrets, kinds, groups)
viennent de la config. Les deux shells appellent la commande cachee `__complete`.
"""
import argparse

from .config import GEN_KINDS, GROUPS, one_line


def _secrets():
    """nom -> ce qu'on en dit a cote dans le menu : le format, et la machine qui
    l'heberge. Les noms ne se devinent pas ; le menu doit suffire a choisir."""
    from .engine import Engine
    try:
        cfg = Engine().cfg
    except Exception:
        return {}
    return {name: c["kind"] + (f" @{c['host']}" if c.get("host") else "")
            + (f" — {one_line(c['note'])}" if c.get("note") else "") for name, c in sorted(cfg.items())}


def _service_names():
    from .engine import Engine
    try:
        return sorted(Engine().service_map())
    except Exception:
        return []


def _host_names():
    from . import hosts
    try:
        return {name: one_line(entry["note"]) or entry["url"] for name, entry in hosts.entries().items()}
    except Exception:
        return {}


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


# Sous-commandes dont l'argument libre est un nom de secret.
_TAKES_SECRET = {"get", "gen", "import", "set", "rm"}


def candidates(parser, words, cword):
    """-> {candidat: description}. La description peut etre vide."""
    subs = _subcommands(parser)
    plain = lambda items: {item: "" for item in items}
    if cword <= 1:
        return {name: (sp.description or "") for name, sp in subs.items()}
    sub = words[1] if len(words) > 1 else ""
    cur = words[cword] if cword < len(words) else ""
    prev = words[cword - 1] if 0 < cword <= len(words) else ""

    if prev in ("--only", "--service"):
        return _secrets()
    if prev == "--svc":
        return plain(_service_names())
    if prev == "--host":
        return _host_names()
    if prev == "--kind":
        return plain(sorted(GEN_KINDS))
    if prev == "--group":
        return plain(sorted(GROUPS))
    if prev == "--source" and sub == "audit":
        return plain(["all", "access", "trail", "host", "rotdate"])
    if prev == "completion":
        return plain(sorted(SCRIPTS))

    sp = subs.get(sub)
    if cur.startswith("-") and sp is not None:
        return plain(_options(sp))
    if sub in _TAKES_SECRET:
        return _secrets()
    if sub == "hosts":
        return _host_names()
    return {}


def matching(found: dict, cur: str) -> dict:
    """Ce qui commence par la saisie ; a defaut, ce qui la CONTIENT, sans casse.
    `get dash` doit trouver HERMES_DASHBOARD_PASSWORD : personne ne retient par
    quel mot un nom commence."""
    head = {c: d for c, d in found.items() if c.startswith(cur)}
    if head or not cur:
        return head
    needle = cur.lower()
    return {c: d for c, d in found.items() if needle in c.lower()}


def run(argv):
    """argv = [cword, word0, word1, ...] fourni par le script shell. Une ligne
    par candidat ; avec BV_COMPLETE_DESC, sa description suit une tabulation."""
    import os
    if not argv:
        return
    try:
        cword = int(argv[0])
    except ValueError:
        return
    words = argv[1:]
    from .cli import build_parser
    cur = words[cword] if cword < len(words) else ""
    described = bool(os.environ.get("BV_COMPLETE_DESC"))
    for cand, desc in matching(candidates(build_parser(), words, cword), cur).items():
        print(f"{cand}\t{desc[:70]}" if described and desc else cand)


# Les scripts que le shell charge. Un seul endroit : un paquet installe par pip
# n'a pas de dossier `completions/` a cote de lui.
SCRIPTS = {
    "zsh": r'''#compdef bv-secrets
# bv-secrets completion zsh > ~/.zsh/completions/_bv-secrets   (un dossier de $fpath)
_bv_secrets() {
    local -a lines names descs
    local line
    lines=( ${(f)"$(BV_COMPLETE_DESC=1 bv-secrets __complete $((CURRENT-1)) "${words[@]}" 2>/dev/null)"} )
    if (( ! ${#lines} )); then
        _files                       # scan, adopt : un chemin
        return
    fi
    for line in $lines; do
        names+=( "${line%%$'\t'*}" )
        descs+=( "${line//$'\t'/  }" )
    done
    if (( ${names[(I)${words[CURRENT]}*]} )); then
        compadd -l -d descs -a names
    else
        # Trouves par un morceau du nom (`get dash` -> HERMES_DASHBOARD_PASSWORD) :
        # le candidat REMPLACE la saisie, et on entre dans le menu tout de suite,
        # sinon zsh effacerait le morceau tape faute de prefixe commun.
        compstate[insert]=menu
        compadd -U -l -d descs -a names
    fi
}
if [[ $zsh_eval_context[-1] == loadautofunc ]]; then
    _bv_secrets "$@"
else
    compdef _bv_secrets bv-secrets
fi
''',
    "bash": r'''# source <(bv-secrets completion bash)
_bv_secrets_complete() {
    local IFS=$'\n'
    local out
    out=$(bv-secrets __complete "$COMP_CWORD" "${COMP_WORDS[@]}" 2>/dev/null)
    if [ -n "$out" ]; then
        COMPREPLY=( $out )
    else
        COMPREPLY=( $(compgen -f -- "${COMP_WORDS[COMP_CWORD]}") )   # scan, adopt : un chemin
    fi
}
complete -F _bv_secrets_complete bv-secrets
''',
}
