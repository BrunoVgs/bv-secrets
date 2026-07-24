"""Validation de la FORME d'une valeur, statique et sans effet de bord.

Distinct du `probe` (doctor), qui teste si la valeur MARCHE : ici on verifie
seulement qu'elle RESSEMBLE a ce qu'on attend, avant de l'ecrire dans le store ou
les fichiers. Regle vide = aucune contrainte.

Regles : ``regex:<motif>`` ``prefix:<s>`` ``suffix:<s>`` ``enum:a,b,c``
``len:<spec>`` ``int[:<spec>]`` ``url`` — ou <spec> vaut ``>=N`` ``<=N`` ``>N``
``<N`` ``N..M`` ``N``.
"""
import re

_OPS = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b, "<": lambda a, b: a < b}


def _cmp(spec: str, n: int):
    """(ok, attendu lisible) en comparant l'entier n a une spec."""
    spec = spec.strip()
    for op, fn in _OPS.items():
        if spec.startswith(op):
            x = int(spec[len(op):])
            return fn(n, x), f"{op}{x}"
    if ".." in spec:
        lo, hi = (int(x) for x in spec.split("..", 1))
        return lo <= n <= hi, f"entre {lo} et {hi}"
    x = int(spec)
    return n == x, f"= {x}"


def _dispatch(kind: str, arg: str, value: str):
    if kind == "regex":
        return None if re.search(arg, value) else f"ne correspond pas au motif /{arg}/"
    if kind == "prefix":
        return None if value.startswith(arg) else f"doit commencer par '{arg}'"
    if kind == "suffix":
        return None if value.endswith(arg) else f"doit finir par '{arg}'"
    if kind == "enum":
        allowed = [x.strip() for x in arg.split(",") if x.strip()]
        return None if value in allowed else f"doit valoir l'un de : {', '.join(allowed)}"
    if kind == "url":
        return None if re.match(r"^[a-zA-Z][\w+.-]*://\S+$", value) else "doit être une URL (scheme://...)"
    if kind == "len":
        ok, want = _cmp(arg, len(value))
        return None if ok else f"longueur {len(value)}, attendu {want}"
    if kind == "int":
        try:
            v = int(value)
        except ValueError:
            return "doit être un entier"
        if not arg:
            return None
        ok, want = _cmp(arg, v)
        return None if ok else f"valeur {v}, attendu {want}"
    return f"règle de validation inconnue : {kind}"


def check(rule: str, value: str):
    """-> message d'erreur, ou None si la valeur respecte la regle (ou regle vide)."""
    rule = (rule or "").strip()
    if not rule:
        return None
    kind, _, arg = rule.partition(":")
    try:
        return _dispatch(kind.strip(), arg.strip(), value)
    except ValueError:
        return f"règle de validation invalide : {rule}"
