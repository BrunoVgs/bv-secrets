"""Inventaire des fichiers que bv-secrets gere, derive de secrets.conf.

`adopt` et `render` ne sont pas deux especes de fichier, ce sont deux etapes du
meme pipeline : adopter met un fichier sous gestion, rendre y ecrit les valeurs.
La vue liste donc UNE seule chose -- les fichiers geres -- et precise pour chacun
comment l'ecriture se fait :

  entier    bv-secrets fabrique tout le fichier (sinks `env:` et `file:`)
  cle a cle une seule valeur est reecrite, le reste du fichier ne bouge pas
            (`envfile:` `toml:` `yaml:` `json:` `ini:` `regex:`)

Rien n'est un second registre : tout se deduit des sinks declares, donc rien ne
peut diverger.

Lecture seule et sans valeur, comme le reste du tier web.
"""
from bvsecrets import Engine
from pathlib import Path

from bvsecrets.config import ADOPT_ROOTS, RENDER_DIR
from bvsecrets.locations import writable_schemes

_ADOPTED = writable_schemes() - {"env"}
_SCHEMES = _ADOPTED | {"file", "env"}


# Comment bv-secrets ecrit dans ce fichier. `env:` et `file:` produisent le
# fichier en entier ; tous les autres visent une cle et laissent le reste
# intact -- c'est la seule difference qui change quelque chose a l'usage.
_WHOLE = {"env", "file"}


def _write_mode(scheme):
    return "entier" if scheme in _WHOLE else "cle"


def _split(sink):
    """`scheme:target#selector` -> (scheme, target, selector). Le selecteur est
    optionnel : `file:/chemin` vise le fichier entier."""
    scheme, _, rest = sink.partition(":")
    target, _, selector = rest.partition("#")
    return scheme, target, selector


def _roots():
    return [str(r) for r in ADOPT_ROOTS]


def _in_scope(path):
    return any(path == r or path.startswith(r + "/") for r in _roots())


def list_data():
    """-> [{path, scheme, in_scope, secrets: [{name, selector, kind, group}]}]"""
    engine = Engine()
    by_path = {}
    for name in sorted(engine.cfg):
        conf = engine.cfg[name]
        for sink in conf["sinks"]:
            scheme, target, selector = _split(sink)
            if scheme not in _SCHEMES or not target:
                continue
            mode = _write_mode(scheme)
            # `env:svc#VAR` ne nomme pas un chemin : c'est render qui decide ou
            # le fichier atterrit. On le resout ici pour que la vue montre le
            # fichier reel, pas un nom de service.
            path = str(RENDER_DIR / f"{target}.env") if scheme == "env" else target
            entry = by_path.setdefault(path, {
                "path": path,
                "scheme": scheme,
                "mode": mode,
                "in_scope": _in_scope(path),
                "exists": Path(path.split(":")[0]).exists(),
                "secrets": [],
            })
            entry["secrets"].append({
                "name": name,
                "selector": selector,
                "kind": conf["kind"],
                "group": conf["group"],
            })
    return sorted(by_path.values(), key=lambda e: e["path"])


def data():
    files = list_data()
    return {
        "files": files,
        "roots": _roots(),
        "count": sum(len(f["secrets"]) for f in files),
        "by_mode": {m: sum(1 for f in files if f["mode"] == m)
                    for m in ("entier", "cle")},
    }
