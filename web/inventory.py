"""Vue lecture seule de l'inventaire, telle que consommée par l'UI.

Le dashboard n'a aucun privilège d'écriture : ce module lit le store monté en
read-only et ne renvoie jamais de valeur, seulement leur présence et leur longueur.
"""
from bvsecrets import Engine, looks_like_apikey
from bvsecrets.config import GEN_KINDS, ROTATE_GROUPS


def has_linux_sink(cfg, name):
    return any(s.startswith("linux:") for s in cfg.get(name, {}).get("sinks", []))


def rotatable(cfg, name):
    """Rotable depuis le web : générable, groupe rotable, et sans sink `linux:`
    dont l'élévation doas est interactive."""
    c = cfg.get(name)
    return bool(c) and c["kind"] in GEN_KINDS and c["group"] in ROTATE_GROUPS \
        and not has_linux_sink(cfg, name)


def _row(engine, name, meta):
    c = engine.cfg[name]
    value = engine.value_of(name)
    return {
        "name": name,
        "kind": c["kind"],
        "group": c["group"],
        "present": bool(value),
        "len": len(value),
        "services": sorted({s[4:].split("#", 1)[0] for s in c["sinks"] if s.startswith("env:")}),
        "sink_types": sorted({s.split(":", 1)[0] for s in c["sinks"]}),
        "note": c["note"],
        "rotatable": rotatable(engine.cfg, name),
        "has_linux": has_linux_sink(engine.cfg, name),
        "probed": bool(c.get("probe")) or any(s.startswith(("mysql:", "env:")) for s in c["sinks"]),
        "last_set": meta.get(name, ""),
        "computed": c["kind"] == "computed",
        "apikey": c["kind"] == "apikey" or looks_like_apikey(name),
    }


def list_data():
    engine = Engine()
    meta = engine.meta()
    return [_row(engine, n, meta) for n in sorted(engine.cfg)]


def auto_targets():
    """Secrets que « roter le groupe auto » viserait."""
    return Engine().select(None)


def get_value(name):
    engine = Engine()
    if name not in engine.cfg and name not in engine.data:
        return None
    return engine.value_of(name)
