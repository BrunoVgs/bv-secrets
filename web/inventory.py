"""Read-only inventory view for the UI. The dashboard has no write privilege: this
reads the read-only store and never returns a value, only presence and length."""
from bvsecrets import Engine, looks_like_apikey
from bvsecrets.config import GEN_KINDS, ROTATE_GROUPS


def has_linux_sink(cfg, name):
    return any(s.startswith("linux:") for s in cfg.get(name, {}).get("sinks", []))


def rotatable(cfg, name):
    """Rotatable from the web: generatable, rotatable group, and no `linux:` sink
    (whose doas elevation is interactive)."""
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
    """Secrets that "rotate the auto group" would target."""
    return Engine().select(None)


def get_value(name):
    engine = Engine()
    if name not in engine.cfg and name not in engine.data:
        return None
    return engine.value_of(name)
