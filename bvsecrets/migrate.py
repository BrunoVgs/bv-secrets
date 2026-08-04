"""Conversion secrets.conf (INI) -> secrets.yaml, sans perte.

La conversion est mecanique, mais elle doit etre prouvee : `equivalent()` relit
les deux fichiers avec leurs lecteurs respectifs et compare les dictionnaires
produits. Tant que ce n'est pas identique, on ne remplace rien.

Les gabarits ne sont pas devines a partir d'une heuristique de ressemblance :
seules les combinaisons (kind, group, length) qui reviennent au moins trois fois
deviennent une ancre. En dessous, factoriser rend le fichier moins lisible qu'il
ne l'etait, ce qui est l'inverse du but.
"""
from collections import Counter

from . import conf_yaml
from .config import ConfigError

MIN_USES = 3          # en deca, une ancre coute plus a lire qu'elle ne rapporte


def _signature(c):
    return (c["kind"], c["group"], c["length"])


def _template_name(sig):
    kind, group, length = sig
    base = f"{kind}-{group}" if group != "manual" else kind
    return f"{base}-{length}" if length else base


def plan_templates(cfg):
    """-> {signature: nom d'ancre} pour les combinaisons assez frequentes."""
    counts = Counter(_signature(c) for c in cfg.values())
    return {sig: _template_name(sig) for sig, n in counts.items() if n >= MIN_USES}


def render(cfg, header="") -> str:
    """Le YAML complet, gabarits compris."""
    templates = plan_templates(cfg)
    out = []
    if header:
        out.append(header.rstrip("\n"))
        out.append("")

    if templates:
        out.append("# Gabarits reutilisables (idiome `x-` de la Compose Specification).")
        out.append("# Un secret les reprend avec `<<: *nom` et surcharge ce qui differe.")
        for sig, name in sorted(templates.items(), key=lambda kv: kv[1]):
            kind, group, length = sig
            fields = f"kind: {kind}, group: {group}"
            if length:
                fields += f", length: {length}"
            out.append(f"x-{name}: &{name} {{ {fields} }}")
        out.append("")

    out.append("secrets:")
    for name in sorted(cfg):
        c = cfg[name]
        sig = _signature(c)
        tpl = templates.get(sig)
        block = ["", f"  {name}:"]
        if tpl:
            block.append(f"    <<: *{tpl}")
        else:
            block.append(f"    kind: {c['kind']}")
            block.append(f"    group: {c['group']}")
            if c["length"]:
                block.append(f"    length: {c['length']}")
        for field in ("compute", "probe", "validate", "note"):
            if c[field]:
                block.append(f"    {field}: {_scalar(c[field])}")
        for field in ("sinks", "norestart"):
            if c[field]:
                block.append(f"    {field}:")
                block += [f"      - {_scalar(v)}" for v in c[field]]
        out += block
    return "\n".join(out) + "\n"


def _scalar(v: str) -> str:
    """Cite ce qui casserait la relecture. Un `#` colle ne gene pas (les sinks en
    contiennent tous), un ` #` oui : il ouvrirait un commentaire. Les notes de
    l'INI peuvent etre multi-lignes ; echappees, elles tiennent sur une ligne
    physique et se relisent a l'identique."""
    v = str(v)
    if not v:
        return '""'
    if any(c in v for c in "\n\t\\"):
        return '"' + (v.replace("\\", "\\\\").replace('"', '\\"')
                       .replace("\n", "\\n").replace("\t", "\\t")) + '"'
    if v[0] in "&*{[|>#\"'" or " #" in v or v.strip() != v or ": " in v:
        return '"' + v.replace('"', '\\"') + '"'
    return v


def equivalent(ini_cfg, yaml_cfg):
    """-> [] si les deux configs disent exactement la meme chose, sinon les ecarts."""
    diffs = []
    for name in sorted(set(ini_cfg) | set(yaml_cfg)):
        a, b = ini_cfg.get(name), yaml_cfg.get(name)
        if a is None:
            diffs.append(f"{name}: present seulement dans le YAML")
            continue
        if b is None:
            diffs.append(f"{name}: perdu a la conversion")
            continue
        for field in sorted(set(a) | set(b)):
            if a.get(field) != b.get(field):
                diffs.append(f"{name}.{field}: {a.get(field)!r} -> {b.get(field)!r}")
    return diffs


def convert(ini_cfg, header="") -> str:
    """Rend le YAML et refuse de le retourner s'il ne relit pas a l'identique."""
    text = render(ini_cfg, header)
    reread = {}
    doc = conf_yaml.parse(text)
    anchors = doc["anchors"]
    for name, block in doc["secrets"].items():
        b = conf_yaml._merge(block, anchors, name)
        entry = {f: str(b.get(f, "")).strip() for f in conf_yaml.TEXT_FIELDS}
        entry["kind"] = entry["kind"] or "manual"
        entry["group"] = entry["group"] or "manual"
        for f in conf_yaml.LIST_FIELDS:
            v = b.get(f, [])
            entry[f] = [str(x).strip() for x in v] if isinstance(v, list) else []
        for f in conf_yaml.INT_FIELDS:
            raw = str(b.get(f, "") or "").strip()
            entry[f] = int(raw) if raw else 0
        reread[name] = entry
    diffs = equivalent(ini_cfg, reread)
    if diffs:
        raise ConfigError("conversion non fidele, rien n'a ete ecrit :\n  "
                          + "\n  ".join(diffs[:20]))
    return text
