"""Lecture et ecriture de secrets.yaml -- sous-ensemble restreint de YAML.

Pourquoi pas PyYAML : le projet revendique zero dependance, et cette propriete
est verifiee par la CI. Pourquoi pas INI : il n'a ni valeurs par defaut
reutilisables ni imbrication, donc le bloc de durcissement d'un secret se
recopie a la main a chaque section.

Le sous-ensemble est volontairement pauvre, et c'est ce qui rend un parseur
maison raisonnable :

    x-password: &password { kind: password, length: 20, group: auto }

    include:
      - secrets.media.yaml

    secrets:
      PIHOLE_ADMIN_PASSWORD:
        <<: *password
        length: 14
        sinks:
          - env:pihole#FTLCONF_webserver_api_password
        note: mdp/API Pi-hole

Admis : mappings par blocs, listes `-`, mappings en flux sur UNE ligne (pour les
gabarits `x-`), ancres `&nom`, alias `*nom`, cle de fusion `<<`, commentaires.
Exclu : multi-documents, tags, blocs scalaires `|` et `>`, listes en flux,
imbrication au-dela de ce que montre l'exemple. Une construction non geree leve
une erreur nommant la ligne, plutot que de deviner.

L'ecriture reste par blocs de lignes, comme pour l'INI : commentaires et mise en
forme d'origine survivent a un `adopt` ou a une edition depuis le dashboard.
"""
import os
import re

from .config import CONF, ConfigError

# Un `#` ne commence un commentaire que precede d'un espace ou en debut de ligne.
# Sans cette regle, `env:pihole#FTLCONF_webserver_api_password` perdrait sa moitie
# droite : le selecteur d'un sink est separe par un `#` colle.
_KEY = re.compile(r"^([A-Za-z0-9_.\-<]+)\s*:\s*(.*)$")
_ANCHOR = re.compile(r"^&([A-Za-z0-9_-]+)\s*(.*)$")

# Champs d'un secret, et comment les rendre dans la sortie de _load_conf().
LIST_FIELDS = ("sinks", "norestart")
TEXT_FIELDS = ("kind", "group", "compute", "probe", "validate", "note")
INT_FIELDS = ("length",)

# Cles de premier niveau qui decrivent la machine plutot que des secrets.
HOST_KEYS = ("egress", "audit")


def _strip_comment(line: str) -> str:
    """Retire un commentaire de fin de ligne, sans toucher a ce qui est entre
    guillemets. Deux pieges reels dans ce depot : un sink porte un `#` colle
    (`env:pihole#FTLCONF_...`), et une regle `validate` citee contient un ` #`
    qui fait partie de la valeur. Ignorer les guillemets tronquait la seconde."""
    quote, i = None, 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
        i += 1
    return line


def _unquote(v: str) -> str:
    """Un scalaire entre guillemets doubles peut porter des echappements : c'est
    le seul moyen de garder une note multi-lignes sur une ligne physique, sans
    quoi elle serait relue comme une nouvelle cle."""
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] == '"':
        body, out, i = v[1:-1], [], 0
        while i < len(body):
            if body[i] == "\\" and i + 1 < len(body):
                out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(body[i + 1], body[i + 1]))
                i += 2
            else:
                out.append(body[i])
                i += 1
        return "".join(out)
    if len(v) >= 2 and v[0] == v[-1] == "'":
        return v[1:-1]
    return v


def _parse_inline_list(v: str):
    """`[a, b, c]` -> liste. Le seul flux admis hors des gabarits : une liste de
    CIDR sur une ligne se lit mieux que quatre lignes de tirets."""
    s = v.strip()
    if s.startswith("[") and s.endswith("]"):
        return [_unquote(x) for x in s[1:-1].split(",") if x.strip()]
    return _unquote(s)


def _parse_flow(text: str, where: str) -> dict:
    """`{ kind: password, length: 20 }` -> dict. Une seule ligne, pas d'imbrication."""
    inner = text.strip()[1:-1]
    out = {}
    for part in inner.split(","):
        if not part.strip():
            continue
        key, sep, val = part.partition(":")
        if not sep:
            raise ConfigError(f"{where}: `{part.strip()}` n'est pas `cle: valeur`")
        out[key.strip()] = _unquote(val)
    return out


def _lines(text: str):
    """-> [(numero, indentation, contenu)] pour les lignes signifiantes."""
    out = []
    for i, raw in enumerate(text.splitlines(), 1):
        body = _strip_comment(raw).rstrip()
        if not body.strip():
            continue
        if "\t" in body[: len(body) - len(body.lstrip())]:
            raise ConfigError(f"ligne {i}: tabulation en indentation, utiliser des espaces")
        out.append((i, len(body) - len(body.lstrip()), body.strip()))
    return out


def parse(text: str) -> dict:
    """-> {"anchors": {...}, "include": [...], "secrets": {NOM: {champ: valeur}}}"""
    anchors, include, secrets, host = {}, [], {}, {}
    rows = _lines(text)
    i = 0
    while i < len(rows):
        num, indent, body = rows[i]
        if indent != 0:
            raise ConfigError(f"ligne {num}: indentation inattendue au premier niveau")
        m = _KEY.match(body)
        if not m:
            raise ConfigError(f"ligne {num}: `{body}` n'est pas une cle de premier niveau")
        key, rest = m.group(1), m.group(2).strip()

        if key.startswith("x-"):
            am = _ANCHOR.match(rest)
            if not am:
                raise ConfigError(f"ligne {num}: un gabarit x- doit porter une ancre `&nom`")
            name, payload = am.group(1), am.group(2).strip()
            if payload.startswith("{"):
                anchors[name] = _parse_flow(payload, f"ligne {num}")
                i += 1
            else:
                block, i = _read_block(rows, i + 1, num)
                anchors[name] = block
            continue

        if key == "include":
            items, i = _read_list(rows, i + 1)
            include = items
            continue

        if key == "secrets":
            secrets, i = _read_secrets(rows, i + 1)
            continue

        # `egress:` et `audit:` decrivent la posture de la machine, pas des
        # secrets. Elles sont lues ici et servies a bvsecrets.host ; la liste
        # reste fermee, pour qu'une cle mal tapee se voie tout de suite.
        if key in HOST_KEYS:
            block, i = _read_nested(rows, i + 1)
            host[key] = block
            continue

        raise ConfigError(
            f"ligne {num}: cle de premier niveau inconnue `{key}` "
            f"(attendu : x-*, include, secrets, {', '.join(sorted(HOST_KEYS))})")

    return {"anchors": anchors, "include": include, "secrets": secrets, "host": host}


def _read_list(rows, i):
    """Consomme les `- ...` consecutifs. S'arreter au premier non-element est ce
    qui borne la liste : la cle suivante est plus indentee que zero, donc un test
    sur l'indentation seule avalerait le secret d'apres."""
    items = []
    while i < len(rows) and rows[i][1] > 0 and rows[i][2].startswith("- "):
        items.append(_unquote(rows[i][2][2:]))
        i += 1
    return items, i


def _read_block(rows, i, parent_num):
    """Un mapping indente : champs scalaires et listes, pas de sous-mapping."""
    if i >= len(rows):
        raise ConfigError(f"ligne {parent_num}: bloc vide")
    base = rows[i][1]
    out = {}
    while i < len(rows) and rows[i][1] >= base:
        num, indent, body = rows[i]
        if indent != base:
            raise ConfigError(f"ligne {num}: indentation irreguliere dans le bloc")
        m = _KEY.match(body)
        if not m:
            raise ConfigError(f"ligne {num}: `{body}` n'est pas `cle: valeur`")
        key, rest = m.group(1), m.group(2).strip()
        if rest:
            out[key] = (_parse_flow(rest, f"ligne {num}") if rest.startswith("{")
                        else _parse_inline_list(rest))
            i += 1
        else:
            items, i = _read_list(rows, i + 1)
            out[key] = items
    return out, i


def _read_nested(rows, i):
    """`cle: { nom: {champs} }` -- deux niveaux, comme `egress:` et `audit:`."""
    if i >= len(rows):
        return {}, i
    base = rows[i][1]
    out = {}
    while i < len(rows) and rows[i][1] >= base:
        num, indent, body = rows[i]
        if indent != base:
            raise ConfigError(f"ligne {num}: indentation irreguliere")
        m = _KEY.match(body)
        if not m:
            raise ConfigError(f"ligne {num}: `{body}` n'est pas `cle:`")
        name, rest = m.group(1), m.group(2).strip()
        if rest:
            out[name] = _parse_flow(rest, f"ligne {num}") if rest.startswith("{") \
                else _parse_inline_list(rest)
            i += 1
        else:
            out[name], i = _read_block(rows, i + 1, num)
    return out, i


def _read_secrets(rows, i):
    if i >= len(rows):
        return {}, i
    base = rows[i][1]
    out = {}
    while i < len(rows) and rows[i][1] >= base:
        num, indent, body = rows[i]
        if indent != base:
            raise ConfigError(f"ligne {num}: indentation irreguliere sous `secrets:`")
        m = _KEY.match(body)
        if not m or m.group(2).strip():
            raise ConfigError(f"ligne {num}: attendu `NOM:` seul sur sa ligne")
        name = m.group(1)
        block, i = _read_block(rows, i + 1, num)
        out[name] = block
    return out, i


def _merge(block: dict, anchors: dict, name: str) -> dict:
    """Applique `<<: *gabarit`. Les cles posees en propre gagnent, comme en YAML."""
    ref = block.get("<<")
    if ref is None:
        return dict(block)
    if not (isinstance(ref, str) and ref.startswith("*")):
        raise ConfigError(f"{name}: `<<` attend un alias `*nom`")
    tpl = anchors.get(ref[1:])
    if tpl is None:
        raise ConfigError(f"{name}: gabarit `{ref}` jamais defini")
    merged = dict(tpl)
    merged.update({k: v for k, v in block.items() if k != "<<"})
    return merged


def load(path=None) -> dict:
    """-> la meme forme que le lecteur INI : {NOM: {kind, length, group, sinks, ...}}"""
    path = CONF if path is None else path
    doc = parse(path.read_text(encoding="utf-8"))
    anchors = dict(doc["anchors"])
    secrets = dict(doc["secrets"])

    for rel in doc["include"]:
        sub = (path.parent / rel)
        if not sub.exists():
            raise ConfigError(f"include: {rel} introuvable a cote de {path.name}")
        part = parse(sub.read_text(encoding="utf-8"))
        anchors.update(part["anchors"])
        for name, block in part["secrets"].items():
            if name in secrets:
                raise ConfigError(f"{name}: declare deux fois ({rel} et {path.name})")
            secrets[name] = block

    out = {}
    for name, block in secrets.items():
        b = _merge(block, anchors, name)
        entry = {f: str(b.get(f, "")).strip() for f in TEXT_FIELDS}
        entry["kind"] = entry["kind"] or "manual"
        entry["group"] = entry["group"] or "manual"
        for f in LIST_FIELDS:
            v = b.get(f, [])
            entry[f] = [str(x).strip() for x in v if str(x).strip()] if isinstance(v, list) \
                else [str(v).strip()] if str(v).strip() else []
        for f in INT_FIELDS:
            raw = str(b.get(f, "") or "").strip()
            entry[f] = int(raw) if raw else 0
        out[name] = entry
    return out


# --------------------------------------------------------------------------- #
# Ecriture
# --------------------------------------------------------------------------- #

def render_section(name, kind, group, sinks, length=0, note="", validate="",
                   template="", indent="  ") -> str:
    """Un bloc `NOM:` pret a inserer sous `secrets:`, indentation comprise."""
    f = indent * 2
    out = [f"{indent}{name}:"]
    if template:
        out.append(f"{f}<<: *{template}")
    else:
        out.append(f"{f}kind: {kind}")
        out.append(f"{f}group: {group}")
    if length:
        out.append(f"{f}length: {length}")
    if sinks:
        out.append(f"{f}sinks:")
        out += [f"{f}{indent}- {s}" for s in sinks]
    if validate:
        out.append(f"{f}validate: {validate}")
    if note:
        out.append(f"{f}note: {note}")
    return "\n".join(out)


def write_text(text: str, path=None) -> None:
    """Reecrit le fichier SUR PLACE, inode conserve.

    Pas de tmp + rename : le rename change l'inode, et le fichier est bind-monte
    fichier par fichier dans le conteneur du dashboard, qui reste accroche a
    l'inode vu au demarrage -- il servirait une config figee pour toujours."""
    target = CONF if path is None else path
    data = text.encode("utf-8")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def append_sections(rendered_blocks, path=None) -> None:
    """Ajoute des blocs a la fin de la cle `secrets:`, une ligne vide entre eux."""
    target = CONF if path is None else path
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    if not re.search(r"^secrets:\s*$", existing, re.M):
        existing = (existing.rstrip("\n") + "\n\nsecrets:\n") if existing.strip() else "secrets:\n"
    body = existing.rstrip("\n")
    write_text(body + "\n\n" + "\n\n".join(rendered_blocks) + "\n", target)
