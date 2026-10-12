"""Les instances bv-secrets joignables depuis celle-ci.

Chaque machine fait tourner son propre bv-secrets : son store, ses declarations,
son worker privilegie. Aucune ne lit le disque d'une autre. La seule chose qui
traverse le reseau est un job, depose dans le spool de l'hote vise par son
ecouteur HTTP — le meme schema de job que le spool local, donc le meme executeur
et les memes privileges de l'autre cote.

Le registre des instances vit dans le store (`<store>/hosts/registry.json`), ou
le worker l'ecrit quand on ajoute une instance depuis le dashboard ou par
`bv-secrets hosts add`. La section `[hosts]` de `bv-secrets.ini` reste lue, pour
qui prefere declarer ses machines dans un fichier versionne ; a nom egal, le
registre l'emporte.

    bv-secrets hosts xeon --url http://10.8.0.4:8765

La cle partagee ne vit PAS dans ces fichiers : elle vient de `BV_HOST_KEY_<NOM>` ou du magasin
`<store>/hosts/<nom>.key` en 0600, pour qu'un fichier de config versionnable ne
porte jamais de secret. Elle ne circule pas non plus sur le reseau : elle SIGNE
les requetes (voir `bvsecrets.sign`).
"""
import json
import os
import re
from pathlib import Path

from .config import HOST_KEYS_DIR, HOSTS, REPO_URL, ConfigError

REGISTRY = HOST_KEYS_DIR / "registry.json"
# Cible ssh d'un envoi d'instance : `compte@machine` ou un alias de ~/.ssh/config.
# Jamais un tiret en tete, qui se lirait comme une option de ssh.
SSH_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@:\-]{0,127}$")
KEY_RE = re.compile(r"^[A-Za-z0-9_\-]{20,128}$")
URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+(:\d{1,5})?$")

# Un nom d'hote se retrouve dans un nom de fichier et dans un nom de variable
# d'environnement : le tenir a une forme sans surprise evite les deux pieges.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
SELF = "self"


def _registry() -> dict:
    """Relu a chaque appel : le dashboard tourne des jours, et une instance
    ajoutee par le worker doit y apparaitre sans redemarrage."""
    try:
        data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def entries() -> dict:
    """nom -> {url, note, source}. `source` dit ou l'instance est declaree, donc
    ce qui peut la modifier : le registre s'edite d'ici, le .ini a la main."""
    merged = {n: {"url": u.rstrip("/"), "note": "", "source": "ini"} for n, u in HOSTS.items()}
    for name, entry in _registry().items():
        if isinstance(entry, dict) and entry.get("url"):
            merged[name] = {"url": str(entry["url"]).rstrip("/"),
                            "note": str(entry.get("note") or ""), "source": "registry"}
    return merged


def names() -> list:
    return sorted(entries())


def url(name: str) -> str:
    known = entries()
    if name not in known:
        raise ConfigError(f"hôte inconnu: {name}. Déclarés: {', '.join(sorted(known)) or '(aucun)'}")
    return known[name]["url"]


def _write_registry(data: dict):
    REGISTRY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = REGISTRY.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    tmp.replace(REGISTRY)


def save(name: str, address: str, note: str = ""):
    """Ajoute ou modifie une instance du registre."""
    if not NAME_RE.match(name or "") or name == SELF:
        raise ConfigError(f"nom d'hôte invalide: {name!r} (minuscules, chiffres, - et _)")
    address = (address or "").strip().rstrip("/")
    if not URL_RE.match(address):
        raise ConfigError(f"URL invalide: {address!r} (attendu http://adresse:port)")
    data = _registry()
    data[name] = {"url": address, "note": " ".join((note or "").split())[:200]}
    _write_registry(data)


def deploy(name: str, target: str, log=print, timeout=300):
    """Envoie une instance sur la machine `target`, par ssh : le code, le store,
    la cle partagee, le service du worker et son ecouteur. L'instance doit deja
    etre au registre -- c'est son URL qui dit ou l'ecouteur doit se lier.

    La cle voyage dans l'entree standard de ssh, jamais dans une ligne de
    commande. Tout ce qui s'execute la-bas est `remote-install.sh`, a cote de ce module."""
    import subprocess
    if not SSH_RE.match(target or ""):
        raise ConfigError(f"cible ssh invalide: {target!r}")
    address = re.match(r"^https?://\[?([^\]/]+?)\]?:(\d+)$", url(name))
    if not address:
        raise ConfigError(f"{name}: l'URL doit porter un port ({url(name)})")
    secret = key(name)
    if not secret or not KEY_RE.match(secret):
        raise ConfigError(f"{name}: clé absente ou de forme inattendue "
                          f"(`bv-secrets hosts {name} --key -`)")
    script = (Path(__file__).parent / "remote-install.sh").read_text(encoding="utf-8")
    done = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", target,
         "sh", "-s", "--", address[1], address[2], REPO_URL],
        input=f"KEY='{secret}'\n{script}", capture_output=True, text=True, timeout=timeout)
    for line in (done.stdout + done.stderr).splitlines():
        log(f"  {target}| {line}")
    if done.returncode != 0:
        raise ConfigError(f"{name}: envoi interrompu sur {target} (code {done.returncode})")


def remove(name: str):
    """Retire une instance du registre, et sa cle. Les secrets qui la nomment
    encore sont signales par `check` : on ne les efface pas pour elle."""
    data = _registry()
    if name not in data:
        where = "bv-secrets.ini (à retirer à la main)" if name in HOSTS else "nulle part"
        raise ConfigError(f"{name}: absent du registre, déclaré dans {where}")
    del data[name]
    _write_registry(data)
    key_path(name).unlink(missing_ok=True)


def key_path(name: str) -> Path:
    if not NAME_RE.match(name or ""):
        raise ConfigError(f"nom d'hôte invalide: {name!r}")
    return HOST_KEYS_DIR / f"{name}.key"


def key(name: str):
    """Cle partagee avec cet hote, ou None. L'env l'emporte sur le magasin, comme
    partout ailleurs dans la config."""
    if not NAME_RE.match(name or ""):
        raise ConfigError(f"nom d'hôte invalide: {name!r}")
    from_env = os.environ.get(f"BV_HOST_KEY_{name.upper().replace('-', '_')}")
    if from_env:
        return from_env.strip()
    path = key_path(name)
    if path.exists():
        try:
            return path.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None
    return None


def write_key(name: str, value: str) -> Path:
    """Pose la cle en 0600, mode fixe a la creation."""
    path = key_path(name)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(value.strip() + "\n")
    return path


def local_key():
    """Cle que CETTE instance exige de ses appelants. `BV_WORKER_KEY` d'abord,
    puis `<store>/hosts/self.key`."""
    from_env = os.environ.get("BV_WORKER_KEY")
    if from_env:
        return from_env.strip()
    return key(SELF)
