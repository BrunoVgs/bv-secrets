"""Les instances bv-secrets joignables depuis celle-ci.

Chaque machine fait tourner son propre bv-secrets : son store, ses declarations,
son worker privilegie. Aucune ne lit le disque d'une autre. La seule chose qui
traverse le reseau est un job, depose dans le spool de l'hote vise par son
ecouteur HTTP — le meme schema de job que le spool local, donc le meme executeur
et les memes privileges de l'autre cote.

Les hotes se declarent dans la section `[hosts]` de `bv-secrets.ini` :

    [hosts]
    xeon = http://10.8.0.4:8765

La cle partagee ne vit PAS la : elle vient de `BV_HOST_KEY_<NOM>` ou du magasin
`<store>/hosts/<nom>.key` en 0600, pour qu'un fichier de config versionnable ne
porte jamais de secret.
"""
import hmac
import os
import re
from pathlib import Path

from .config import HOST_KEYS_DIR, HOSTS, ConfigError

# Un nom d'hote se retrouve dans un nom de fichier et dans un nom de variable
# d'environnement : le tenir a une forme sans surprise evite les deux pieges.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
SELF = "self"


def names() -> list:
    return sorted(HOSTS)


def url(name: str) -> str:
    if name not in HOSTS:
        known = ", ".join(names()) or "(aucun)"
        raise ConfigError(f"hôte inconnu: {name}. Déclarés: {known}")
    return HOSTS[name].rstrip("/")


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


def key_matches(presented, expected) -> bool:
    """Comparaison a temps constant, et refus net quand rien n'est configure :
    sans cle, l'ecouteur ne doit accepter personne plutot que tout le monde."""
    if not expected or not presented:
        return False
    return hmac.compare_digest(str(presented), str(expected))
