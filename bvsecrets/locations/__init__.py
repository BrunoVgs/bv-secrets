"""Connecteurs de localisation : lire ET ecrire une valeur la ou elle vit.

Bidirectionnel, pas seulement en ecriture : `read` extrait la valeur en place,
`write` la remplace. C'est ce qui permet d'adopter un fichier existant, de viser
une seule valeur dans une conf structuree, et de detecter les derives.

Ecriture chirurgicale : seule la valeur ciblee change ; commentaires, ordre et
indentation restent identiques octet pour octet. Aucun parseur ne reecrit tout le
fichier, aucune dependance externe.

Adressage : ``scheme:target#selector``
    envfile:/chemin/.env#CLE          une cle dans un fichier CLE=VALEUR
    regex:/chemin/fichier#<motif>     groupe 1 d'un motif (catch-all)
    file:/chemin                      le fichier entier comme valeur
    json:/chemin/conf.json#a.b.c      une valeur a un chemin JSON
    yaml:/chemin/conf.yaml#a.b.c      un scalaire a un chemin YAML
    ini:/chemin/conf.ini#section.cle  une cle dans une section INI
    toml:/chemin/conf.toml#a.b.c      une cle dans une table TOML
    sqlite:/base.db@ctr#t.col?id=1    une cellule, la condition visant UNE ligne
"""
from . import db, envfile, structured, text
from .base import LocationError, atomic_write, split

_READERS = {
    "envfile": envfile.read,
    "regex": text.regex_read,
    "file": text.file_read,
    "json": structured.json_read,
    "yaml": structured.yaml_read,
    "ini": structured.ini_read,
    "toml": structured.toml_read,
    "sqlite": db.read,
}
_WRITERS = {
    "envfile": envfile.write,
    "regex": text.regex_write,
    "file": text.file_write,
    "json": structured.json_write,
    "yaml": structured.yaml_write,
    "ini": structured.ini_write,
    "toml": structured.toml_write,
    "sqlite": db.write,
}


def readable_schemes():
    return set(_READERS)


def writable_schemes():
    return set(_WRITERS)


def env_keys(target: str):
    """Cles d'un fichier .env, pour `scan`."""
    return envfile.keys(target)


def read_location(location: str):
    """Valeur en place, ou None si absente. Leve si le schema ne sait pas lire."""
    scheme, target, selector = split(location)
    reader = _READERS.get(scheme)
    if not reader:
        raise LocationError(f"schema non lisible: {scheme}")
    return reader(target, selector)


def write_location(location: str, value: str):
    scheme, target, selector = split(location)
    writer = _WRITERS.get(scheme)
    if not writer:
        raise LocationError(f"schema non inscriptible: {scheme}")
    writer(target, selector, value)
