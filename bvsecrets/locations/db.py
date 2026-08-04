"""sqlite: une cellule d'une base SQLite, sur l'hote ou dans un conteneur.

    sqlite:/chemin/base.db[@conteneur]#table.colonne?cle=valeur[&cle=valeur]

La condition doit designer EXACTEMENT une ligne. Un fichier de conf a une ancre
naturelle -- la ligne de la cle ; une table n'en a pas, et un UPDATE trop large
ecrase des lignes voisines sans rien laisser voir. Le connecteur compte donc
avant d'agir, et refuse 0 comme 2.

Deux executeurs pour un seul jeu de SQL : le module stdlib quand le fichier est
lisible ici, `docker exec sqlite3` quand la base vit dans un volume root d'un
conteneur. Ce second cas est le plus courant et c'est le seul moyen d'y toucher
sans elevation, l'hote n'ayant pas le droit de lire le volume. Il suppose en
revanche un binaire `sqlite3` DANS l'image visee ; sans lui la sortie de docker
remonte telle quelle et dit ce qui manque. Le chemin local, lui, ne demande que
la stdlib et marche partout.

L'ecriture ne fait qu'UPDATE, jamais INSERT : inventer une ligne demanderait de
remplir des colonnes dont un gestionnaire de secrets ne sait rien.
"""
import re
import sqlite3
import subprocess
from pathlib import Path

from .base import LocationError

# Les identifiants (table, colonne, cles de condition) sont bornes a \w : ils
# entrent tels quels dans le SQL, ou aucun binding n'existe cote `docker exec`.
# Les VALEURS, elles, passent toutes par _lit().
_SELECTOR = re.compile(r"^(\w+)\.(\w+)\?(.+)$", re.S)


def _parse(target: str, selector: str):
    path, _, container = target.partition("@")
    if not path:
        raise LocationError(f"chemin de base sqlite absent: {target}")
    m = _SELECTOR.match(selector or "")
    if not m:
        raise LocationError(
            f"selecteur attendu `table.colonne?cle=valeur`, recu: {selector!r}")
    table, column, where = m.groups()
    pairs = []
    for chunk in where.split("&"):
        key, sep, value = chunk.partition("=")
        key = key.strip()
        if not sep or not re.fullmatch(r"\w+", key):
            raise LocationError(f"condition malformee: {chunk!r}")
        pairs.append((key, value))
    return path, container, table, column, pairs


def _lit(value) -> str:
    """Litteral chaine SQLite. Doubler l'apostrophe est le seul echappement du
    format, et le seul disponible cote `docker exec` faute de binding."""
    return "'" + str(value).replace("'", "''") + "'"


def _clause(pairs) -> str:
    return " AND ".join(f"{k} = {_lit(v)}" for k, v in pairs)


def _docker(container: str, path: str, sql: str) -> str:
    r = subprocess.run(["docker", "exec", "-i", container, "sqlite3", "-noheader", path],
                       input=sql.encode(), capture_output=True)
    if r.returncode:
        raise LocationError(
            f"sqlite3 dans {container}: {r.stderr.decode().strip() or 'echec'}")
    return r.stdout.decode()


def _scalar(path: str, container: str, sql: str):
    """-> la premiere colonne de la premiere ligne, en texte, ou None.

    Cote docker on rend la sortie entiere amputee du saut final plutot que sa
    premiere ligne : l'appelant a deja garanti qu'une seule ligne repond, et une
    valeur multiligne serait sinon tronquee."""
    if container:
        out = _docker(container, path, sql)
        return out[:-1] if out.endswith("\n") else out
    con = sqlite3.connect(path)
    try:
        row = con.execute(sql).fetchone()
    except sqlite3.Error as e:
        raise LocationError(f"sqlite {path}: {e}") from e
    finally:
        con.close()
    if row is None or row[0] is None:
        return None
    return str(row[0])


def _execute(path: str, container: str, sql: str):
    if container:
        _docker(container, path, sql)
        return
    con = sqlite3.connect(path)
    try:
        con.execute(sql)
        con.commit()
    except sqlite3.Error as e:
        raise LocationError(f"sqlite {path}: {e}") from e
    finally:
        con.close()


def _count(path: str, container: str, table: str, clause: str) -> int:
    n = _scalar(path, container, f"SELECT count(*) FROM {table} WHERE {clause};")
    return int(n or 0)


def read(target: str, selector: str):
    path, container, table, column, pairs = _parse(target, selector)
    if not container and not Path(path).exists():
        return None
    clause = _clause(pairs)
    n = _count(path, container, table, clause)
    if n == 0:
        return None
    if n > 1:
        raise LocationError(
            f"{table}: la condition designe {n} lignes, la lecture serait arbitraire")
    return _scalar(path, container, f"SELECT {column} FROM {table} WHERE {clause};")


def write(target: str, selector: str, value: str):
    path, container, table, column, pairs = _parse(target, selector)
    if not container and not Path(path).exists():
        raise LocationError(f"base absente: {path}")
    clause = _clause(pairs)
    n = _count(path, container, table, clause)
    if n != 1:
        raise LocationError(
            f"{table}: la condition designe {n} ligne(s), il en faut exactement une")
    _execute(path, container,
             f"UPDATE {table} SET {column} = {_lit(value)} WHERE {clause};")
