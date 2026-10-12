"""Ce que la vue Hotes montre : les instances declarees, et leur etat.

L'etat n'est JAMAIS calcule au chargement de la page. Un hote eteint ne repond
pas, et attendre son timeout TCP figerait le dashboard entier -- c'est
exactement le cas du Xeon quand il est down. La page liste ce que la config
declare ; interroger le reseau est une action explicite.
"""
from bvsecrets import hosts, remote
from bvsecrets.engine import Engine


def data() -> dict:
    """Les hotes declares et les secrets qu'ils hebergent, sans toucher au reseau."""
    cfg = Engine().cfg
    hosted = {}
    for name, c in cfg.items():
        if c.get("host"):
            hosted.setdefault(c["host"], []).append(name)
    return {"hosts": [{"name": n,
                       "url": entry["url"],
                       "note": entry["note"],
                       # `ini` : declaree dans bv-secrets.ini, donc pas modifiable d'ici.
                       "editable": entry["source"] == "registry",
                       "hasKey": bool(hosts.key(n)),
                       "secrets": sorted(hosted.get(n, []))}
                      for n, entry in sorted(hosts.entries().items())],
            # Declares `host: X` avec X absent de [hosts] : `check` le signale
            # deja, mais le voir ici evite de chercher pourquoi rien ne part.
            "orphans": sorted({c["host"] for c in cfg.values()
                               if c.get("host") and c["host"] not in hosts.names()})}


def sheet(name: str) -> dict:
    """La fiche d'une instance, lue chez elle : sa machine et ses secrets. Chaque
    secret dit s'il est pilote d'ici (declare `host: <nom>` dans NOTRE config)."""
    here = {n for n, c in Engine().cfg.items() if c.get("host") == name}
    data = remote.inventory(name)
    there = data.get("secrets") or []
    for secret in there:
        secret["managed"] = secret["name"] in here
    return {"name": name, "machine": data.get("machine") or {}, "secrets": there,
            "missing": sorted(here - {s["name"] for s in there})}


def probe(name: str) -> dict:
    """Le diagnostic vient du coeur : le dashboard et la CLI doivent dire la
    meme chose d'un meme hote."""
    return {**remote.probe(name), "name": name}
