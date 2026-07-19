<p align="center">
  <img src="docs/logo.png" alt="bv-secrets" width="180">
</p>

<h1 align="center">bv-secrets</h1>

<p align="center">
  Gestionnaire de secrets et de rotation côté serveur, sans dépendance.<br>
  Il ne se contente pas de stocker un secret : il sait le <b>régénérer et l'appliquer</b>
  partout où il vit.
</p>

<p align="center">
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-3776ab">
  <img alt="Sans dépendance" src="https://img.shields.io/badge/d%C3%A9pendances-aucune-3fbf5f">
  <img alt="Licence MIT" src="https://img.shields.io/badge/licence-MIT-c0242c">
</p>

---

## Ce que c'est

Un coffre personnel (Bitwarden, Dashlane) garde des mots de passe pour un humain.
bv-secrets gère les secrets d'**infrastructure** et ferme la boucle : quand un mot
de passe de base de données est roté, l'utilisateur SQL est réellement modifié, les
fichiers `.env` sont réécrits, et les conteneurs concernés sont recréés pour les
relire. Le tout depuis une source déclarative unique.

Sans rotation appliquée, un secret « roté » n'est qu'une nouvelle chaîne dans un
fichier pendant que le service continue d'utiliser l'ancienne.

## Ce que ça n'est pas

Ni un coffre d'équipe, ni un serveur de secrets réseau (Vault, Infisical). Pas de
démon exposé, pas de base, pas de cluster. Un fichier de config, un store en
`0600`, et un binaire Python de la bibliothèque standard.

## Modèle de sécurité

C'est le cœur du projet : les privilèges sont **asymétriques**.

| Composant | Où | Privilèges |
|---|---|---|
| CLI | hôte, interactif | store rw, `doas` pour les comptes Linux |
| Worker | hôte, service système | docker + store rw, **aucun réseau entrant** |
| Dashboard web | conteneur | store **read-only**, aucun accès docker |

Le dashboard n'exécute **aucune** rotation. Il dépose un descripteur de job dans
un répertoire de spool ; le worker le ramasse, l'exécute, et réécrit un journal
**sans aucune valeur**. C'est ce qui permet d'exposer l'interface derrière un
reverse-proxy sans lui donner le moindre privilège : la compromission du conteneur
web ne donne ni docker, ni écriture sur le store.

Aucune valeur n'est jamais journalisée. Les seules commandes qui en impriment une
sont `get` et `open`, explicitement.

## Deux axes orthogonaux

La distinction structurante, à ne pas remélanger :

- **`kind`** — le FORMAT de la valeur, ce qu'elle *est* :
  `password`, `hex`, `b64`, `passphrase`, `userpass`, `opaque`, `computed`, `apikey`
- **`group`** — la POLITIQUE de rotation, *quand* on la régénère :
  `auto`, `app`, `careful`, `manual`

Une `apikey` est émise par une application tierce. Elle n'est **jamais** générée :
écrire une chaîne aléatoire produirait une clé que l'application refuse, et le
service tombe. Un nom contenant `API` ou `TOKEN` impose ce format, et le passage
vers un format générable est refusé à trois endroits indépendants — l'interface,
l'API et le worker.

## Démarrage

```sh
git clone https://github.com/<compte>/bv-secrets.git
cd bv-secrets
cp secrets.conf.example secrets.conf     # décrire ses propres secrets

export BV_SECRETS_DIR=/opt/bv-secrets    # store, rendus, miroir chiffré
bin/bv-secrets list                      # inventaire, aucune valeur
bin/bv-secrets plan                      # ce qu'une rotation ferait
bin/bv-secrets rotate --yes              # régénère et applique le groupe auto
bin/bv-secrets doctor                    # vérifie que chaque valeur MARCHE
```

`secrets.conf` n'est pas versionné : il décrit l'infrastructure (services,
utilisateurs SQL, commandes de vérification). Seul le modèle l'est.

### Dashboard

```sh
docker build -t bv-secrets-web .
docker run -d --name bv-secrets-web --read-only -u 1000:1000 -p 8000:8000 \
  -e BV_DASH_PASSWORD='<mot de passe applicatif>' \
  -v "$PWD/secrets.conf:/app/secrets.conf:ro" \
  -v /opt/bv-secrets:/opt/bv-secrets:ro \
  -v /opt/bv-secrets/spool:/spool:rw \
  bv-secrets-web
```

Le `secrets.conf` doit être le **même fichier** pour le worker et le conteneur :
le worker le réécrit lors d'un changement de format depuis l'interface. Le monter,
ne jamais s'appuyer sur la copie embarquée dans l'image.

Un exemple de service compose et l'unité OpenRC du worker sont dans
[`docs/`](docs/) et [`deploy/`](deploy/).

## Commandes

| Commande | Effet |
|---|---|
| `list` | inventaire : nom, format, groupe, présence, services |
| `check` | cohérence de la config, valeurs présentes, permissions `0600` |
| `plan` | dry-run d'une rotation, aucune valeur touchée |
| `rotate [--only N] --yes` | régénère **et applique partout**, avec rollback |
| `apply [--only N] --yes` | pousse les valeurs actuelles sans régénérer |
| `doctor [--only N]` | vérifie chaque valeur contre l'application réelle |
| `render` | réécrit les `rendered/<service>.env` |
| `get` / `set` / `gen` | lecture, écriture, génération d'une valeur |
| `add` | enregistre un nouveau secret et ses cibles |
| `seal` / `open` | miroir chiffré du store, pour sauvegarde hors machine |
| `audit` | cherche des valeurs gérées présentes en clair ailleurs |
| `verify-render` | vérifie que `render()` reproduit les rendus actuels |

## Rotation : ce qui se passe réellement

`rotate` n'écrit dans le store qu'**après** que tous les sinks vivants ont été
appliqués et vérifiés. Si l'un échoue, les précédents sont remis à leur valeur
antérieure et le store reste inchangé — pas de secret à moitié roté.

L'ordre compte : le mot de passe root de la base est appliqué en dernier, pour que
les `ALTER USER` précédents s'authentifient encore avec l'ancien.

Les services à recréer sont **déduits** des sinks, jamais déclarés à la main : un
conteneur ne relit son `env_file` qu'à la création, donc tout service ciblé par un
sink `env:` est recréé. Les secrets `computed` qui référencent une valeur rotée
entraînent aussi la recréation de leurs propres cibles.

## Configuration

Tous les chemins ont une valeur par défaut et se surchargent par environnement :

| Variable | Défaut | Rôle |
|---|---|---|
| `BV_SECRETS_DIR` | `/opt/bv-secrets` | store, rendus, miroir chiffré |
| `BV_SECRETS_CONF` | `<projet>/secrets.conf` | source déclarative |
| `BV_SPOOL` | `$BV_SECRETS_DIR/spool` | file de jobs web → worker |
| `BV_ACCESS_CONF` | `<compose>/access/access.conf` | matrice service × rôle |
| `BV_COMPOSE_DIR` | dossier parent du projet | racine docker compose |
| `BV_DASH_PASSWORD` | — | mot de passe applicatif du dashboard |
| `BV_PORT` | `8000` | port d'écoute du dashboard |

Le worker pilote en plus des services dont les noms varient d'une installation à
l'autre. Laissés vides, les fonctionnalités correspondantes sont désactivées
plutôt que d'agir sur un service arbitraire :

| Variable | Rôle |
|---|---|
| `BV_PROXY_SERVICE` | reverse-proxy recréé après un changement d'accès |
| `BV_ACCESS_RELOAD_SERVICES` | services à redémarrer ensuite, séparés par des virgules |
| `BV_AUTH_SERVICE` | service portant la console de gestion des comptes |

Sur un système OpenRC, ces valeurs vivent dans `/etc/conf.d/bvsecrets-worker` —
voir [`deploy/bvsecrets-worker.confd.example`](deploy/bvsecrets-worker.confd.example).
Le dépôt reste ainsi générique, les noms réels ne sont jamais versionnés.

## Structure

```
bvsecrets/          moteur partagé par les trois faces
  config.py           chemins et vocabulaire du domaine
  envfile.py          lecture/écriture atomique des .env
  engine.py           résolution, rendu, rotation, doctor
  cli.py              interface en ligne de commande
  worker/             exécuteur privilégié du spool
web/                dashboard
  server.py           transport HTTP, sessions, CSRF
  routes.py           points d'entrée de l'API
  static/css|js/      feuilles par couche, modules ES sans build
deploy/             unité OpenRC du worker
docs/               exemple de service compose
```

Aucune dépendance : bibliothèque standard Python côté serveur, modules ES natifs
côté navigateur, pas d'étape de build.

## Licence

MIT — voir [LICENSE](LICENSE).
