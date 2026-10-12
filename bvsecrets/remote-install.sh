#!/bin/sh
# Installe ou met a jour une instance bv-secrets sur CETTE machine, et ouvre son
# ecouteur. Envoye par `bv-secrets hosts <nom> --deploy <cible ssh>` (ou le
# formulaire du dashboard) : le script
# arrive par l'entree standard de ssh, precede d'une ligne KEY='...'.
#
#   sh -s -- <adresse d'ecoute> <port> <depot git>
#
# Root n'est pris que s'il est disponible SANS mot de passe (sudo -n, doas -n).
# Sinon le store va sous $HOME et les commandes restantes sont affichees.
set -eu
BIND=$1 PORT=$2 REPO=$3
[ -n "${KEY:-}" ] || { echo "clé absente" >&2; exit 2; }

for outil in python3 git; do
    command -v "$outil" >/dev/null 2>&1 || { echo "il manque $outil sur $(hostname)" >&2; exit 2; }
done
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
    || { echo "python 3.11 ou plus requis" >&2; exit 2; }

en_root() {
    if [ "$(id -u)" = 0 ]; then "$@"
    elif sudo -n true 2>/dev/null; then sudo -n "$@"
    elif doas -n true 2>/dev/null; then doas -n "$@"
    else return 127
    fi
}

DIR="$HOME/bv-secrets"
if [ -d "$DIR/.git" ]; then
    git -C "$DIR" pull -q --ff-only
    echo "code mis à jour : $(git -C "$DIR" log --oneline -1)"
else
    git clone -q "$REPO" "$DIR"
    echo "code installé : $(git -C "$DIR" log --oneline -1)"
fi
cd "$DIR"

STORE=/opt/bv-secrets
if [ ! -d "$STORE" ] && ! en_root install -d -m 700 -o "$(id -un)" -g "$(id -gn)" "$STORE"; then
    STORE="$HOME/.local/share/bv-secrets"
fi
if [ "$STORE" = /opt/bv-secrets ]; then
    bin/bv-secrets init --no-service >/dev/null
else
    bin/bv-secrets init --no-service --dir "$STORE" >/dev/null
fi
( umask 077; mkdir -p "$STORE/hosts"; printf '%s\n' "$KEY" > "$STORE/hosts/self.key" )
echo "store : $STORE, clé partagée posée"

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    INIT=systemd UNITE=/etc/systemd/system/bvsecrets-worker.service REGLAGES=/etc/default/bvsecrets-worker
elif command -v rc-service >/dev/null 2>&1; then
    INIT=openrc UNITE=/etc/init.d/bvsecrets-worker REGLAGES=/etc/conf.d/bvsecrets-worker
else
    echo "ni systemd ni OpenRC ici : lancer le worker à la main," >&2
    echo "    BV_WORKER_BIND=$BIND BV_WORKER_PORT=$PORT python3 -u -m bvsecrets.worker.loop" >&2
    exit 3
fi

# Les deux reglages de l'ecouteur, sans toucher aux autres lignes du fichier.
reglages() {
    { [ -r "$REGLAGES" ] && grep -v -E '^BV_WORKER_(BIND|PORT)=' "$REGLAGES" || true; }
    printf 'BV_WORKER_BIND="%s"\nBV_WORKER_PORT="%s"\n' "$BIND" "$PORT"
}

if ! en_root true; then
    echo "pas de root sans mot de passe ici. Reste à lancer sur $(hostname), en root :" >&2
    echo "    cd $DIR && bin/bv-secrets init --unit $INIT > $UNITE" >&2
    echo "    printf 'BV_WORKER_BIND=\"$BIND\"\\nBV_WORKER_PORT=\"$PORT\"\\n' >> $REGLAGES" >&2
    exit 4
fi
bin/bv-secrets init --unit "$INIT" | en_root tee "$UNITE" >/dev/null
reglages | en_root tee "$REGLAGES.nouveau" >/dev/null
en_root mv "$REGLAGES.nouveau" "$REGLAGES"
if [ "$INIT" = systemd ]; then
    en_root systemctl daemon-reload
    en_root systemctl enable -q bvsecrets-worker
    en_root systemctl restart bvsecrets-worker
else
    en_root chmod +x "$UNITE"
    en_root rc-update add bvsecrets-worker default >/dev/null 2>&1 || true
    en_root rc-service bvsecrets-worker restart >/dev/null
fi
echo "worker relancé ($INIT), écouteur sur $BIND:$PORT"
