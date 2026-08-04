#!/bin/sh
# Bootstrap a small self-hosted box: docker, compose, caddy, bv-secrets.
#
# POSIX sh on purpose: Alpine ships busybox ash and Void may not have bash.
# Idempotent: every step checks before acting, so a re-run repairs rather than
# duplicates. Nothing here is specific to one estate; a fresh user on a fresh box
# is the intended caller, and the CI runs this same file to prove it.
#
#   ./deploy/bootstrap.sh                 full install (needs root for packages)
#   ./deploy/bootstrap.sh --no-packages   skip the package manager (CI, or already installed)
#   ./deploy/bootstrap.sh --no-service    do not register the worker service
#   ./deploy/bootstrap.sh --check         report what is missing, change nothing
#   ./deploy/bootstrap.sh --store DIR     put the store elsewhere than /opt/bv-secrets
set -eu

PACKAGES=1; SERVICE=1; CHECK=0; STORE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-packages) PACKAGES=0 ;;
    --no-service)  SERVICE=0 ;;
    --check)       CHECK=1; PACKAGES=0; SERVICE=0 ;;
    --store)       STORE="${2:?--store attend un chemin}"; shift ;;
    # the header comment is the help text; its end is the first line of code
    -h|--help)     sed -n '2,/^set -eu/p' "$0" | sed '$d;s/^# \{0,1\}//'; exit 0 ;;
    *) echo "option inconnue: $1" >&2; exit 2 ;;
  esac
  shift
done

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
say()  { printf '\n== %s\n' "$1"; }
ok()   { printf '   ok   %s\n' "$1"; }
warn() { printf '   !!   %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

as_root() {
  if [ "$(id -u)" = 0 ]; then "$@"
  elif have sudo; then sudo "$@"
  elif have doas; then doas "$@"
  else warn "ni root, ni sudo, ni doas: '$*' a lancer a la main"; return 1
  fi
}

# --- distribution ----------------------------------------------------------- #
DISTRO=unknown
[ -r /etc/os-release ] && . /etc/os-release && DISTRO="${ID:-unknown}"
case "$DISTRO" in
  alpine) PKG_INSTALL="apk add --no-progress" ;;
  void)   PKG_INSTALL="xbps-install -y" ;;
  debian|ubuntu) PKG_INSTALL="apt-get install -y" ;;
  *) PKG_INSTALL="" ;;
esac

say "distribution"
if [ -n "$PKG_INSTALL" ]; then ok "$DISTRO"; else warn "$DISTRO non gere: installer les paquets a la main"; fi

# Package names differ per distro; only these three sets are needed.
case "$DISTRO" in
  alpine) PKGS="python3 docker docker-cli-compose caddy" ; SVC_MGR=openrc ;;
  void)   PKGS="python3 docker docker-compose caddy"     ; SVC_MGR=runit  ;;
  debian|ubuntu) PKGS="python3 docker.io docker-compose-v2 caddy" ; SVC_MGR=systemd ;;
  *)      PKGS="" ; SVC_MGR=unknown ;;
esac

# --- 1. packages ------------------------------------------------------------ #
if [ "$PACKAGES" = 1 ] && [ -n "$PKGS" ]; then
  say "paquets"
  [ "$DISTRO" = alpine ] && as_root apk update >/dev/null 2>&1 || true
  [ "$DISTRO" = debian ] || [ "$DISTRO" = ubuntu ] && as_root apt-get update -qq >/dev/null 2>&1 || true
  # shellcheck disable=SC2086
  as_root $PKG_INSTALL $PKGS || warn "installation partielle, voir ci-dessus"
fi

# --- 2. prerequis ----------------------------------------------------------- #
# Deux niveaux: sans python ni docker rien ne tourne, alors qu'un noeud place
# derriere le reverse-proxy d'une autre machine n'a aucune raison d'avoir Caddy.
# Le declarer requis ferait echouer --check sur une box parfaitement saine.
say "prerequis"
MISSING=""; OPTIONAL=""
for tool in python3 docker; do
  if have "$tool"; then ok "$tool $("$tool" --version 2>/dev/null | head -1)"
  else warn "$tool absent"; MISSING="$MISSING $tool"; fi
done
if docker compose version >/dev/null 2>&1; then ok "docker compose (plugin)"
elif have docker-compose; then ok "docker-compose (standalone)"
else warn "docker compose absent"; MISSING="$MISSING docker-compose"; fi

if have caddy; then ok "caddy $(caddy version 2>/dev/null | head -1)"
else
  warn "caddy absent (facultatif: inutile si le reverse-proxy est ailleurs)"
  OPTIONAL="$OPTIONAL caddy"
fi

# bv-secrets needs 3.11+ for tomllib; say so plainly rather than failing later.
if have python3; then
  python3 - <<'PY' || { warn "python 3.11+ requis"; MISSING="$MISSING python3.11"; }
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
  ok "python >= 3.11"
fi

if [ "$CHECK" = 1 ]; then
  say "resultat"
  [ -n "$OPTIONAL" ] && warn "facultatif absent:$OPTIONAL"
  [ -n "$MISSING" ] && { warn "requis absent:$MISSING"; exit 1; }
  ok "tout le requis est present"
  exit 0
fi

# --- 3. bv-secrets sur le PATH ---------------------------------------------- #
say "bv-secrets"
BIN="$HOME/.local/bin"
mkdir -p "$BIN"
if [ ! -e "$BIN/bv-secrets" ] || [ "$(readlink -f "$BIN/bv-secrets" 2>/dev/null)" != "$ROOT/bin/bv-secrets" ]; then
  ln -sf "$ROOT/bin/bv-secrets" "$BIN/bv-secrets"
fi
ok "$BIN/bv-secrets -> $ROOT/bin/bv-secrets"
case ":$PATH:" in
  *":$BIN:"*) ok "$BIN deja dans le PATH" ;;
  *) warn "ajouter au shell rc :  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

# --- 4. store + config ------------------------------------------------------ #
say "init"
# Whether the config already existed decides how the run ends: on a first install
# the template's declared-but-unset secrets are the starting point, not faults.
CONF_PATH=$(PYTHONPATH="$ROOT" python3 -c 'from bvsecrets.config import CONF; print(CONF)' 2>/dev/null || echo "")
FRESH=0
[ -n "$CONF_PATH" ] && [ ! -e "$CONF_PATH" ] && FRESH=1
# The default store is /opt/bv-secrets, which needs root once. An unprivileged
# install must still end up working, so it falls back under $HOME rather than
# stopping to ask for a privilege the caller may not have.
if [ -z "$STORE" ] && [ "$(id -u)" != 0 ] && ! have sudo && ! have doas; then
  STORE="$HOME/.local/share/bv-secrets"
  warn "sans root: store place dans $STORE"
fi
INIT_ARGS=""
[ "$SERVICE" = 0 ] && INIT_ARGS="--no-service"
[ -n "$STORE" ] && INIT_ARGS="$INIT_ARGS --dir $STORE"
# shellcheck disable=SC2086
if "$ROOT/bin/bv-secrets" init $INIT_ARGS; then ok "store et config en place"
else warn "init incomplet (voir ci-dessus)"; fi

# --- 5. verification -------------------------------------------------------- #
say "verification"
if [ "$FRESH" = 1 ]; then
  ok "config de depart installee : ${CONF_PATH:-secrets.conf}"
  echo "        Les secrets qu'elle declare n'ont pas encore de valeur : c'est normal,"
  echo "        ce sont les exemples du modele. Les remplacer par les tiens, puis"
  echo "        \`bv-secrets rotate\` pour generer, ou \`bv-secrets set NOM\` pour poser."
else
  "$ROOT/bin/bv-secrets" check || warn "check signale des points a corriger"
fi

say "termine"
cat <<EOF
   Suite :
     bv-secrets list              les secrets, groupes par famille
     bv-secrets adopt <fichier>   adopter le .env d'une app existante
     bv-secrets check             ce qui manque une fois tes secrets declares
     bv-secrets elevation --rules regles d'audit des elevations
EOF
