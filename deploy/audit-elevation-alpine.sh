#!/bin/sh
# Ouvre la trace d'elevation sur Alpine, a lancer avec doas.
#
#   doas sh deploy/audit-elevation-alpine.sh
#
# Deux choses, aucune n'ajoute de privilege dormant :
#   1. le journal d'audit passe au groupe wheel, pour etre lisible sans root
#   2. les regles qui produisent la trace sont chargees
set -eu

[ "$(id -u)" = 0 ] || { echo "a lancer en root (doas sh $0)" >&2; exit 1; }

CONF=/etc/audit/auditd.conf
RULES=/etc/audit/rules.d/50-bv-elevation.rules

echo "== 1. lisibilite du journal"
if grep -qE '^\s*log_group\s*=\s*wheel' "$CONF"; then
  echo "   ok   log_group = wheel deja pose"
else
  cp -a "$CONF" "$CONF.bak.$(date +%Y%m%d-%H%M%S)"
  if grep -qE '^\s*log_group\s*=' "$CONF"; then
    sed -i 's/^\s*log_group\s*=.*/log_group = wheel/' "$CONF"
  else
    printf 'log_group = wheel\n' >> "$CONF"
  fi
  echo "   ok   log_group = wheel (sauvegarde faite)"
fi

echo "== 2. regles d'elevation"
mkdir -p "$(dirname "$RULES")"
{
  echo "# Rendered by bv-secrets -- do not edit. Trace des elevations."
  echo "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k bv_elevation"
  for t in doas sudo su; do
    p=$(command -v "$t" 2>/dev/null) && p=$(readlink -f "$p") && echo "-w $p -p x -k bv_elevation"
  done
} > "$RULES"
chmod 640 "$RULES"
echo "   ok   $RULES"

echo "== 3. rechargement"
rc-service auditd restart >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true
augenrules --load >/dev/null 2>&1 || true

echo "== 4. verification"
auditctl -l | grep bv_elevation || { echo "   !!   aucune regle chargee" >&2; exit 1; }
ls -ld /var/log/audit /var/log/audit/audit.log

cat <<'EOF'

Verifier ensuite en tant que bv, sans privilege :
    doas true                       # produit un evenement
    bv-secrets elevation --since 1h
EOF
