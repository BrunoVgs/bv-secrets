#!/usr/bin/env python3
"""Met a jour le mot de passe du client qBittorrent declare dans `qui`.

Moitie Alpine du decouplage. Le mot de passe appartient au Xeon, qui heberge
qBittorrent et les *arr ; cette machine n'heberge que `qui`, et ne touche donc
que `qui`. Aucun appel ne traverse le tunnel : `qui` est un conteneur local,
joint par l'IP de son bridge docker.

Usage :  qui-qb-client.py <nouveau-mdp>
"""
import json
import subprocess
import sys
import urllib.request

QB = 'http://10.8.0.4:8080'          # identifie l'instance a mettre a jour, pas appele
QUI_PORT = 7476
QUI_BASE = '/qbittorrent'            # doit suivre QUI__BASE_URL (compose)
BV_SECRETS = '/home/bv/.local/bin/bv-secrets'


def secret(name):
    r = subprocess.run([BV_SECRETS, 'get', name], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ''


def http(url, data=None, headers=None, method=None, timeout=30):
    r = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with urllib.request.urlopen(r, timeout=timeout) as f:
        return f.status, f.read(), f.headers


# ---------- qui ----------
def qui_base():
    """qui n'est pas publie : on l'atteint par l'IP de son conteneur, routable
    depuis l'hote (bridge docker)."""
    r = subprocess.run(['docker', 'inspect', 'qui', '--format',
                        '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'],
                       capture_output=True, text=True)
    ip = r.stdout.strip()
    if r.returncode != 0 or not ip:
        raise RuntimeError('qui: conteneur introuvable')
    return f'http://{ip}:{QUI_PORT}{QUI_BASE}'


def qui_update(new):
    pw = secret('QUI_PASSWORD')
    if not pw:
        raise RuntimeError('qui: QUI_PASSWORD absent du store')
    base = qui_base()

    def call(path, data=None, cookie=None, method=None):
        body = json.dumps(data).encode() if data is not None else None
        headers = {'Content-Type': 'application/json'}
        if cookie:
            headers['Cookie'] = cookie
        _s, b, h = http(base + path, body, headers, method)
        return h.get('Set-Cookie'), (json.loads(b) if b else None)

    cookie, _ = call('/api/auth/login', {'username': 'bv', 'password': pw})
    if not cookie:
        raise RuntimeError('qui: login refuse')
    sid = cookie.split(';')[0]
    done = 0
    for inst in call('/api/instances', cookie=sid)[1]:
        if not inst['host'].startswith(QB):
            continue
        call(f'/api/instances/{inst["id"]}',
             {'name': inst['name'], 'host': inst['host'],
              'username': inst['username'], 'password': new},
             cookie=sid, method='PUT')
        done += 1
    if not done:
        raise RuntimeError('qui: aucune instance ne pointe vers ' + QB)


def main():
    if len(sys.argv) != 2:
        print("usage: qui-qb-client.py <nouveau-mdp>", file=sys.stderr)
        return 2
    try:
        qui_update(sys.argv[1])
    except Exception as exc:
        print(f"qui: {exc}", file=sys.stderr)
        return 1
    print("qui: client qBittorrent mis a jour")
    return 0


if __name__ == '__main__':
    sys.exit(main())
