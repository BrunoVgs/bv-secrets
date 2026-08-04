"""La posture de la machine, declaree a cote des secrets.

Le besoin de depart etait « je pose l'outil sur la box et je controle tout
acces ». Le moyen refuse est un daemon unique qui cumulerait tous les pouvoirs :
un bug dedans emporte le pare-feu, les secrets ET les fichiers de conf adoptes,
ce qui est l'inverse de l'asymetrie de privilege sur laquelle le projet est bati.

Le moyen retenu : bv-secrets est le PLAN DE CONTROLE. Il ne fait rien tourner en
permanence, il rend des fichiers que des mecanismes deja presents et maintenus
par la distribution appliquent -- auditd pour la trace, iptables pour l'egress.
Une declaration, plusieurs executants.

    egress:
      console:
        subnet: 172.22.0.0/16
        block: [192.168.0.0/16, 10.0.0.0/8, 169.254.0.0/16]

    audit:
      elevation:
        trace: [sudo, doas, su, execve-setuid]
        window: 4

Aucun privilege dormant : le rendu se fait dans un repertoire que le compte
possede deja, et les commandes root sont IMPRIMEES, jamais lancees en douce.
"""
import shutil
from pathlib import Path

from .config import AUDIT_RULES_FILE, ELEVATION_KEY, SECRETS_DIR, ConfigError

# Ce que `trace:` sait produire. Un nom inconnu est refuse : une regle d'audit
# silencieusement ignoree donne une trace incomplete qu'on croit complete.
TRACE_BINARIES = {"sudo": "/usr/bin/sudo", "doas": "/usr/bin/doas", "su": "/bin/su"}
TRACE_SYSCALL = "execve-setuid"
DEFAULT_TRACE = ["sudo", "doas", "su", TRACE_SYSCALL]

# Destinations qu'un conteneur cloisonne ne doit pas joindre, par defaut : les
# trois plages privees plus le link-local (169.254 porte les metadata cloud).
DEFAULT_BLOCK = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16"]

RENDER_DIR = SECRETS_DIR / "host"


def privilege_tool() -> str:
    """`doas` ou `sudo`, selon ce qui existe ici. Imprimer une commande avec
    l'outil de l'autre distribution donne une consigne qui ne s'execute pas."""
    for tool in ("doas", "sudo"):
        if shutil.which(tool):
            return tool
    return "sudo"


def _resolve(binary: str) -> str:
    """Le vrai chemin sur CETTE machine. `su` est bbsuid sur Alpine, `doas`
    n'existe pas sur Ubuntu : une regle sur un chemin absent est acceptee par
    auditd et ne declenche jamais."""
    found = shutil.which(binary)
    return str(Path(found).resolve()) if found else ""


def audit_rules(spec: dict, key: str = None) -> tuple:
    """-> (texte des regles, [avertissements])"""
    key = key or ELEVATION_KEY
    trace = spec.get("trace") or DEFAULT_TRACE
    if isinstance(trace, str):
        trace = [t.strip() for t in trace.split(",") if t.strip()]
    unknown = [t for t in trace if t != TRACE_SYSCALL and t not in TRACE_BINARIES]
    if unknown:
        raise ConfigError(
            f"audit.elevation.trace : {', '.join(unknown)} inconnu.\n"
            f"Attendu : {', '.join(sorted(TRACE_BINARIES) + [TRACE_SYSCALL])}")

    lines = ["# Rendu par bv-secrets -- ne pas editer a la main.",
             f"# Source : la cle `audit:` du fichier de declaration.",
             ""]
    warn = []
    if TRACE_SYSCALL in trace:
        lines.append(f"-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k {key}")
    for name in trace:
        if name == TRACE_SYSCALL:
            continue
        path = _resolve(name)
        if path:
            lines.append(f"-w {path} -p x -k {key}")
        else:
            warn.append(f"{name} absent de cette machine, regle non posee")
    return "\n".join(lines) + "\n", warn


def egress_commands(spec: dict) -> list:
    """-> les invocations de bv-egress.sh, une par zone declaree."""
    out = []
    for zone, conf in sorted(spec.items()):
        if not isinstance(conf, dict):
            raise ConfigError(f"egress.{zone} : attendu un bloc avec `subnet:`")
        subnet = str(conf.get("subnet", "")).strip()
        if not subnet:
            raise ConfigError(f"egress.{zone} : `subnet:` manquant")
        if "/" not in subnet:
            raise ConfigError(f"egress.{zone} : `{subnet}` n'est pas un CIDR")
        block = conf.get("block") or DEFAULT_BLOCK
        if isinstance(block, str):
            block = [b.strip() for b in block.split(",") if b.strip()]
        out.append({"zone": zone, "subnet": subnet, "block": list(block),
                    "cmd": f"{privilege_tool()} sh /usr/local/sbin/bv-egress.sh {subnet}"})
    return out


def plan(doc: dict, key: str = None) -> dict:
    """-> ce que la declaration demande, sans rien ecrire."""
    audit_spec = (doc.get("audit") or {}).get("elevation") or {}
    rules, warn = audit_rules(audit_spec, key) if doc.get("audit") else ("", [])
    return {
        "rules": rules,
        "rules_target": Path(AUDIT_RULES_FILE),
        "rules_staged": RENDER_DIR / Path(AUDIT_RULES_FILE).name,
        "warnings": warn,
        "egress": egress_commands(doc.get("egress") or {}),
    }


def write(p: dict) -> Path:
    """Rend les regles dans le store, que le compte possede deja. L'installation
    a leur place definitive demande root : la commande est imprimee, pas lancee.
    """
    RENDER_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    staged = p["rules_staged"]
    staged.write_text(p["rules"], encoding="utf-8")
    staged.chmod(0o640)
    return staged


def diff(p: dict) -> tuple:
    """-> (etat, message). Trois etats, pas deux : « je ne peux pas verifier »
    n'est pas « c'est conforme », et ce n'est pas non plus « ca differe ».
    Les confondre ferait passer une machine sans regles pour une machine en
    ecart, ou pire l'inverse."""
    target = p["rules_target"]
    try:
        current = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "absent", f"{target} n'existe pas : aucune trace n'est produite"
    except PermissionError:
        return "unknown", (f"{target} n'est pas lisible sans privilege, "
                           f"conformite non verifiable")
    if current == p["rules"]:
        return "ok", f"{target} conforme a la declaration"
    return "drift", f"{target} differe de la declaration"


EXAMPLE = """\
egress:
  # Un conteneur d'outillage peut sortir sur Internet, mais pas atteindre le LAN
  # ni le tunnel. Le subnet doit etre celui, fixe, du reseau docker concerne.
  console:
    subnet: 172.22.0.0/16
    block: [192.168.0.0/16, 10.0.0.0/8, 169.254.0.0/16]

audit:
  # Ce que la lentille `bv-secrets elevation` aura a lire. Sans ces regles, il
  # n'y a rien a montrer : la donnee n'existe pas.
  elevation:
    trace: [sudo, doas, su, execve-setuid]
    window: 4
"""
