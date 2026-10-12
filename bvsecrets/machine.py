"""Ce qu'une instance dit de la machine qui la porte.

Lu sur place par le worker, envoye a l'instance qui pilote quand elle ouvre la
fiche de cet hote. Rien de secret : de quoi reconnaitre la machine et voir d'un
coup d'oeil si elle va bien.
"""
import os
import platform
import shutil
import socket

from .config import SECRETS_DIR


def _os_name() -> str:
    try:
        for line in open("/etc/os-release", encoding="utf-8"):
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.system()


def _meminfo(field: str) -> int:
    """Octets, ou 0 si /proc ne le dit pas."""
    try:
        for line in open("/proc/meminfo", encoding="utf-8"):
            if line.startswith(field + ":"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def facts() -> dict:
    try:
        uptime = int(float(open("/proc/uptime", encoding="utf-8").read().split()[0]))
    except (OSError, ValueError, IndexError):
        uptime = 0
    disk = shutil.disk_usage(SECRETS_DIR if SECRETS_DIR.exists() else "/")
    return {
        "hostname": socket.gethostname(),
        "os": _os_name(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "cpus": os.cpu_count() or 0,
        "uptime": uptime,
        "memTotal": _meminfo("MemTotal"),
        "memAvailable": _meminfo("MemAvailable"),
        "diskTotal": disk.total,
        "diskFree": disk.free,
    }
