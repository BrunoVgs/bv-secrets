"""Read/write the store's .env files. Split on the FIRST `=` only, values kept
verbatim: a value may contain `=`, spaces or quotes without being altered."""
import os
from pathlib import Path


def parse_env(path: Path) -> dict:
    out = {}
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        if key:
            out[key] = value
    return out


def write_env(path: Path, data: dict, header: str = "") -> None:
    """Atomic 0600 write: no reader ever sees a partial file."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lines = []
    if header:
        lines += [f"# {ln}" for ln in header.splitlines()] + [""]
    lines += [f"{k}={v}" for k, v in data.items()]
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
