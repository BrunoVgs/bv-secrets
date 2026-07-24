#!/bin/sh
# Release bv-secrets end to end: test -> commit -> push -> build -> GitHub release.
#
#   scripts/release.sh [VERSION]     VERSION defaults to 1.0.0
#
# Idempotent-ish: skips the commit if the tree is clean, refuses if the tag
# already exists. Requires `gh` authenticated (gh auth status) and a `main` that
# tracks origin. No compiled binary: the tool is pure Python, so the release
# assets are the wheel + sdist (people can `pipx install` them) alongside the
# source archives GitHub attaches automatically.
set -eu

VERSION="${1:-1.0.0}"
TAG="v${VERSION}"

# --- run from the repo root, whatever the caller's cwd -----------------------
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# --- preconditions -----------------------------------------------------------
[ "$(git branch --show-current)" = "main" ] || { echo "not on main, aborting."; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh not authenticated (gh auth login)."; exit 1; }
if git rev-parse "$TAG" >/dev/null 2>&1 || gh release view "$TAG" >/dev/null 2>&1; then
    echo "$TAG already exists, aborting."; exit 1
fi

# --- gate: never release a broken tree ---------------------------------------
say "Tests"
python3 -m compileall -q bvsecrets
python3 -m unittest discover -s tests -t .

# --- commit any pending work (store + config are gitignored) -----------------
if [ -n "$(git status --porcelain)" ]; then
    say "Commit"
    git add -A
    git commit -m "Release ${TAG}

- unittest suite over the risky core: surgical writes per format, rotate
  rollback, validation, config precedence (zero deps)
- GitHub Actions CI: run the suite on 3.11-3.13, build wheel + sdist
- pyproject.toml: pipx-installable bv-secrets console script
- README: store is 0600 plaintext (host-perms trust, not encryption-at-rest;
  seal covers encrypted backup); Linux-account rotation needs doas"
else
    echo "tree clean, nothing to commit."
fi

say "Push"
git push origin main

# --- wait for GitHub CI to go green on THIS commit before tagging -------------
# The local tests above are a fast fail; GitHub Actions is the source of truth.
say "Wait for GitHub CI"
SHA=$(git rev-parse HEAD)
RUN_ID=""; i=0
while [ -z "$RUN_ID" ] && [ "$i" -lt 24 ]; do
    RUN_ID=$(gh run list -w ci.yml -c "$SHA" -L 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)
    [ -n "$RUN_ID" ] && break
    i=$((i + 1)); sleep 5
done
[ -n "$RUN_ID" ] || { echo "no CI run found for $SHA after 2min, aborting."; exit 1; }
gh run watch "$RUN_ID" --exit-status    # blocks until done, non-zero if CI fails

# --- build the release assets, no build dep (setuptools backend) -------------
say "Build wheel + sdist"
rm -rf dist build ./*.egg-info
python3 -c "from setuptools import build_meta as b; import os; \
os.makedirs('dist', exist_ok=True); \
print(b.build_sdist('dist')); print(b.build_wheel('dist'))"

# --- cut the release ---------------------------------------------------------
say "GitHub release $TAG"
gh release create "$TAG" dist/* --title "bv-secrets ${VERSION}" --notes-file - <<'EOF'
First public release.

bv-secrets rotates, applies and audits infrastructure secrets on a single
self-hosted box, from one declarative file, with zero runtime dependencies
(Python stdlib only).

**Highlights**
- Rotation with all-or-nothing rollback: SQL users, .env/config files, Linux
  passwords and app commands move together or not at all.
- Two-way connectors for .env, JSON, YAML, INI, TOML and regex — surgical
  writes that change only the targeted value, comments and formatting kept
  byte-for-byte.
- `status` drift detection, `doctor` live probes, `adopt`/`import` to onboard
  existing files, `run` to inject secrets into a process with nothing on disk.
- Read-only audit timeline over logs the box already writes.
- Unprivileged dashboard + privileged worker split via a filesystem spool.

**Install**
- `pipx install .` from a checkout, or grab the wheel below.
- Python 3.11+ (tomllib). `doas` needed only for Linux-account rotation.

**Scope**
Single-host / self-hosted (VPS, homelab). The store is a 0600 plaintext file —
host-permission trust, not encryption-at-rest (see Security model). Not a
Vault/k8s replacement, by design.
EOF

rm -rf build ./*.egg-info
say "Done: https://github.com/BrunoVgs/bv-secrets/releases/tag/${TAG}"
