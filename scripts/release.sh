#!/bin/sh
# Release bv-secrets end to end, one command, nothing to run by hand:
# commit -> push -> CI -> tag -> build -> GitHub release.
#
#   scripts/release.sh                      version from pyproject.toml
#   scripts/release.sh 1.2.0                must match pyproject.toml
#   scripts/release.sh 1.2.0 "Subject..."   commit message, else $EDITOR opens
#
# Nothing about a given release is written in here: the version comes from
# pyproject.toml, the notes from the commits since the last tag. Every command
# it runs is printed before it runs. Requires `gh` authenticated and a `main`
# that tracks origin. Pure Python, so the assets are the wheel + sdist.
set -eu

# --- run from the repo root, whatever the caller's cwd -----------------------
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
run() { printf '\033[2m$ %s\033[0m\n' "$*"; "$@"; }
die() { printf '\033[31m%s\033[0m\n' "$1" >&2; exit 1; }

PYPROJECT_VERSION=$(python3 -c \
    'import tomllib;print(tomllib.load(open("pyproject.toml","rb"))["project"]["version"])')
VERSION="${1:-$PYPROJECT_VERSION}"
MESSAGE="${2:-}"
TAG="v${VERSION}"

# --- preconditions -----------------------------------------------------------
say "Preflight $TAG"
[ "$(git branch --show-current)" = "main" ] || die "not on main, aborting."
gh auth status >/dev/null 2>&1 || die "gh not authenticated (gh auth login)."
[ "$VERSION" = "$PYPROJECT_VERSION" ] || \
    die "asked for $VERSION but pyproject.toml says $PYPROJECT_VERSION — bump it first."
if git rev-parse "$TAG" >/dev/null 2>&1 || gh release view "$TAG" >/dev/null 2>&1; then
    die "$TAG already exists, aborting."
fi
echo "version $VERSION, tag $TAG, from $(git rev-parse --short HEAD)"

# --- gate: never release a broken tree ---------------------------------------
say "Tests"
run python3 -m compileall -q bvsecrets
run python3 -m unittest discover -s tests -t .

# --- commit whatever is pending (store + real config are gitignored) ---------
if [ -n "$(git status --porcelain)" ]; then
    say "Commit"
    run git status --short
    run git add -A
    if [ -n "$MESSAGE" ]; then
        run git commit -m "$MESSAGE"
    elif [ -t 0 ]; then
        git commit -e -m "Release ${TAG}"      # $EDITOR opens, prefilled
    else
        run git commit -m "Release ${TAG}"
    fi
else
    echo "tree clean, nothing to commit."
fi

say "Push"
run git push origin main

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
[ -n "$RUN_ID" ] || die "no CI run found for $SHA after 2min, aborting."
run gh run watch "$RUN_ID" --exit-status   # blocks until done, non-zero if CI fails

# --- tag locally and push it, so the next release can diff from here ---------
say "Tag"
PREVIOUS=$(git describe --tags --abbrev=0 2>/dev/null || true)
run git tag -a "$TAG" -m "bv-secrets ${VERSION}"
run git push origin "$TAG"

# --- build the release assets, no build dep (setuptools backend) -------------
say "Build wheel + sdist"
rm -rf dist build ./*.egg-info
python3 -c "from setuptools import build_meta as b; import os; \
os.makedirs('dist', exist_ok=True); \
print(b.build_sdist('dist')); print(b.build_wheel('dist'))"
ls -1 dist

# --- notes: the commits since the last tag, nothing hand-maintained ----------
RANGE="${PREVIOUS:+${PREVIOUS}..}HEAD"
say "GitHub release $TAG ($RANGE)"
NOTES=$(mktemp)
{
    printf 'Server-side secret rotation, access control and audit in a single\n'
    printf 'stdlib-only tool. Python 3.11+, no runtime dependency.\n\n'
    printf '**Changes**\n'
    git log --no-merges --pretty='- %s' "$RANGE"
    printf '\n**Install**\n'
    printf '`pipx install bv_secrets-%s-py3-none-any.whl`, or `pipx install .`\n' "$VERSION"
    printf 'from a checkout, then `bv-secrets init`.\n'
} > "$NOTES"
cat "$NOTES"
run gh release create "$TAG" dist/* --title "bv-secrets ${VERSION}" --notes-file "$NOTES"
rm -f "$NOTES"

rm -rf build ./*.egg-info
say "Done: https://github.com/BrunoVgs/bv-secrets/releases/tag/${TAG}"
