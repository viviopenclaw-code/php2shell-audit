#!/usr/bin/env bash
# Assemble release assets and publish them as a GitHub Release.
#
# Usage:
#   scripts/release.sh 1.1.0            # build assets + create the release
#   scripts/release.sh 1.1.0 --local    # build assets only, no upload
#
# Requires dist/php2shell-audit.exe to exist (see BUILDING.md).
# Publishing needs either an authenticated `gh`, or GITHUB_TOKEN with repo scope.
set -euo pipefail

VERSION="${1:-}"
MODE="${2:-}"

if [ -z "$VERSION" ]; then
    echo "usage: $0 <version> [--local]" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

EXE="dist/php2shell-audit.exe"
OUT="dist/release"
TAG="v$VERSION"

# --- sanity checks -----------------------------------------------------------

if [ ! -f "$EXE" ]; then
    echo "error: $EXE not found. Build it first (see BUILDING.md)." >&2
    exit 1
fi

SCRIPT_VERSION="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' php2shell_audit.py)"
if [ "$SCRIPT_VERSION" != "$VERSION" ]; then
    echo "error: version mismatch." >&2
    echo "  requested : $VERSION" >&2
    echo "  in source : $SCRIPT_VERSION" >&2
    exit 1
fi

if ! git diff --quiet HEAD -- php2shell_audit.py README.md RELEASING.md; then
    echo "warning: uncommitted changes in tracked files." >&2
    echo "         tag $TAG would not match what ships." >&2
fi

# --- build assets ------------------------------------------------------------

echo "==> assembling assets for $VERSION"
rm -rf "$OUT"
mkdir -p "$OUT"

cp "$EXE" "$OUT/php2shell-audit.exe"

# Build the zip reproducibly: a plain `zip` writes the current mtime into each
# entry header, so the archive checksum would change on every run and
# SHA256SUMS.txt would be useless. Pin the timestamp to the source commit date
# and sort entries, so the same input always yields the same archive.
COMMIT_EPOCH="$(git log -1 --format=%ct)"
python3 - "$OUT" "$COMMIT_EPOCH" <<'PY'
import os, sys, zipfile, time

out, epoch = sys.argv[1], int(sys.argv[2])
names = sorted(n for n in os.listdir(out) if n.endswith(".exe"))
stamp = time.gmtime(max(epoch, 315532800))[:6]  # zip cannot store dates before 1980

with zipfile.ZipFile(os.path.join(out, "php2shell-audit-win64.zip"), "w",
                     compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for name in names:
        info = zipfile.ZipInfo(name, date_time=stamp)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o755 << 16
        with open(os.path.join(out, name), "rb") as fh:
            zf.writestr(info, fh.read())
PY

( cd "$OUT" && sha256sum php2shell-audit.exe php2shell-audit-win64.zip > SHA256SUMS.txt )

echo
cat "$OUT/SHA256SUMS.txt"
echo

if [ "$MODE" = "--local" ]; then
    echo "==> assets ready in $OUT (upload skipped)"
    exit 0
fi

# --- tag ---------------------------------------------------------------------

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    echo "==> tag $TAG already exists, reusing it"
else
    git tag -a "$TAG" -m "php2shell-audit $VERSION"
    git push origin "$TAG"
fi

# --- publish -----------------------------------------------------------------

NOTES_FILE="CHANGELOG.md"
NOTES_ARG=()
[ -f "$NOTES_FILE" ] && NOTES_ARG=(--notes-file "$NOTES_FILE")

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    echo "==> publishing with gh"
    gh release create "$TAG" \
        "$OUT/php2shell-audit.exe" \
        "$OUT/php2shell-audit-win64.zip" \
        "$OUT/SHA256SUMS.txt" \
        --title "php2shell-audit $VERSION" \
        "${NOTES_ARG[@]}"

elif [ -n "${GITHUB_TOKEN:-}" ]; then
    echo "==> publishing with GITHUB_TOKEN"
    API="https://api.github.com/repos/viviopenclaw-code/php2shell-audit"

    REL_ID="$(curl -sS -X POST \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "$API/releases" \
        -d "{\"tag_name\":\"$TAG\",\"name\":\"php2shell-audit $VERSION\",\"draft\":false}" \
        | sed -n 's/.*"id": *\([0-9]*\).*/\1/p' | head -1)"

    if [ -z "$REL_ID" ]; then
        echo "error: could not create release (bad token or tag?)." >&2
        exit 1
    fi

    for f in php2shell-audit.exe php2shell-audit-win64.zip SHA256SUMS.txt; do
        echo "    uploading $f"
        curl -sS -X POST \
            -H "Authorization: Bearer $GITHUB_TOKEN" \
            -H "Content-Type: application/octet-stream" \
            --data-binary "@$OUT/$f" \
            "https://uploads.github.com/repos/viviopenclaw-code/php2shell-audit/releases/$REL_ID/assets?name=$f" \
            > /dev/null
    done

else
    echo "error: no upload method available." >&2
    echo "  install and authenticate 'gh', or export GITHUB_TOKEN with repo scope." >&2
    echo "  assets are ready in $OUT if you prefer the web UI." >&2
    exit 1
fi

echo "==> done: https://github.com/viviopenclaw-code/php2shell-audit/releases/tag/$TAG"
