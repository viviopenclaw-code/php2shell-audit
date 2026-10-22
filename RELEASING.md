# Releasing

The Windows binary is **not** committed to git. It ships as a GitHub Release
asset so that `git clone` stays small and the repository history never contains
16 MB blobs that could not be removed later.

## What goes where

| Artifact | Location | Why |
|----------|----------|-----|
| source (`php2shell_audit.py`, docs) | git | small, diffable, reviewable |
| `php2shell-audit.exe` | Release asset | 8.1 MB binary, changes wholesale |
| `php2shell-audit-win64.zip` | Release asset | same exe, for transfer |
| `SHA256SUMS.txt` | Release asset | lets users verify the download |

`bin/` is gitignored. `dist/` holds local build output and is also ignored.

## Cut a release

### 1. Bump the version

The version lives in two places and they must match:

```bash
grep -n 'VERSION' php2shell_audit.py     # __version__ = "1.1.0"
```

### 2. Build the Windows binary

On Windows, or cross-build from Linux with wine. Full recipe and the known
pitfalls are in `BUILDING.md`. The result is a single file:

```
dist/php2shell-audit.exe
```

### 3. Assemble the assets

```bash
scripts/release.sh 1.1.0 --local
```

That writes `dist/release/` with the exe, a zip, and `SHA256SUMS.txt`. The zip is
built reproducibly: the entry timestamp is pinned to the source commit date, so
rebuilding the same input yields the same checksum. A plain `zip` embeds the
current time and would make `SHA256SUMS.txt` differ on every run.

The script also refuses to run if the requested version does not match
`__version__` in `php2shell_audit.py`, and warns when tracked files are dirty -
the tag must describe exactly what ships.

### 4. Tag and push the tag

```bash
git tag -a "v$VERSION" -m "php2shell-audit $VERSION"
git push origin "v$VERSION"
```

Tags are pushed **after** the source commit, so the tag always points at code
that is already on `main`.

### 5. Create the release and upload the assets

`scripts/release.sh` wraps the whole flow. Preferred, if the GitHub CLI is
available and authenticated:

```bash
scripts/release.sh 1.1.0
```

Or run the steps by hand:

```bash
gh release create "v$VERSION" \
    dist/release/php2shell-audit.exe \
    dist/release/php2shell-audit-win64.zip \
    dist/release/SHA256SUMS.txt \
    --title "php2shell-audit $VERSION" \
    --notes-file CHANGELOG.md
```

Without `gh`, either use the web UI (**Releases → Draft a new release**, pick the
tag, attach the three files) or call the API directly:

```bash
TOKEN=<a token with repo scope>
REPO=viviopenclaw-code/php2shell-audit

# create the release
curl -sS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/$REPO/releases" \
  -d "{\"tag_name\":\"v$VERSION\",\"name\":\"php2shell-audit $VERSION\",\"draft\":false}"

# upload each asset (upload_url is in the response above)
curl -sS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @dist/release/php2shell-audit.exe \
  "https://uploads.github.com/repos/$REPO/releases/<ID>/assets?name=php2shell-audit.exe"
```

`scripts/release.sh` wraps steps 3 and 5 and picks whichever method is available.

## Do not commit the binary

If `git status` ever shows `bin/` or a `.exe`, the ignore file regressed. Fix it
before committing; a binary that reaches `main` can only be removed by rewriting
history and force-pushing, which breaks every existing clone.

## Verifying a download

```cmd
certutil -hashfile php2shell-audit.exe SHA256
```

Compare against the `SHA256SUMS.txt` from the same release. The exe is unsigned,
so SmartScreen warns on first run; the checksum is what actually establishes
integrity.
