# Changelog

## 1.1.0

Initial public release.

**Local audit (`--local`)**

- Discovers PHP binaries, FPM daemons and Apache `mod_php` modules across
  Debian/Ubuntu, RHEL/Fedora, Alpine, Arch, Homebrew, and on Windows across
  `C:\php`, XAMPP, WAMP, Laragon, Chocolatey, Scoop and `Program Files\PHP`.
- Reads every version banner and compares against the fixed releases
  `8.2.35` / `8.3.36` / `8.4.27` / `8.5.12` for CVE-2026-109618 and
  CVE-2026-109619.
- Audits the interim-mitigation directives in each loaded `php.ini`
  (`memory_limit`, `session.upload_progress.enabled`, `fatal_error_backtraces`).
- Lists the running workers that must be restarted after patching, and prints
  concrete upgrade commands per platform.

**Remote fingerprint (`--remote`)**

- One benign `HEAD` request per target (falls back to a single `GET` only when
  the server rejects `HEAD`), reading `Server:`, `X-Powered-By:` and
  `Set-Cookie`.
- Batch mode with a thread pool (`--file`, `--workers`), plus `--json` output for
  CI/SIEM integration.
- Reports `VULNERABLE` only on disclosed versions below the fix; a hidden
  version is `UNKNOWN`, never `PASS`.

**Packaging**

- Windows x64 single-file binary built with PyInstaller; the build recipe and
  its known pitfalls are documented in `BUILDING.md`.
- Exit codes: `0` clean, `2` vulnerable version found, `1` tool error, so the
  tool can gate a pipeline directly.
