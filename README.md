# php2shell-audit

A **read-only, non-intrusive** auditor for the two recent high-severity PHP RCE
vulnerabilities:

| CVE | Title | Severity | Fixed in |
|-----|-------|----------|----------|
| CVE-2026-109618 | RCE via OOM corruption (CWE-416) | 9.2 CVSS 4.0 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| CVE-2026-109619 | RCE via stale global state (CWE-416) | 9.2 CVSS 4.0 / 9.8 CVSS 3.1 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |

Both are unauthenticated remote code execution issues in the PHP engine itself.
This tool helps you answer one question quickly: **is this host exposed?**

> **Read [`DISCLAIMER.md`](DISCLAIMER.md) first.** This is a diagnostic aid, not a
> security guarantee. `UNKNOWN` does not mean safe, distro backports cause false
> positives, and you must have authorization to probe every target.

## Screenshots and descriptions
Vulnerability exists：[VULNERABLE] 
<img width="879" height="439" alt="image" src="https://github.com/user-attachments/assets/5fe83f25-fd75-448c-87bf-f6c949100ac1" />

Vulnerability Fix：[PASS] 
<img width="984" height="439" alt="image" src="https://github.com/user-attachments/assets/379daa10-3b8e-4a5f-a287-ca83af2269f4" />

Insufficient data to prove：[UNKNOWN] 
<img width="834" height="402" alt="image" src="https://github.com/user-attachments/assets/75bcc2b3-eacc-4445-9a4f-8390b3876fef" />

## What it does

* **`--local`** — audits the machine it runs on:
  * discovers every PHP binary / FPM daemon / Apache `mod_php` module,
  * reads each version banner (`php -v`) and compares it to the fixed releases,
  * parses `php.ini` for the directives that act as interim mitigations,
  * lists the running workers you must restart after patching,
  * prints concrete upgrade commands for Debian, RHEL, Alpine and source builds.
* **`--remote`** — fingerprints one target, or a whole list in parallel:
  * sends **one benign HEAD request** (falls back to GET only if the server
    rejects HEAD) and reads the response headers,
  * parses `Server:` and `X-Powered-By:` for a `PHP/x.y.z` disclosure,
  * reports `VULNERABLE` only when a version is actually disclosed and below the
    fixed release; otherwise `UNKNOWN`.

## What it deliberately does NOT do

* It never generates or sends an exploit. No multipart bodies, no oversized
  payloads, no OOM triggers, no use-after-free triggers.
* It never writes to, installs on, or modifies the audited host.
* Remote mode makes **one request per target**. It does not brute-force, fuzz or
  probe for crash behaviour.

Remote mode therefore **cannot prove exploitability** — it can only report what a
server volunteers. A hidden version is `UNKNOWN`, not "safe".

## Requirements

**Linux / macOS:** Python 3.8+ and the standard library. Nothing to `pip install`.

**Windows:** use the prebuilt `php2shell-audit.exe` from the release (no Python
needed), or run the script with Python 3.8+ installed.

## Installation

```bash
# Linux / macOS
git clone https://github.com/viviopenclaw-code/php2shell-audit.git
cd php2shell-audit
chmod +x php2shell_audit.py

# Windows: no Python needed - download the release asset
#   https://github.com/viviopenclaw-code/php2shell-audit/releases/latest
```

### Prebuilt Windows binary

The Windows build is published as a **GitHub Release asset**, not committed to
the repository. Grab it from the latest release:

| Asset | What it is |
|-------|------------|
| `php2shell-audit.exe` | single-file console binary, Windows 10/11 x64 |
| `php2shell-audit-win64.zip` | the same exe, zipped for transfer |
| `SHA256SUMS.txt` | checksums - verify before running |

```cmd
certutil -hashfile php2shell-audit.exe SHA256
```

Compare the output against `SHA256SUMS.txt` from the same release. The binary is
unsigned, so SmartScreen may warn on first launch - verify the checksum first;
that is what the file is for.

## Usage

```bash
# Local audit
python3 php2shell_audit.py --local

# Local audit, JSON report for CI / SIEM
python3 php2shell_audit.py --local --json report.json

# Single remote target
python3 php2shell_audit.py --remote example.com

# Batch remote targets, 20 parallel workers
python3 php2shell_audit.py --remote --file targets.txt --workers 20 --json out.json

# Targets can also be passed inline
python3 php2shell_audit.py --remote https://a.example 10.0.0.5
```

`targets.txt` — one target per line, `#` starts a comment (start from
`targets.example.txt`):

```
# production fleet
example.com
https://shop.example.net
10.0.0.5:8080
```

### Options

| Flag | Meaning |
|------|---------|
| `--local` / `--remote` | pick the mode (exactly one) |
| `--file PATH` | read remote targets from a file |
| `--json PATH` | write a full JSON report (`-` = stdout) |
| `--timeout N` | per-request timeout, default 8s |
| `--workers N` | parallel workers for remote batches, default 10 |
| `--insecure` | skip TLS verification (fingerprinting only) |

### How it runs on each platform

| | Linux / macOS | Windows |
|---|---|---|
| PHP discovery | `/usr/bin/php*`, `/usr/sbin/php-fpm*`, `/opt/*`, `/usr/lib/php/*/sapi/*`, Homebrew | `C:\php`, XAMPP, WAMP, Laragon, Chocolatey, Scoop, `Program Files\PHP` |
| Process listing | `/proc` (falls back to `ps`) | `tasklist` |
| Entry point | `python3 php2shell_audit.py` | `php2shell-audit.exe` |
| `--local` on a host with no PHP | reports `[UNKNOWN]`, never `[PASS]` | same |

This tool audits the machine it runs on. If PHP lives in a container or on a
remote web server, run it inside that container, or use `--remote`.

## Building the Windows executable

The release `.exe` is built with PyInstaller. On Windows:

```cmd
pip install pyinstaller
pyinstaller --onefile --console --name php2shell-audit php2shell_audit.py
```

Cross-building from Linux works with wine plus the Windows Python build; see
`BUILDING.md`.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | no vulnerable version found |
| `2` | at least one vulnerable version found |
| `1` | tool error (e.g. JSON report could not be written) |

Exit code `2` on a hit makes the tool usable directly as a CI/CD gate.

## Reading the output

```
[VULNERABLE] https://shop.example.net
         http    : 200
         server  : Apache/2.4.62 (Debian)
         powered : PHP/8.4.16
         php     : 8.4.16
         verdict : PHP 8.4.16 < fixed 8.4.27
```

`[PASS]` = version disclosed and at/above the fix. `[WARNING]` = a mitigation
directive is not set as recommended. `[UNKNOWN]` = not enough information.

## Remediation

**Patching is the only complete fix.**

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install --only-upgrade php
# RHEL / Fedora
sudo dnf upgrade 'php*'
# Alpine
sudo apk upgrade php83 php84
```

Interim mitigations, only until you can patch — apply and then **restart every
worker** (`systemctl restart php*-fpm apache2 nginx`):

* **CVE-2026-109619** — `session.upload_progress.enabled=0`.
  Removes the demonstrated session producer/consumer pair.
* **CVE-2026-109618** — the advisory's primary config mitigation is
  `memory_limit=-1`, enforced administratively with no pool or application
  override. Keep `post_max_size` conservative and cap the decoded request size at
  the reverse proxy. **Do not use `RLIMIT_AS` / `RLIMIT_DATA`** — those make
  `mmap()` fail and re-enter the vulnerable `longjmp()` path.
* **PHP 8.5 only** — `fatal_error_backtraces=0`, which removes the producer used
  by the confirmed mod_php RCE case.

Each of these is partial. None covers every lifecycle path described in the
advisories.

## References

* CVE-2026-109618 — <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
* CVE-2026-109619 — <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
* Wiz write-up — <https://www.wiz.io/blog/php2shell-php-rce>

## Disclaimer

This tool is a diagnostic aid, not a security guarantee or a penetration test.

* **`UNKNOWN` does not mean safe.** Remote mode only reports what a server
  volunteers; a vulnerable host that hides its version is reported `UNKNOWN`.
* **Distro backports cause false positives.** Debian/Ubuntu/RHEL/Alpine often
  patch without bumping the version, so a patched host can read `VULNERABLE`.
  Check `apt changelog` / `rpm -q --changelog` before acting.
* **Authorized use only.** Scanning systems without explicit written permission
  may be illegal (CFAA, UK CMA 1990, 《刑法》第 285 条). A single `HEAD` request
  is still a request and still appears in the target's logs.
* **No warranty.** Provided "AS IS" under Apache-2.0 sections 7 and 8.

Full text, including report-handling and third-party data caveats:
[`DISCLAIMER.md`](DISCLAIMER.md).

## License

Apache License 2.0. See `LICENSE`.
