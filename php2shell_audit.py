#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell-audit - defensive auditor for CVE-2026-109618 and CVE-2026-109619.

Two modes:
  * local  - inspect this machine's PHP binaries, php.ini/FPM config and processes.
  * remote - fingerprint one or many http(s) targets for a PHP version disclosure.

Design rules enforced by this tool:
  * Read-only. It never writes, installs or modifies anything on the host.
  * No exploit traffic. Remote mode only issues benign GET/HEAD requests and
    reads response headers/cookies. It never sends multipart bodies, oversized
    payloads or anything that could trigger an OOM or a use-after-free.

Only the Python 3 standard library is used, so the same single file runs on any
Linux distribution (and macOS) without a dependency install step.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__version__ = "1.1.0"

IS_WINDOWS = os.name == "nt"

# --------------------------------------------------------------------------- #
# CVE knowledge base
# --------------------------------------------------------------------------- #

# Fixed release for each maintained branch. A branch whose patch level is below
# its entry here is affected; anything at or above it carries the patch.
FIXED_RELEASES: Dict[Tuple[int, int], Tuple[int, int, int]] = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

# Advisories / references, printed in the report so an operator can verify.
REFERENCES = [
    "CVE-2026-109618 (CVSS 4.0 9.2) RCE via OOM corruption - CWE-416",
    "  https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "CVE-2026-109619 (CVSS 4.0 9.2 / 3.1 9.8) RCE via stale global state - CWE-416",
    "  https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
]

# Which config directives act as partial mitigations, and the value considered
# safe. These are administrative mitigations only: patching remains the fix.
MITIGATION_DIRECTIVES: Dict[str, str] = {
    "session.upload_progress.enabled": "0",   # removes the session consumer/producer
    "fatal_error_backtraces": "0",            # PHP 8.5 producer used by the confirmed RCE
    "expose_php": "0",                        # not a mitigation, but reduces remote fingerprinting
}


# --------------------------------------------------------------------------- #
# Terminal helpers
# --------------------------------------------------------------------------- #

class Color:
    """ANSI colours, disabled automatically when stdout is not a TTY."""

    enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    @classmethod
    def _wrap(cls, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if cls.enabled else text

    @classmethod
    def green(cls, t: str) -> str: return cls._wrap("32", t)

    @classmethod
    def red(cls, t: str) -> str: return cls._wrap("31;1", t)

    @classmethod
    def yellow(cls, t: str) -> str: return cls._wrap("33", t)

    @classmethod
    def cyan(cls, t: str) -> str: return cls._wrap("36", t)

    @classmethod
    def bold(cls, t: str) -> str: return cls._wrap("1", t)

    @classmethod
    def dim(cls, t: str) -> str: return cls._wrap("2", t)


def tag(status: str) -> str:
    """Render a coloured [STATUS] tag."""
    table = {
        "PASS": Color.green("[PASS]"),
        "VULNERABLE": Color.red("[VULNERABLE]"),
        "WARNING": Color.yellow("[WARNING]"),
        "UNKNOWN": Color.yellow("[UNKNOWN]"),
        "INFO": Color.cyan("[INFO]"),
    }
    return table.get(status, f"[{status}]")


# --------------------------------------------------------------------------- #
# Version model
# --------------------------------------------------------------------------- #

VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Extract the first x.y.z triple from a string such as 'PHP 8.4.16'."""
    m = VERSION_RE.search(text or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def classify(version: Optional[Tuple[int, int, int]]) -> Tuple[str, str]:
    """
    Compare a PHP version against the fixed releases.

    Returns (status, reason) where status is one of VULNERABLE / PASS / UNKNOWN.
    """
    if version is None:
        return "UNKNOWN", "no parsable PHP version was found"

    major, minor, patch = version
    fixed = FIXED_RELEASES.get((major, minor))

    if fixed is None:
        if (major, minor) < (8, 2):
            # Every branch below 8.2 is outside the maintained set; upstream
            # never shipped a fixed build for it, so treat it as affected.
            return "VULNERABLE", (
                f"PHP {major}.{minor}.{patch} is an unsupported branch with no "
                f"fixed release; treat as affected"
            )
        return "UNKNOWN", (
            f"PHP {major}.{minor}.{patch} is newer than the known fixed set; "
            f"verify against the upstream advisory"
        )

    if (major, minor, patch) < fixed:
        return "VULNERABLE", (
            f"PHP {major}.{minor}.{patch} < fixed {fixed[0]}.{fixed[1]}.{fixed[2]}"
        )
    return "PASS", (
        f"PHP {major}.{minor}.{patch} >= fixed {fixed[0]}.{fixed[1]}.{fixed[2]}"
    )


# --------------------------------------------------------------------------- #
# Local audit
# --------------------------------------------------------------------------- #

@dataclass
class PHPInstall:
    path: str
    kind: str                      # cli | fpm | cgi | apache-module | unknown
    version_raw: str = ""
    version: Optional[Tuple[int, int, int]] = None
    status: str = "UNKNOWN"
    reason: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["version"] = ".".join(map(str, self.version)) if self.version else None
        return d


@dataclass
class LocalReport:
    hostname: str = ""
    platform: str = ""
    installs: List[PHPInstall] = field(default_factory=list)
    ini_files: List[str] = field(default_factory=list)
    ini_values: Dict[str, str] = field(default_factory=dict)
    processes: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "platform": self.platform,
            "installs": [i.to_dict() for i in self.installs],
            "ini_files": self.ini_files,
            "ini_values": self.ini_values,
            "processes": self.processes,
            "notes": self.notes,
        }


# Candidate paths, ordered so the most common distribution layout wins.
PHP_PATH_GLOBS = [
    "/usr/bin/php", "/usr/bin/php[0-9]*", "/usr/local/bin/php", "/usr/local/bin/php[0-9]*",
    "/usr/sbin/php-fpm[0-9]*", "/usr/sbin/php-fpm", "/usr/local/sbin/php-fpm[0-9]*",
    "/opt/*/bin/php", "/opt/*/sbin/php-fpm[0-9]*",
    "/usr/lib/php/*/sapi/fpm/php-fpm", "/usr/lib/php/*/sapi/cli/php",
    "/opt/homebrew/bin/php", "/opt/homebrew/sbin/php-fpm",
]

# Windows installs are never at the Linux paths above, so the bundle is probed
# with its own list. These cover the common bundles (XAMPP, WAMP, Laragon,
# Chocolatey, Scoop) plus a plain C:\php drop-in build.
PHP_PATH_GLOBS_WINDOWS = [
    r"C:\php\php.exe",
    r"C:\php*\php.exe",
    r"C:\Program Files\PHP\*\php.exe",
    r"C:\Program Files (x86)\PHP\*\php.exe",
    r"C:\xampp\php\php.exe",
    r"C:\wamp*\bin\php\php*\php.exe",
    r"C:\laragon\bin\php\php*\php.exe",
    r"C:\tools\php*\php.exe",
    r"C:\ProgramData\chocolatey\bin\php.exe",
    r"C:\ProgramData\chocolatey\lib\php*tool\tools\php.exe",
    r"%USERPROFILE%\scoop\apps\php\current\php.exe",
]


def _kind_from_path(path: str) -> str:
    base = os.path.basename(path)
    if "php-fpm" in base:
        return "fpm"
    if base.startswith("php-cgi"):
        return "cgi"
    if "/sapi/fpm/" in path:
        return "fpm"
    if base.startswith("php"):
        return "cli"
    return "unknown"


def _silence_subprocess_gc() -> None:
    """
    Suppress the 'Exception ignored in Popen.__del__: [WinError 6]' noise.

    When process creation fails on Windows (missing binary, broken handle), the
    half-built Popen object still runs its destructor during garbage collection
    and prints a traceback to stderr. The failure is already reported through
    _run's return value, so the duplicate GC complaint is pure noise in a
    console tool. Only subprocess-internal OSErrors are dropped; everything else
    still goes to the default handler.
    """
    previous = sys.unraisablehook

    def hook(unraisable):
        exc = unraisable.exc_value
        owner = getattr(unraisable.object, "__qualname__", "") or ""
        if isinstance(exc, OSError) and ("Popen" in owner or "Handle" in owner):
            return
        previous(unraisable)

    sys.unraisablehook = hook


def _run(cmd: Sequence[str], timeout: int = 8) -> Tuple[int, str]:
    """Run a command read-only and capture combined output. Never raises."""
    try:
        proc = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout or b"").decode("utf-8", "replace")
    except FileNotFoundError:
        return 127, "command not found"
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, f"{type(exc).__name__}: {exc}"


def discover_php_binaries() -> List[str]:
    """Find every PHP-family executable we can see without scanning the disk."""
    import glob

    patterns = PHP_PATH_GLOBS_WINDOWS if IS_WINDOWS else PHP_PATH_GLOBS

    found: List[str] = []
    for pattern in patterns:
        pattern = os.path.expandvars(pattern)
        for hit in glob.glob(pattern):
            if os.path.isfile(hit) and hit not in found:
                # os.access(X_OK) is unreliable on Windows; existence is enough.
                if IS_WINDOWS or os.access(hit, os.X_OK):
                    found.append(hit)

    # PATH lookup as a fallback for non-standard installs.
    for name in ("php", "php-fpm", "php-cgi"):
        which = shutil.which(name)
        if which and which not in found:
            found.append(which)

    # Apache mod_php: the module file proves a loaded SAPI even without a binary.
    apache_patterns = (
        (r"C:\xampp\apache\bin\php*.dll",)
        if IS_WINDOWS else
        ("/usr/lib/apache2/modules/libphp*.so",
         "/usr/lib64/httpd/modules/libphp*.so",
         "/etc/apache2/mods-enabled/php*.load")
    )
    for pattern in apache_patterns:
        for hit in glob.glob(pattern):
            if hit not in found:
                found.append(hit)

    return sorted(found)


def audit_binary(path: str) -> PHPInstall:
    """Read the version banner of one PHP executable. Read-only."""
    kind = _kind_from_path(path)
    install = PHPInstall(path=path, kind=kind)

    if path.endswith((".so", ".load")):
        # A module file cannot be executed directly; record and move on.
        install.status = "UNKNOWN"
        install.reason = "Apache module file; version must be read from the SAPI"
        return install

    code, out = _run([path, "-v"])
    if code != 0 and not out:
        install.error = f"could not execute ({code})"
        install.status = "UNKNOWN"
        install.reason = "execution failed"
        return install

    install.version_raw = out.splitlines()[0].strip() if out else ""
    install.version = parse_version(install.version_raw)
    install.status, install.reason = classify(install.version)
    return install


def find_ini_files(binary: str) -> List[str]:
    """Ask PHP where its ini lives, then fall back to the usual locations."""
    paths: List[str] = []
    if os.path.isfile(binary) and not binary.endswith((".so", ".load")):
        code, out = _run([binary, "--ini"])
        if code == 0:
            for line in out.splitlines():
                if "=>" in line:
                    candidate = line.split("=>", 1)[1].strip()
                    if candidate and candidate != "(none)" and candidate not in paths:
                        paths.append(candidate)

    ini_patterns = (
        (r"C:\php\php.ini", r"C:\Windows\php.ini", r"C:\xampp\php\php.ini",
         r"C:\wamp*\bin\php\php*\php.ini", r"C:\laragon\bin\php\php*\php.ini",
         r"C:\Program Files\PHP\*\php.ini", r"C:\tools\php*\php.ini")
        if IS_WINDOWS else
        ("/etc/php/*/*/php.ini", "/etc/php.ini", "/etc/php/*/php.ini",
         "/usr/local/etc/php.ini", "/usr/local/etc/php/php.ini",
         "/opt/homebrew/etc/php/*/php.ini")
    )
    for pattern in ini_patterns:
        import glob
        for hit in glob.glob(pattern):
            if os.path.isfile(hit) and hit not in paths:
                paths.append(hit)
    return paths


def read_ini_values(ini_paths: Iterable[str]) -> Dict[str, str]:
    """
    Parse only the directives we care about. Missing values are reported as
    '(unset)' so the operator can tell "absent" from "unreadable".
    """
    values: Dict[str, str] = {}
    for directive in MITIGATION_DIRECTIVES:
        values[directive] = "(unset)"

    for ini in ini_paths:
        try:
            with open(ini, "r", encoding="utf-8", errors="replace") as handle:
                for raw in handle:
                    line = raw.split(";", 1)[0].split("#", 1)[0].strip()
                    if "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip().lower()
                    if key in values:
                        # Later files override earlier ones, which mirrors the
                        # scan order PHP itself uses.
                        values[key] = val.strip().strip('"')
        except PermissionError:
            values.setdefault("_errors", "")
            values["_errors"] = (values.get("_errors", "") + f" permission denied: {ini}").strip()
        except OSError as exc:
            values["_errors"] = (values.get("_errors", "") + f" {ini}: {exc}").strip()
    return values


def scan_processes() -> List[str]:
    """List running web/PHP processes without touching the network."""
    targets = ("php-fpm", "php-cgi", "php", "httpd", "apache2", "nginx",
               "frankenphp", "lsphp")
    seen: List[str] = []

    # The auditor's own process name starts with "php" on every platform
    # (php2shell-audit.exe), so it must never be counted as a PHP worker.
    self_name = os.path.basename(sys.argv[0]).lower()
    if self_name.endswith(".exe"):
        self_name = self_name[:-4]

    if IS_WINDOWS:
        # tasklist is present on every supported Windows build.
        code, out = _run(["tasklist", "/FO", "CSV", "/NH"])
        if code == 0:
            for line in out.splitlines():
                name = line.split(",", 1)[0].strip('"').lower()
                if name.endswith(".exe"):
                    name = name[:-4]
                if not name or name == self_name or "php2shell" in name:
                    continue
                if any(name == t or name.startswith(t) for t in targets):
                    seen.append(name)
    elif os.path.isdir("/proc"):
        for entry in sorted(os.listdir("/proc")):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/comm", "r", encoding="utf-8", errors="replace") as fh:
                    name = fh.read().strip()
            except OSError:
                continue
            if any(name.startswith(t) for t in targets):
                seen.append(f"{name} (pid {entry})")
    else:
        code, out = _run(["ps", "-eo", "comm="])
        if code == 0:
            for name in out.split():
                if any(name.startswith(t) for t in targets):
                    seen.append(name)

    # Collapse duplicates while keeping one representative line per service.
    collapsed: List[str] = []
    for item in seen:
        service = item.split(" (pid")[0]
        if not any(existing.startswith(service) for existing in collapsed):
            collapsed.append(f"{service} - {sum(1 for s in seen if s.startswith(service))} process(es)")
    return collapsed


def run_local_audit() -> LocalReport:
    report = LocalReport(
        hostname=socket.gethostname(),
        platform=f"{platform.system()} {platform.release()} ({platform.machine()})",
    )

    binaries = discover_php_binaries()
    if not binaries:
        report.notes.append("No PHP binary, FPM daemon or Apache PHP module was found on this host.")
        if IS_WINDOWS:
            report.notes.append(
                "Windows note: this tool only reads local files and runs 'php -v'. "
                "If PHP lives in a container or on a remote web server, run --remote "
                "or run the auditor inside that container."
            )

    for path in binaries:
        report.installs.append(audit_binary(path))

    # Config audit only matters when something is actually vulnerable, but we
    # always collect it so the JSON report is self-contained.
    ini_paths: List[str] = []
    for install in report.installs:
        for ini in find_ini_files(install.path):
            if ini not in ini_paths:
                ini_paths.append(ini)
    report.ini_files = ini_paths
    report.ini_values = read_ini_values(ini_paths)

    report.processes = scan_processes()
    return report


def render_local(report: LocalReport) -> None:
    print(Color.bold(f"\nphp2shell-audit {__version__} - local audit"))
    print(f"Host    : {report.hostname}")
    print(f"System  : {report.platform}")
    print("-" * 72)

    if not report.installs:
        print(tag("UNKNOWN"), "No PHP installation detected.")
    for install in report.installs:
        print(f"{tag(install.status)} {install.path} [{install.kind}]")
        if install.version_raw:
            print(f"         version : {install.version_raw}")
        print(f"         detail  : {install.reason or install.error}")

    print("-" * 72)
    print(Color.bold("php.ini mitigation directives"))
    for key in MITIGATION_DIRECTIVES:
        value = report.ini_values.get(key, "(unset)")
        safe = value == MITIGATION_DIRECTIVES[key]
        marker = tag("PASS") if safe else tag("WARNING")
        print(f"{marker} {key} = {value}  (recommended {MITIGATION_DIRECTIVES[key]})")
    if report.ini_values.get("_errors"):
        print(tag("WARNING"), "config read issues:" + report.ini_values["_errors"])

    print("-" * 72)
    print(Color.bold("Running services that must be restarted after patching"))
    if report.processes:
        for proc in report.processes:
            print(f"{tag('INFO')} {proc}")
    else:
        print(f"{tag('INFO')} no PHP/web worker processes detected")

    if report.notes:
        print("-" * 72)
        for note in report.notes:
            print(tag("INFO"), note)

    print("-" * 72)
    print(Color.bold("Remediation"))
    print_remediation(report)


def print_remediation(report: LocalReport) -> None:
    vulnerable = [i for i in report.installs if i.status == "VULNERABLE"]
    if not report.installs:
        print(tag("UNKNOWN"),
              "No PHP install was audited, so nothing can be confirmed safe.")
    elif not vulnerable:
        print(tag("PASS"), "No affected PHP build found. Keep the packages updated.")

    for install in vulnerable:
        fixed = FIXED_RELEASES.get(install.version[:2]) if install.version else None
        print(tag("VULNERABLE"), f"{install.path} ({install.version_raw or 'unknown'})")
        if fixed:
            print(f"         upgrade to {fixed[0]}.{fixed[1]}.{fixed[2]} or later")
        print("         Debian/Ubuntu : sudo apt update && sudo apt install --only-upgrade php")
        print("         RHEL/Fedora   : sudo dnf upgrade 'php*'")
        print("         Alpine        : sudo apk upgrade php83 php84")
        print("         source build  : rebuild from php-src with the security patch")

    if vulnerable:
        print()
        print(Color.bold("Interim mitigation (only until you can patch)"))
        print("  CVE-2026-109619: set session.upload_progress.enabled=0 in php.ini / pool config")
        print("  CVE-2026-109618: the advisory's primary config mitigation is memory_limit=-1,")
        print("                   enforced administratively, with no pool/app override.")
        print("                   Keep post_max_size conservative and cap request size at the")
        print("                   reverse proxy. Do not use RLIMIT_AS / RLIMIT_DATA - they make")
        print("                   mmap() fail and re-enter the vulnerable longjmp() path.")
        print("  PHP 8.5 only   : set fatal_error_backtraces=0")
        print("  Then restart every worker: systemctl restart php*-fpm apache2 nginx")
        print()
        print(Color.dim("  Patching is the only complete fix; the settings above are partial."))


# --------------------------------------------------------------------------- #
# Remote fingerprinting (non-intrusive)
# --------------------------------------------------------------------------- #

@dataclass
class RemoteResult:
    target: str
    reachable: bool = False
    status_code: Optional[int] = None
    server: str = ""
    powered_by: str = ""
    cookies: List[str] = field(default_factory=list)
    version: Optional[Tuple[int, int, int]] = None
    status: str = "UNKNOWN"
    reason: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["version"] = ".".join(map(str, self.version)) if self.version else None
        return d


# Version strings appear in Server and X-Powered-By headers. Only these two are
# parsed; everything else is reported verbatim.
HEADER_VERSION_RE = re.compile(r"PHP/(\d+\.\d+\.\d+)", re.IGNORECASE)


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        return target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target


def fetch_target(target: str, timeout: float, insecure: bool) -> RemoteResult:
    """
    Issue one benign HEAD request (falling back to GET) and read the headers.

    This never sends a body, never uploads a file and never repeats a request to
    provoke a crash: one request per target, by design.
    """
    result = RemoteResult(target=target)
    url = normalize_target(target)

    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": f"php2shell-audit/{__version__} (defensive; read-only)"},
    )

    def _open(req):
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)

    try:
        try:
            response = _open(request)
        except urllib.error.HTTPError as http_err:
            # 405/501 simply mean HEAD is not allowed; retry once with GET.
            if http_err.code in (403, 405, 501):
                response = _open(urllib.request.Request(
                    url, method="GET",
                    headers={"User-Agent": request.headers["User-agent"]},
                ))
            else:
                response = http_err
        with response:
            result.reachable = True
            result.status_code = response.status
            headers = response.headers
            result.server = headers.get("Server", "") or ""
            result.powered_by = headers.get("X-Powered-By", "") or ""
            result.cookies = headers.get_all("Set-Cookie") or []
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.reason = "target unreachable"
        return result

    # Fingerprint only from what the server voluntarily disclosed.
    blob = " ".join([result.server, result.powered_by])
    match = HEADER_VERSION_RE.search(blob)
    if match:
        result.version = parse_version(match.group(1))
        result.status, result.reason = classify(result.version)
    else:
        # A PHP session cookie proves PHP is present but not which version.
        has_php_cookie = any("PHPSESSID" in c for c in result.cookies)
        if result.powered_by or has_php_cookie:
            result.status = "UNKNOWN"
            result.reason = (
                "PHP detected but the version is hidden; only the operator can "
                "confirm it locally (expose_php=Off)"
            )
        else:
            result.status = "UNKNOWN"
            result.reason = "no PHP version disclosed in response headers"
    return result


def load_targets(args: argparse.Namespace) -> List[str]:
    targets: List[str] = list(args.targets or [])
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        targets.append(line)
        except OSError as exc:
            print(tag("WARNING"), f"cannot read target file: {exc}", file=sys.stderr)
    # De-duplicate while preserving order.
    seen = set()
    unique = []
    for item in targets:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def run_remote_audit(targets: Sequence[str], timeout: float, workers: int,
                     insecure: bool) -> List[RemoteResult]:
    results: List[RemoteResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(fetch_target, t, timeout, insecure): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:  # defensive: a worker must never kill the run
                results.append(RemoteResult(target=futures[future], error=str(exc)))
    # Present in the same order the user supplied them.
    order = {t: i for i, t in enumerate(targets)}
    results.sort(key=lambda r: order.get(r.target, 0))
    return results


def render_remote(results: Sequence[RemoteResult]) -> None:
    print(Color.bold(f"\nphp2shell-audit {__version__} - remote fingerprint"))
    print("-" * 72)
    for res in results:
        print(f"{tag(res.status)} {res.target}")
        if res.error:
            print(f"         error   : {res.error}")
            continue
        print(f"         http    : {res.status_code}")
        if res.server:
            print(f"         server  : {res.server}")
        if res.powered_by:
            print(f"         powered : {res.powered_by}")
        if res.cookies:
            print(f"         cookies : {', '.join(c.split(';')[0] for c in res.cookies[:4])}")
        if res.version:
            print(f"         php     : {'.'.join(map(str, res.version))}")
        print(f"         verdict : {res.reason}")

    print("-" * 72)
    print(Color.bold("How to read this"))
    print("  A disclosed version below the fixed release is a real VULNERABLE hit.")
    print("  UNKNOWN means the server hid its version - it is not a clean bill of")
    print("  health. Confirm with the local audit on the host itself.")
    print("  This tool never sends exploit traffic, so it cannot prove exploitability.")
    print()
    print(Color.bold("References"))
    for line in REFERENCES:
        print("  " + line)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell_audit.py",
        description="Read-only auditor for CVE-2026-109618 and CVE-2026-109619.",
        epilog="Example: php2shell_audit.py --local --json report.json",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--local", action="store_true",
                      help="audit this host's PHP installs, config and processes")
    mode.add_argument("--remote", action="store_true",
                      help="fingerprint remote targets (version disclosure only)")

    parser.add_argument("targets", nargs="*",
                        help="remote targets, e.g. example.com https://1.2.3.4")
    parser.add_argument("--file", metavar="PATH",
                        help="file with one remote target per line (# comments allowed)")
    parser.add_argument("--json", metavar="PATH",
                        help="write the full report as JSON to PATH (use - for stdout)")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="per-request timeout in seconds (default 8)")
    parser.add_argument("--workers", type=int, default=10,
                        help="parallel workers for remote batch mode (default 10)")
    parser.add_argument("--insecure", action="store_true",
                        help="do not verify TLS certificates (fingerprinting only)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    if IS_WINDOWS:
        _silence_subprocess_gc()

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.remote and not (args.targets or args.file):
        parser.error("--remote needs at least one target or --file")
    if args.workers < 1:
        parser.error("--workers must be >= 1")

    if args.local:
        report = run_local_audit()
        render_local(report)
        payload = {"mode": "local", "tool": __version__, "report": report.to_dict()}
        exit_code = 2 if any(i.status == "VULNERABLE" for i in report.installs) else 0
    else:
        targets = load_targets(args)
        results = run_remote_audit(targets, args.timeout, args.workers, args.insecure)
        render_remote(results)
        payload = {"mode": "remote", "tool": __version__,
                   "results": [r.to_dict() for r in results]}
        exit_code = 2 if any(r.status == "VULNERABLE" for r in results) else 0

    if args.json:
        text = json.dumps(payload, indent=2, ensure_ascii=False)
        if args.json == "-":
            print(text)
        else:
            try:
                with open(args.json, "w", encoding="utf-8") as handle:
                    handle.write(text + "\n")
                print(tag("INFO"), f"JSON report written to {args.json}")
            except OSError as exc:
                print(tag("WARNING"), f"cannot write JSON report: {exc}", file=sys.stderr)
                exit_code = max(exit_code, 1)

    # 0 = clean, 2 = at least one vulnerable target found, 1 = tool error.
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
