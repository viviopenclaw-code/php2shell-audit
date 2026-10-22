# Building the Windows executable from Linux

The `php2shell-audit.exe` release artifact is produced on Linux by cross-building
with wine and a Windows CPython distribution. No Windows machine is required.

## Why not just `pyinstaller` on Linux?

PyInstaller does not cross-compile. Running Linux PyInstaller produces an ELF
binary, not a PE executable. The trick is to run the *Windows* PyInstaller under
wine.

## Prerequisites

```bash
sudo apt install -y wine64 wine unzip curl
```

## Steps

```bash
export WINEPREFIX=/root/.wine-py2s
export WINEARCH=win64
export WINEDEBUG=-all

mkdir -p /root/bUILD/win && cd /root/bUILD/win
wineboot -i && wineserver -w
```

Install a Windows CPython. The NuGet package is a self-contained layout with
`python.exe`, `DLLs/` and `Lib/`:

```bash
curl -sSL -o python.nupkg https://www.nuget.org/api/v2/package/python/3.12.8
unzip -qo python.nupkg -d pynuget
wine pynuget/tools/python.exe -V      # sanity check
```

Install PyInstaller into that interpreter:

```bash
wine pynuget/tools/python.exe -m pip install pyinstaller
```

Build:

```bash
cp /path/to/php2shell_audit.py .
wine pynuget/tools/python.exe -m PyInstaller \
    --onefile --console --name php2shell-audit --clean --noconfirm \
    php2shell_audit.py
```

The artifact lands in `dist/php2shell-audit.exe` (PE32+ x86-64, ~8 MB).

## Smoke test under wine

```bash
wine dist/php2shell-audit.exe --version
wine dist/php2shell-audit.exe --local
wine dist/php2shell-audit.exe --remote example.com
```

`--local` on a wine prefix reports `[UNKNOWN] No PHP installation detected.`
That is the expected result: no PHP is installed inside the prefix.

## Windows-specific behaviour worth re-testing after code changes

These were fixed after the first build and are easy to regress:

1. **Process scan must not match itself.** The exe is named
   `php2shell-audit.exe`, which starts with `php`, so the name filter has to
   exclude the auditor's own process. `scan_processes()` compares against
   `os.path.basename(sys.argv[0])`.
2. **No spurious `[PASS]` with zero PHP installs.** `print_remediation()` checks
   `report.installs` before concluding anything is safe.
3. **No `Exception ignored in Popen.__del__: [WinError 6]` noise.** When process
   creation fails on Windows the half-built `Popen` still runs its destructor
   during GC. `_silence_subprocess_gc()` filters those specific `OSError`s via
   `sys.unraisablehook`.

## Notes

* Windows Defender and SmartScreen frequently flag one-file PyInstaller bundles
  as suspicious. Publish the SHA256 alongside the release so users can verify.
* The exe bundles CPython, so it is self-contained. Do not ship it next to an
  existing `python3.dll` from another vendor — the bundled one wins.
