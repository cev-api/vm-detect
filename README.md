# VMDetect

![WithHardenedVMLoader](https://i.imgur.com/1sMPRcR.png)
![WithoutHardenedVMLoader](https://i.imgur.com/YzRTABn.png)

VMDetect is a Windows-focused Python utility that detects virtual machine indicators and assesses whether a system appears freshly installed or recently scrubbed. It performs low-level, read-only firmware table inspection (ACPI/RSMB) via the Windows firmware API, which is the exact surface many anti-VM bypass projects attempt to patch or hide.

### Features

- **Detect obfuscated VM environments**: Accurately detects [`VmwareHardenedLoader`](https://github.com/hzqst/VmwareHardenedLoader) and similar anti‑anti‑VM techniques.
- **ACPI/SMBIOS firmware scanning (core)**:
  - Enumerates and reads ALL ACPI tables and SMBIOS via `EnumSystemFirmwareTables`/`GetSystemFirmwareTable` (both ACPI and RSMB providers).
  - Scans OEMID and full table blobs using an expanded keyword list.
  - Sequence detection is limited to ACPI OEMID to reduce noise; WAET presence is flagged.
  - Robust fallbacks (ACPI direct probes; SMBIOS via CIM/WMI or BIOS registry snapshot) if enumeration is blocked.
- **HPET heuristic scoring**: Decodes the ACPI HPET table and scores “VM-likeness” using strict heuristics. Missing HPET is flagged as suspicious. 
- **Display Adapter “Chip type” scanner (Win7-friendly)**: Reads `HKLM\SYSTEM\CurrentControlSet\Control\Video` to extract chip/adapter strings without relying on WMIC/PowerShell. Flags keyword or sequence hits (prints details only on hit).
- **Registry/driver corroboration**: BIOS strings fallback; driver/services enumeration and path sanity checks.
- **Vendor-specific indicators**:
  - PCI Vendor ID scanning via WMIC, PowerShell, and Registry fallbacks.
  - Network OUIs for various VM vendors and DXGI adapter name checks.
- **Soft detections (forensic)**:
  - Multi-source installation date evidence (Registry, WMI/WMIC, `systeminfo`, setup logs, profile timestamps).
  - PCA logs summary when available (Windows 10/11; not present on all systems) with suspiciously low-entry highlighting.
  - System artifact cleanliness (Temp, Prefetch, Recent) to flag unusually clean environments.
 
### Why?

Some software blocks virtual machines to hinder reverse‑engineering, malware analysis, and abuse. Tools like [`VmwareHardenedLoader`](https://github.com/hzqst/VmwareHardenedLoader) try to hide the VM by patching fingerprints so those apps will run anyway. VMDetect exists to expose both the VM and those concealment attempts, and if all else fails will give you a forensic view of the system showing how much it has been used - a soft indicator of a freshly installed VM.

### Comparison to VMAware

I honestly had NO idea about this project until I finished my own, but to compare...

![VMAware](https://github.com/kernelwernel/VMAware) is a large, cross-platform C++ library with around a hundred detection techniques, support for Windows, Linux, and macOS, and coverage of over 70 virtualization brands and hypervisors. It’s designed as a broad, flexible framework for VM detection — useful for anti-cheat, research, and security projects that need maximum breadth and configurability across different operating systems and architectures.

VMDetect, by contrast, is Windows-focused, written in Python and is purpose-built. Rather than aiming for maximum coverage, it drills deep into firmware table inspection (ACPI/SMBIOS via GetSystemFirmwareTable) — the exact layer many anti-VM hardeners try to patch. VMDetect is uniquely effective at exposing obfuscated VMware environments (e.g. detecting [`VmwareHardenedLoader`](https://github.com/hzqst/VmwareHardenedLoader)) and complements this with forensic context: install date triangulation, PCA log summaries, and “system cleanliness” checks that highlight suspiciously fresh or scrubbed environments. It is suitable for porting into apps that use Python or can simply be used on its own.

### Windows version support

- Designed to run on Windows 7, 10, and 11.
- Some detections are version-dependent:
  - PCA logs often exist on Windows 10/11 and may be absent on Windows 7.
  - WMIC availability varies (deprecated on newer builds); fallbacks are implemented where possible.

### Requirements

- Python 3 on Windows
- Optional (for DXGI adapter check): `comtypes`

Install optional dependency:

```bash
pip install comtypes
```

### Building (PyInstaller)

- Supported build toolchain for broad compatibility (including legacy targets):
  - PyInstaller v4.x
  - Python 3.8

Example build command:

```bash
pyinstaller --onefile vmdetect.py
```

- Match the target architecture (build 32-bit on a 32-bit Python if you need x86).
- To bundle additional runtime DLLs, copy them alongside `vmdetect.py` and add with `--add-binary`, or place them next to the built executable.

### Windows XP compatibility notes

This tool can be compiled with PyInstaller v4 using Python 3.8 and run on Windows XP provided the following prerequisites are met. Alternatively, you can bundle the listed runtime DLLs with your PyInstaller build.

- Required OS updates (so the VC++ redist installs and the UCRT loads):
  - ![KB2533623](https://web.archive.org/web/20200803205235id_/https://download.microsoft.com/download/F/1/0/F106E158-89A1-41E3-A9B5-32FEB2A99A0B/Windows6.1-KB2533623-x64.msu)
  - ![KB4490628](https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2019/03/windows6.1-kb4490628-x64_d3de52d6987f7c8bdc2c015dca69eac96047c76e.msu) (Servicing Stack)
  - ![KB4474419](https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2019/09/windows6.1-kb4474419-v3-x64_b5614c6cea5cb4e198717789633dca16308ef79c.msu) (SHA-2 support)
  - ![KB2999226](https://download.microsoft.com/download/1/1/5/11565a9a-ea09-4f0a-a57e-520d5d138140/Windows6.1-KB2999226-x64.msu) (Universal CRT)

- Then install: Microsoft Visual C++ 2015–2022 Redistributable matching your build (x64 or x86).

- Or bundle these with PyInstaller (either via `--add-binary` or by placing them next to the executable):
  - `ucrtbase.dll`
  - `vcruntime140.dll`
  - `vcruntime140_1.dll`
  - `msvcp140.dll` (and if present on your build box: `msvcp140_1.dll`, `msvcp140_2.dll`)
  - The `api-ms-win-crt-*.dll` files (UCRT “api-ms-win-crt” stubs)

### Caveats

- Not fool-proof; use results as part of a broader assessment.
- Some signals (PCA logs, Prefetch) may be disabled by policy or unavailable depending on OS/configuration.
- Administrative rights are not strictly required, but access to certain artifacts may be limited without elevation.
