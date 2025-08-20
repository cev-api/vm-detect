# VMDetect by CevAPI

import os, sys, struct, base64, subprocess, shutil, json, csv  
from datetime import datetime  
import ctypes
from ctypes import wintypes
import re  

if os.name != "nt":
    print("Windows Only - Obviously"); sys.exit(1)

KEYWORDS = [b"vmware", b"777777", b"virtual machine", b"virtual"]
ACPI_TARGETS = [b"APIC", b"BOOT", b"FACP", b"FACS", b"HPET", b"MCFG", b"SRAT", b"WAET", b"XSDT"]
ACPI_HDR_SIZE = 36

def dword_le(tag4: bytes) -> int:  # little-endian int from 4 ASCII bytes
    return struct.unpack("<I", tag4)[0]
def dword_be(tag4: bytes) -> int:  # big-endian int from 4 ASCII bytes
    return struct.unpack(">I", tag4)[0]
def ascii_fixed(bs: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in bs)

# ---- WinAPI ----
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
EnumSystemFirmwareTables = kernel32.EnumSystemFirmwareTables
EnumSystemFirmwareTables.argtypes = [wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]
EnumSystemFirmwareTables.restype  = wintypes.UINT
GetSystemFirmwareTable = kernel32.GetSystemFirmwareTable
GetSystemFirmwareTable.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD]
GetSystemFirmwareTable.restype  = wintypes.UINT
GetLastError = kernel32.GetLastError
GetLastError.restype = wintypes.DWORD
GetLogicalDrives = kernel32.GetLogicalDrives
GetLogicalDrives.restype = wintypes.DWORD  # ### ADDED ### ensure prototype for Win7

# Try both encodings that Windows code commonly uses
PROVIDERS = {
    "ACPI_be": dword_be(b"ACPI"),  # 0x41435049 
    "ACPI_le": dword_le(b"ACPI"),  # 0x49504341
    "RSMB_be": dword_be(b"RSMB"),  # 0x52534D42
    "RSMB_le": dword_le(b"RSMB"),  # 0x424D5352
}

def enum_acpi_ids(provider):
    size = EnumSystemFirmwareTables(provider, None, 0)
    if size == 0:
        raise OSError(GetLastError())
    count = size // 4
    arr = (ctypes.c_uint32 * count)()
    got = EnumSystemFirmwareTables(provider, ctypes.byref(arr), size)
    if got != size:
        raise OSError(GetLastError() or 0)
    return list(arr)

def get_table(provider, table_id):
    need = GetSystemFirmwareTable(provider, table_id, None, 0)
    if need == 0:
        return b""
    buf = (ctypes.c_ubyte * need)()
    got = GetSystemFirmwareTable(provider, table_id, ctypes.byref(buf), need)
    return bytes(buf[:got])

# ---- PowerShell helpers (for SMBIOS fallbacks) ----
def ps_base64(cmd: str) -> bytes:
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return b""
    try:
        out = subprocess.check_output(
            [exe, "-NoProfile", "-NonInteractive", "-Command", cmd],
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore"
        ).strip()
        return base64.b64decode(out) if out else b""
    except Exception:
        return b""

def smbios_via_cim() -> bytes:
    # Correct namespace: root\WMI
    cmd = (
        "$x=Get-CimInstance -Namespace root\\WMI -ClassName MSSmBios_RawSMBiosTables "
        "-ErrorAction SilentlyContinue; if($x -and $x.SMBiosData){[Convert]::ToBase64String($x.SMBiosData)}"
    )
    return ps_base64(cmd)

def smbios_via_wmi() -> bytes:
    cmd = (
        "$x=Get-WmiObject -Namespace root\\WMI -Class MSSmBios_RawSMBiosTables "
        "-ErrorAction SilentlyContinue; if($x -and $x.SMBiosData){[Convert]::ToBase64String($x.SMBiosData)}"
    )
    return ps_base64(cmd)

# ---- Scan helpers ----
def find_all(hay: bytes, needle: bytes):
    out=[]; i=0; n=len(needle)
    while n and (j:=hay.find(needle,i))!=-1:
        out.append(j); i=j+n
    return out

def scan_blob(blob: bytes):
    hits=[]
    if not blob: return hits
    low=blob.lower()
    for kw in KEYWORDS:
        for off in find_all(low, kw):
            s=max(0,off-32); e=min(len(blob), off+len(kw)+32)
            hits.append({"keyword": kw.decode(), "offset": off,
                         "context": ascii_fixed(blob[s:e])})
    return hits

def parse_acpi_header(tbl: bytes):
    if len(tbl) < ACPI_HDR_SIZE: return None
    length = struct.unpack_from("<I", tbl, 4)[0]
    oemid  = ascii_fixed(tbl[10:16]).rstrip("\x00").rstrip()
    oemtid = ascii_fixed(tbl[16:24]).rstrip("\x00").rstrip()
    chk_ok = (sum(tbl[:min(length,len(tbl))]) & 0xFF) == 0
    return oemid, oemtid, length, chk_ok, f"0x{tbl[9]:02X}"

# ==============================#
#          ASCII Banner    
# ==============================#
def print_banner(): 
    banner = r"""


 █████   █████ ██████   ██████ ██████████             █████                       █████   
░░███   ░░███ ░░██████ ██████ ░░███░░░░███           ░░███                       ░░███    
 ░███    ░███  ░███░█████░███  ░███   ░░███  ██████  ███████    ██████   ██████  ███████  
 ░███    ░███  ░███░░███ ░███  ░███    ░███ ███░░███░░░███░    ███░░███ ███░░███░░░███░   
 ░░███   ███   ░███ ░░░  ░███  ░███    ░███░███████   ░███    ░███████ ░███ ░░░   ░███    
  ░░░█████░    ░███      ░███  ░███    ███ ░███░░░    ░███ ███░███░░░  ░███  ███  ░███ ███
    ░░███      █████     █████ ██████████  ░░██████   ░░█████ ░░██████ ░░██████   ░░█████ 
     ░░░      ░░░░░     ░░░░░ ░░░░░░░░░░    ░░░░░░     ░░░░░   ░░░░░░   ░░░░░░     ░░░░░  


"""
    print(banner)

# ==============================#
#         Console Colors  
# ==============================#
class _ConsoleColor:  # Win7-safe colored output (no reliance on ANSI VT)
    def __init__(self):
        self._k32 = kernel32
        self._h = self._k32.GetStdHandle(wintypes.DWORD(-11))  # STD_OUTPUT_HANDLE
        class COORD(ctypes.Structure):
            _fields_=[("X", wintypes.SHORT), ("Y", wintypes.SHORT)]
        class SMALL_RECT(ctypes.Structure):
            _fields_=[("Left", wintypes.SHORT), ("Top", wintypes.SHORT),
                      ("Right", wintypes.SHORT), ("Bottom", wintypes.SHORT)]
        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_=[("dwSize", COORD), ("dwCursorPosition", COORD),
                      ("wAttributes", wintypes.WORD),
                      ("srWindow", SMALL_RECT), ("dwMaximumWindowSize", COORD)]
        self._CSBI = CONSOLE_SCREEN_BUFFER_INFO
        self._default = 7  # fallback
        try:
            csbi = self._CSBI()
            if self._k32.GetConsoleScreenBufferInfo(self._h, ctypes.byref(csbi)):
                self._default = csbi.wAttributes
        except Exception:
            pass
        self.RED = 0x0C      # FOREGROUND_RED | FOREGROUND_INTENSITY
        self.YELLOW = 0x0E   # RED | GREEN | INTENSITY (approx. orange/yellow)
        self.GREEN = 0x0A    # GREEN | INTENSITY

    def red(self, text: str):
        try:
            self._k32.SetConsoleTextAttribute(self._h, self.RED)
            print(text)
        finally:
            self._k32.SetConsoleTextAttribute(self._h, self._default)

    def yellow(self, text: str):
        try:
            self._k32.SetConsoleTextAttribute(self._h, self.YELLOW)
            print(text)
        finally:
            self._k32.SetConsoleTextAttribute(self._h, self._default)

    def green(self, text: str):
        try:
            self._k32.SetConsoleTextAttribute(self._h, self.GREEN)
            print(text)
        finally:
            self._k32.SetConsoleTextAttribute(self._h, self._default)

CC = _ConsoleColor()  

# =======================================#
#        Driver/Service Scanning   
# =======================================#
def _run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                       text=True, encoding="utf-8", errors="ignore")
    except Exception:
        return ""

def _wmic(text_cmd):
    exe = shutil.which("wmic")
    if not exe: return ""
    return _run([exe] + text_cmd)

def list_system_drivers_wmic():
    #Return a list of dicts with keys: Name, DisplayName, PathName, State, StartMode, Caption
    #Using /format:list (robust on Win7).
    
    out = _wmic(["sysdriver", "get",
                 "Name,DisplayName,PathName,State,StartMode,Caption",
                 "/format:list"])
    drivers = []
    if not out:
        return drivers
    cur = {}
    for line in out.splitlines():
        line=line.strip()
        if not line:
            if cur:
                drivers.append(cur); cur={}
            continue
        if "=" in line:
            k,v=line.split("=",1)
            cur[k.strip()] = v.strip()
    if cur: drivers.append(cur)
    return drivers

def list_drivers_driverquery():
    #Fallback: parse DRIVERQUERY /V /FO CSV.
    exe = shutil.which("driverquery")
    if not exe: return []
    out = _run([exe, "/v", "/fo", "csv"])
    if not out: return []
    rows = []
    rdr = csv.DictReader(out.splitlines())
    # Normalize key names across OS versions
    def getf(d, names):
        for n in names:
            if n in d: return d[n]
        return ""
    for r in rdr:
        rows.append({
            "Name": getf(r, ["Module Name","Name"]),
            "DisplayName": getf(r, ["Display Name","Description"]),
            "PathName": getf(r, ["Path","Image Path"]),
            "State": getf(r, ["State","Status"]),
            "StartMode": "",
            "Caption": getf(r, ["Description","Display Name"])
        })
    return rows

def list_driver_services_sc():
    #Fallback: enumerate driver services via SC and fetch qc for each.
    #Returns list of dicts with Name, DisplayName, PathName, State.
    
    exe = shutil.which("sc")
    if not exe: return []
    out = _run([exe, "query", "type=", "driver", "state=", "all"])
    names = []
    for line in out.splitlines():
        line=line.strip()
        if line.upper().startswith("SERVICE_NAME:"):
            names.append(line.split(":",1)[1].strip())
    results = []
    for n in names:
        qc = _run([exe, "qc", n])
        q = _run([exe, "query", n])
        disp = ""; path = ""; state = ""
        for line in qc.splitlines():
            L=line.strip()
            if L.upper().startswith("DISPLAY_NAME"):
                disp = L.split(":",1)[1].strip()
            elif L.upper().startswith("BINARY_PATH_NAME"):
                path = L.split(":",1)[1].strip()
        for line in q.splitlines():
            L=line.strip()
            if L.upper().startswith("STATE"):
                parts = L.split()
                state = parts[-1] if parts else ""
        results.append({"Name": n, "DisplayName": disp, "PathName": path, "State": state,
                        "StartMode": "", "Caption": disp})
    return results

def registry_service_info(name: str):
   #Fetch Type, ImagePath, DisplayName for a service from CurrentControlSet.
    info = {}
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\{}".format(name))
        i = 0
        while True:
            try:
                n,v,t = winreg.EnumValue(key, i); i+=1
                info[n]=v
            except OSError:
                break
        winreg.CloseKey(key)
    except Exception:
        pass
    return info

def registry_search_all_services_for_vmloader():
    #Search services registry for 'vmloader' by key name or ImagePath/DisplayName.
    hits = []
    try:
        import winreg
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        idx = 0
        while True:
            try:
                sub = winreg.EnumKey(root, idx); idx += 1
            except OSError:
                break
            try:
                k = winreg.OpenKey(root, sub)
            except OSError:
                continue
            vals = {}
            i = 0
            while True:
                try:
                    n,v,t = winreg.EnumValue(k, i); i+=1
                    vals[n] = v
                except OSError:
                    break
            winreg.CloseKey(k)
            name_l = sub.lower()
            disp_l = str(vals.get("DisplayName","")).lower()
            img_l  = str(vals.get("ImagePath","")).lower()
            if "vmloader" in name_l or "vmloader" in disp_l or "vmloader" in img_l:
                hits.append({
                    "Name": sub,
                    "DisplayName": vals.get("DisplayName",""),
                    "PathName": vals.get("ImagePath",""),
                    "Type": vals.get("Type","")
                })
        winreg.CloseKey(root)
    except Exception:
        pass
    return hits

def normalize_path(p: str) -> str:
    if not p: return ""
    p = p.strip().strip('"').strip("'")
    if " " in p and not p.startswith(r"\\??\\") and not p.startswith(r"\??\\"):
        p = p.split(" ")[0]
    return p

# helper to strip NT prefix for matching
def _strip_nt_prefix(p: str) -> str:
    if not p: return ""
    if p.startswith(r"\\??\\"):
        return p[4:]
    if p.startswith(r"\??\\"):
        return p[4:]

    return p

def suspicious_path_reason(p: str) -> str:
    if not p: return ""
    pl = normalize_path(p)
    pl = _strip_nt_prefix(pl)
    # match drive-root + single filename (no additional backslashes)
    # and ensure it's a .sys (case-insensitive)
    if re.match(r"^[A-Za-z]:\\[^\\/:*?\"<>|]+$", pl):
        if pl.lower().endswith(".sys"):
            return "driver file located directly in drive root"
    return ""

# enumerate all logical drive roots and check for \vmloader.sys
def all_drive_roots():
    drives = []
    mask = GetLogicalDrives()
    for i in range(26):
        if mask & (1 << i):
            drives.append(f"{chr(ord('A')+i)}:\\")
    return drives

def find_vmloader_files():
    hits = []
    for root in all_drive_roots():
        p = os.path.join(root, "vmloader.sys")
        try:
            if os.path.exists(p):
                sz = os.path.getsize(p)
                hits.append(f"{p} ({sz} bytes)")
        except Exception:
            hits.append(f"{p} (exists, size unknown)")
        # common driver folder just in case
        p2 = os.path.join(root, r"Windows\System32\drivers\vmloader.sys")
        try:
            if os.path.exists(p2):
                sz = os.path.getsize(p2)
                hits.append(f"{p2} ({sz} bytes)")
        except Exception:
            hits.append(f"{p2} (exists, size unknown)")
    return sorted(set(hits))


# ================================#
#          Soft Detections 
# ================================#
def _silent_getctime(path):
    try:
        return datetime.fromtimestamp(os.path.getctime(path))
    except Exception:
        return None

def _get_user_folder_timestamp():
    return _silent_getctime(os.environ.get("USERPROFILE", ""))

def _get_ntuser_dat_timestamp():
    return _silent_getctime(os.path.join(os.environ.get("USERPROFILE", ""), "NTUSER.DAT"))

def _get_setup_log_timestamp():
    for path in [r"C:\\Windows\\Panther\\setupact.log", r"C:\\Windows\\setupact.log"]:
        ts = _silent_getctime(path)
        if ts:
            return ts
    return None

def _get_os_install_date_wmi():
    try:
        out = subprocess.check_output(["wmic", "os", "get", "installdate"], stderr=subprocess.DEVNULL)
        lines = out.decode(errors="ignore").splitlines()
        for line in lines:
            line = line.strip()
            if line.isdigit():
                try:
                    return datetime.strptime(line, "%Y%m%d%H%M%S.%f")
                except Exception:
                    pass
    except Exception:
        return None

def _get_systeminfo_install_date():
    try:
        out = subprocess.check_output(["systeminfo"], stderr=subprocess.DEVNULL, shell=True)
        decoded = out.decode(errors="ignore")
        for line in decoded.splitlines():
            if "Original Install Date" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    date_str = parts[1].strip()
                    for fmt in ("%m/%d/%Y, %I:%M:%S %p", "%d/%m/%Y, %I:%M:%S %p", "%d/%m/%Y, %H:%M:%S", "%m/%d/%Y, %H:%M:%S"):
                        try:
                            return datetime.strptime(date_str, fmt)
                        except Exception:
                            continue
    except Exception:
        return None

def _get_registry_install_date():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "InstallDate")
        winreg.CloseKey(key)
        return datetime.fromtimestamp(value)
    except Exception:
        return None

def _get_pca_logs_info():
    #Windows 11 Only AFAIK
    timestamps = []
    entry_counts = []
    suspicious_logs = []
    base_path = r"C:\\Windows\\AppCompat\\PCA"
    files = ["PcaGeneralDb0.txt", "PcaAppLaunchDic.txt"]

    for fname in files:
        fpath = os.path.join(base_path, fname)
        try:
            if os.path.exists(fpath):
                ts = _silent_getctime(fpath)
                timestamps.append((fname, ts))
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        count = sum(1 for _ in f)
                except Exception:
                    count = 0
                entry_counts.append((fname, count))
                if count and count < 10:
                    suspicious_logs.append(fname)
        except Exception:
            continue

    earliest = None
    for _, ts in timestamps:
        if ts and (earliest is None or ts < earliest):
            earliest = ts
    is_pca_suspicious = bool(suspicious_logs)
    return earliest, timestamps, entry_counts, suspicious_logs, is_pca_suspicious

def _collect_installation_evidence():
    #Return tuple: (timestamps_list, oldest_tuple_or_None, pca_info_tuple)"""
    timestamps = []
    for label, getter in [
        ("User Folder", _get_user_folder_timestamp),
        ("NTUSER.DAT", _get_ntuser_dat_timestamp),
        ("Setup Log", _get_setup_log_timestamp),
        ("Systeminfo Install Date", _get_systeminfo_install_date),
        ("WMI OS Install Date", _get_os_install_date_wmi),
        ("Registry InstallDate", _get_registry_install_date),
    ]:
        try:
            ts = getter()
            if ts:
                timestamps.append((label, ts))
        except Exception:
            pass

    pca_info = _get_pca_logs_info()
    if pca_info[0]:
        timestamps.append(("PCA Logs", pca_info[0]))

    oldest = None
    if timestamps:
        oldest = min(timestamps, key=lambda x: x[1])
    return timestamps, oldest, pca_info

def _check_system_artifacts():
    suspicious = []
    paths = [
        os.environ.get("TEMP", ""),
        r"C:\\Windows\\Temp",
        os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\\Windows\\Recent"),
        r"C:\\Windows\\Prefetch",
    ]
    for path in paths:
        try:
            if path and os.path.exists(path):
                files = os.listdir(path)
                if len(files) < 5:
                    suspicious.append(path)
        except Exception:
            continue
    return suspicious

# ================================#
#    Boring VMware Indicators
# ================================#
def _get_mac_addresses():
    macs = []
    try:
        for line in os.popen("getmac"):
            if "-" in line or ":" in line:
                mac = line.strip().split()[0]
                if len(mac) >= 12:
                    macs.append(mac)
    except Exception:
        pass
    return macs

def _vmware_oui_matches(macs):
    vm_ouis = {"00:05:69", "00:0C:29", "00:1C:14", "00:50:56"}
    matches = []
    for mac in macs:
        m = mac.strip().upper().replace("-", ":")
        if len(m) >= 8 and m[:8] in vm_ouis:
            matches.append(mac.strip())
    return matches

def _check_dxgi_adapter_vmware():
    try:
        import comtypes  # noqa: F401
        from comtypes.client import CreateObject
        dxgi = CreateObject("DXGI.Factory")
        adapter = dxgi.EnumAdapters(0)
        desc = adapter.GetDesc()
        try:
            name = desc.Description if hasattr(desc, "Description") else str(desc)
        except Exception:
            name = str(desc)
        return ("vmware" in (name or "").lower(), name)
    except Exception:
        return (False, None)

def main():
    print_banner()

    #print("Keywords:", ", ".join(k.decode() for k in KEYWORDS)); print()

    #SMBIOS: API (both encodings) -> CIM -> WMI
    smbios = b""
    src = None
    for tag in ("RSMB_be","RSMB_le"):
        blob = get_table(PROVIDERS[tag], 0)
        if blob:
            smbios, src = blob, f"API({tag})"; break
    if not smbios:
        smbios = smbios_via_cim()
        src = "PowerShell CIM (root\\WMI)" if smbios else None
    if not smbios:
        smbios = smbios_via_wmi()
        src = "PowerShell WMI (root\\WMI)" if smbios else None

    # detection bucket moved earlier so SMBIOS/ACPI can append
    detections = []  # global collection across sections

    if smbios:
        hits = scan_blob(smbios)
        print(f"[SMBIOS] Source: {src}; Size: {len(smbios)} bytes")
        if hits:
            # summarize and red-highlight hit lines
            total = len(hits)
            summary={}
            for h in hits: summary[h["keyword"]] = summary.get(h["keyword"],0)+1
            CC.red(f"[SMBIOS] Matches: {total}")
            for k,v in summary.items():
                CC.red(f"  - '{k}': {v} occurrence(s)")
            show=min(20,total)
            CC.red(f"[SMBIOS] First {show} hits:")
            for i in range(show):
                h=hits[i]
                CC.red(f"  @0x{h['offset']:X} '{h['keyword']}'  ctx=\"{h['context']}\"")
            if total>show:
                CC.red(f"  ... ({total-show} more)")

            # Put SMBIOS keywords into DETECTIONS
            det_frag = ", ".join([f"{k}:{v}" for k,v in summary.items()])
            detections.append(f"SMBIOS keywords found ({total} hits): {det_frag}")
        else:
            print("[SMBIOS] No matches.")
    else:
        print("[SMBIOS] Unavailable from API/CIM/WMI; falling back to BIOS registry strings.")
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS")
            blobs=[]
            i=0
            while True:
                try:
                    name,val,typ=winreg.EnumValue(key,i); i+=1
                    if isinstance(val,str): blobs.append(val.encode("utf-8","ignore"))
                except OSError: break
            winreg.CloseKey(key)
            blob=b"\x00".join(blobs)
            hits = scan_blob(blob)
            print(f"[SMBIOS] Registry strings: Size={len(blob)} bytes")
            if hits:
                total = len(hits)
                summary={}
                for h in hits: summary[h["keyword"]] = summary.get(h["keyword"],0)+1
                CC.red(f"[SMBIOS] Matches in registry snapshot: {total}")
                for k,v in summary.items():
                    CC.red(f"  '{k}' -> {v} occurrence(s)")
                for h in hits[:10]:
                    CC.red(f"  ctx=\"{h['context']}\"")
                detections.append("SMBIOS registry snapshot contains keywords: " +
                                  ", ".join([f"{k}:{v}" for k,v in summary.items()]))
            else:
                print("[SMBIOS] No matches in registry strings.")
        except Exception:
            print("[SMBIOS] Registry access failed.")

    print()

    # ACPI: try enum with both provider encodings; then direct fetch with both encodings
    acpi_tables = {}
    enum_ok = False
    for ptag in ("ACPI_be","ACPI_le"):
        try:
            ids = enum_acpi_ids(PROVIDERS[ptag])
            enum_ok = True
            wanted = {dword_le(t): t.decode() for t in ACPI_TARGETS}
            wanted.update({dword_be(t): t.decode() for t in ACPI_TARGETS})
            for dw in ids:
                name = wanted.get(dw)
                if not name: continue
                tbl = get_table(PROVIDERS[ptag], dw)
                if not tbl:
                    tbl = get_table(PROVIDERS[ptag], dword_le(name.encode()))
                if tbl: acpi_tables[name] = tbl
            if acpi_tables:
                print(f"[ACPI] Retrieved via enumeration using {ptag}.")
                break
        except OSError:
            continue

    if not acpi_tables:
        for name_b in ACPI_TARGETS:
            name = name_b.decode()
            got = False
            for ptag in ("ACPI_be","ACPI_le"):
                for enc_id in (dword_le(name_b), dword_be(name_b)):
                    tbl = get_table(PROVIDERS[ptag], enc_id)
                    if tbl:
                        acpi_tables[name] = tbl
                        got = True
                        break
                if got: break
        if acpi_tables:
            print("[ACPI] Retrieved by direct signature probe.")
        else:
            print("[ACPI] No ACPI tables retrieved (provider likely blocked).")

    if acpi_tables:
        print("[ACPI] OEMID scan for target tables:")
        for name_b in ACPI_TARGETS:
            name = name_b.decode()
            if name not in acpi_tables:
                print(f"  {name:4s}: not present")
                continue
            hdr = acpi_tables[name]
            if len(hdr) < ACPI_HDR_SIZE:
                print(f"  {name:4s}: present, header too small"); continue
            oemid, oemtid, length, chk_ok, chk_byte = parse_acpi_header(hdr)
            # keyword hits (OEMID only, as requested throughout)
            matches = [kw.decode() for kw in KEYWORDS if kw.decode() in (oemid.lower())]
            mtxt = "none" if not matches else ", ".join(matches)
            line = (f"  {name:4s}: OEMID='{oemid}' OEMTableID='{oemtid}' "
                    f"matches=[{mtxt}] len={length} checksum_ok={chk_ok} ({chk_byte})")
            # red-highlight tables with matches (detections)
            if matches:
                CC.red(line)
                for kw in matches:
                    detections.append(f"ACPI {name} OEMID contains '{kw}'")
            else:
                print(line)

            if name == "WAET":
                detections.append("WAET table present (Windows ACPI Emulated Devices; common in VMs)")
    else:
        print("[ACPI] Skipped detailed scan.")

    # Driver/service detections
    print("\n[DRIVERS] Enumerating system drivers (WMIC/SC/DRIVERQUERY/Registry)...")
    drv_list = list_system_drivers_wmic()
    if not drv_list:
        drv_list = list_driver_services_sc()
    else:
        drv_list += list_driver_services_sc()
    drv_list += list_drivers_driverquery()
    dedup = {}
    for d in drv_list:
        key = (d.get("Name",""), d.get("PathName",""))
        dedup[key] = d
    drv_list = list(dedup.values())

    vmloader_hits = []
    suspicious_hits = []
    for d in drv_list:
        name = d.get("Name","")
        disp = d.get("DisplayName","")
        path = normalize_path(d.get("PathName",""))
        cap  = d.get("Caption","")
        state = d.get("State","")
        joined = " ".join([name, disp, cap, path]).lower()
        if "vmloader" in joined:
            vmloader_hits.append({"Name":name, "DisplayName":disp, "Caption":cap,
                                  "PathName":path, "State":state})
        rsn = suspicious_path_reason(path)
        if rsn:
            suspicious_hits.append({"Name":name, "PathName":path, "Reason":rsn})

    svc_reg = registry_service_info("vmloader")
    if svc_reg:
        img = normalize_path(str(svc_reg.get("ImagePath","")))
        typ = svc_reg.get("Type", None)
        detections.append("Service key present: HKLM\\SYSTEM\\CurrentControlSet\\Services\\vmloader")
        if img:
            detections.append(f"vmloader ImagePath: {img}")
        if isinstance(typ, int):
            if typ in (1, 2):
                detections.append(f"vmloader Type=0x{typ:X} (driver)")
            else:
                detections.append(f"vmloader Type=0x{typ:X}")

    reg_hits = registry_search_all_services_for_vmloader()
    for h in reg_hits:
        detections.append(f"Service registry match: Name='{h['Name']}' "
                          f"DisplayName='{h['DisplayName']}' ImagePath='{h['PathName']}' Type='{h['Type']}'")

    file_hits = find_vmloader_files()
    for fh in file_hits:
        detections.append(f"File present: {fh}")

    for h in vmloader_hits:
        detections.append(f"Loaded/registered driver reference: Name='{h['Name']}' "
                          f"DisplayName='{h['DisplayName']}' State='{h['State']}' "
                          f"Path='{h['PathName']}'")
    for h in suspicious_hits:
        detections.append(f"Suspicious driver path ({h['Reason']}): "
                          f"{h['Name'] or '(no name)'} -> {h['PathName']}")

    # DISPLAY CLASS key check
    print("\n[DISPLAY CLASS] Checking registry for VMware/Virtual strings and 'Standard VGA Graphics Adapter'...")
    try:
        import winreg
        cls_path = r"SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cls_path)
        vals = {}
        i = 0
        while True:
            try:
                n,v,t = winreg.EnumValue(key, i); i+=1
                vals[n] = v
            except OSError:
                break
        winreg.CloseKey(key)
        summary = []
        for n,v in vals.items():
            if isinstance(v, str):
                low = v.lower()
                for kw in [b"vmware", b"virtual machine", b"virtual", b"777777"]:
                    if kw.decode() in low:
                        summary.append(f"{n}='{v}' contains '{kw.decode()}'")
                if "standard vga graphics adapter" in low:
                    summary.append(f"{n}='{v}' equals/contains 'Standard VGA Graphics Adapter'")
        if summary:
            for s in summary:
                detections.append(f"Display class key hit: {s}")
        else:
            print("  No keyword hits in display class key.")
    except Exception:
        print("  Display class key not present or inaccessible.")

    # Final detection summary (RED)
    if detections:
        CC.red("\n[DETECTIONS]")
        for dmsg in detections:
            CC.red(f"  - {dmsg}")
    else:
        print("\n[DETECTIONS] None triggered (no SMBIOS/ACPI keyword hits; no WAET table; no vmloader or root-drive driver files; no display-class hits).")

    # SOFT INDICATORS 
    print("\n[SOFT] Forensic Install Timestamps")
    ts_list, oldest, pca_info = _collect_installation_evidence()
    now = datetime.now()
    if ts_list:
        for label, ts in ts_list:
            try:
                age_days = (now - ts).days
                print(f"  - {label:25}: {ts} ({age_days} days ago)")
            except Exception:
                print(f"  - {label:25}: {ts}")
        if oldest:
            print(f"  Oldest Detected: {oldest[0]} -> {oldest[1]}")
            try:
                older_than_30 = (now - oldest[1]).days > 30
                if older_than_30:
                    CC.green("  System OLDER than 30 days")
                else:
                    CC.yellow("  System NOT older than 30 days")
            except Exception:
                pass
    else:
        print("  No timestamp evidence available")

    pca_earliest, pca_timestamps, entry_counts, suspicious_logs, is_pca_suspicious = pca_info
    if pca_timestamps:
        print("\n[SOFT] PCA Logs Summary (not present on all Windows versions)")
        for fname, ts in pca_timestamps:
            try:
                age_days = (now - ts).days if ts else None
            except Exception:
                age_days = None
            line = f"  - {fname} Created: {ts} ({age_days if age_days is not None else '?'} days ago)"
            if age_days is not None and age_days < 30:
                CC.yellow(line)
            else:
                print(line)
        for fname, count in entry_counts:
            if count and count < 10:
                CC.yellow(f"  - {fname} Entry Count: {count}")
            else:
                print(f"  - {fname} Entry Count: {count}")
        for fname in suspicious_logs:
            CC.yellow(f"  - [!] {fname} has suspiciously few entries")
        if is_pca_suspicious:
            CC.yellow("  [!] PCA logs suggest suspiciously low usage — system may be fresh or scrubbed")

    # ENV FRESHNESS
    print("\n[SOFT] System Artifact Cleanliness")
    artifacts = _check_system_artifacts()
    if artifacts:
        CC.yellow("  Suspiciously clean locations:")
        for p in artifacts:
            CC.yellow(f"    {p}")
    else:
        print("  Typical artifact volume present")

    # VMWARE-SPECIFIC
    print("\n[VMWARE] Vendor-specific Indicators")
    macs = _get_mac_addresses()
    mac_hits = _vmware_oui_matches(macs)
    if mac_hits:
        for m in mac_hits:
            CC.red(f"  VMware OUI MAC detected: {m}")
    else:
        print("  No VMware MAC OUIs detected")
    dxgi_hit, dxgi_name = _check_dxgi_adapter_vmware()
    if dxgi_hit:
        CC.red(f"  DXGI Adapter indicates VMware: {dxgi_name}")
    else:
        print("  DXGI Adapter does not indicate VMware or unavailable")

if __name__ == "__main__":
    main()
