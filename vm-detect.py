# VMDetect by CevAPI

import os, sys, struct, base64, subprocess, shutil, json, csv  
from datetime import datetime  
import ctypes
from ctypes import wintypes
import re  

if os.name != "nt":
    print("Windows Only - Obviously"); sys.exit(1)

KEYWORDS = [
    b"vmware",
    b"virtual machine",
    b"virtual",
    b"pheonix",
    b"phoenix",
    b"phoenix technologies",
    b"vbox",
    b"bochs",
    b"vtrual",
    b"prls",
    b"vm",
    b"v m ware",
]
BOUNDARY_KEYWORDS = {b"vm"}
ACPI_TARGETS = [b"APIC", b"BOOT", b"FACP", b"FACS", b"HPET", b"MCFG", b"SRAT", b"WAET", b"XSDT"]
ACPI_HDR_SIZE = 36

def dword_le(tag4: bytes) -> int:  # little-endian int from 4 ASCII bytes
    return struct.unpack("<I", tag4)[0]
def dword_be(tag4: bytes) -> int:  # big-endian int from 4 ASCII bytes
    return struct.unpack(">I", tag4)[0]
def ascii_fixed(bs: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in bs)

def dword_to_acpi_tag(value: int) -> str:
    #Best-effort decode of a firmware table ID DWORD to a 4-char tag. Tries little-endian first, then big-endian; falls back to hex.
    bs_le = struct.pack("<I", value)
    bs_be = struct.pack(">I", value)
    def is_printable(bs: bytes) -> bool:
        return all(32 <= b < 127 for b in bs)
    if is_printable(bs_le):
        return bs_le.decode()
    if is_printable(bs_be):
        return bs_be.decode()
    return f"{value:08X}"

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

def ps_text(cmd: str) -> str:
    exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if not exe:
        return ""
    try:
        out = subprocess.check_output(
            [exe, "-NoProfile", "-NonInteractive", "-Command", cmd],
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore"
        )
        return out or ""
    except Exception:
        return ""

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

def scan_blob(blob: bytes, include_sequences: bool = True, boundary_keywords=None):
    hits=[]
    if not blob: return hits
    low=blob.lower()
    if boundary_keywords is None:
        boundary_keywords = set()
    # 1) Fixed keyword hits
    for kw in KEYWORDS:
        if kw in boundary_keywords:
            try:
                pat = re.compile(rb'(?<![A-Za-z0-9])' + re.escape(kw) + rb'(?![A-Za-z0-9])')
                for m in pat.finditer(low):
                    off = m.start()
                    s=max(0,off-32); e=min(len(blob), off+len(kw)+32)
                    hits.append({"keyword": kw.decode(), "offset": off,
                                 "context": ascii_fixed(blob[s:e])})
            except Exception:
                pass
        else:
            for off in find_all(low, kw):
                s=max(0,off-32); e=min(len(blob), off+len(kw)+32)
                hits.append({"keyword": kw.decode(), "offset": off,
                             "context": ascii_fixed(blob[s:e])})
    if include_sequences:
        # 2) Sequential pattern hits
        #    - Repeated alnum chars length >= 4 (AAAA, 7777, ZZZZZZ)
        #    - Ascending alnum sequences length >= 4 (ABCD, 0123)
        try:
            rep_re = re.compile(rb'([A-Za-z0-9])\1{3,}')
            for m in rep_re.finditer(blob):
                off = m.start()
                s=max(0,off-32); e=min(len(blob), off+len(m.group(0))+32)
                hits.append({
                    "keyword": f"seq:{ascii_fixed(m.group(0))}",
                    "offset": off,
                    "context": ascii_fixed(blob[s:e])
                })
            # Ascending runs
            b = blob
            n = len(b)
            i = 0
            while i < n-3:
                c = b[i]
                if (48 <= c <= 57) or (65 <= c <= 90) or (97 <= c <= 122):
                    j = i
                    while j+1 < n:
                        a = b[j]
                        d = b[j+1]
                        # same category and strictly ascending by 1
                        if ((48 <= a <= 57 and 48 <= d <= 57) or
                            (65 <= a <= 90 and 65 <= d <= 90) or
                            (97 <= a <= 122 and 97 <= d <= 122)) and d == a + 1:
                            j += 1
                        else:
                            break
                    if j - i + 1 >= 4:
                        off = i
                        seq = b[i:j+1]
                        s=max(0,off-32); e=min(n, off+len(seq)+32)
                        hits.append({
                            "keyword": f"seq:{ascii_fixed(seq)}",
                            "offset": off,
                            "context": ascii_fixed(b[s:e])
                        })
                        i = j + 1
                        continue
                i += 1
        except Exception:
            pass
    return hits

def detect_sequences_in_ascii(text: str):
    #Return list of seq:XXXX patterns found in ASCII string (length>=4).
    results = []
    if not text:
        return results
    try:
        # repeated alnum
        for m in re.finditer(r'([A-Za-z0-9])\1{3,}', text):
            results.append(f"seq:{m.group(0)}")
        # ascending runs
        n = len(text)
        i = 0
        while i < n-3:
            ch = text[i]
            if ch.isdigit() or ch.isalpha():
                j = i
                while j+1 < n and text[j].isalnum() and text[j+1].isalnum():
                    a = ord(text[j])
                    d = ord(text[j+1])
                    if (
                        (text[j].isdigit() and text[j+1].isdigit()) or
                        (text[j].isupper() and text[j+1].isupper()) or
                        (text[j].islower() and text[j+1].islower())
                    ) and d == a + 1:
                        j += 1
                    else:
                        break
                if j - i + 1 >= 4:
                    results.append(f"seq:{text[i:j+1]}")
                    i = j + 1
                    continue
            i += 1
    except Exception:
        pass
    # dedupe while preserving order
    seen = set()
    uniq = []
    for r in results:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    return uniq

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
                                                          github.com/cev-api/vm-detect             

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
    #Return tuple: (timestamps_list, oldest_tuple_or_None, pca_info_tuple)
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
    vm_ouis = {"00:05:69", "00:0C:29", "00:1C:14", "00:50:56", "00:15:5D", "08:00:27", "00:1C:42", "00:16:3E", "52:54:00"}
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
        hits = scan_blob(smbios, boundary_keywords=BOUNDARY_KEYWORDS)
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
            hits = scan_blob(blob, boundary_keywords=BOUNDARY_KEYWORDS)
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

    # ACPI: enumerate and scan ALL tables (merge both provider encodings). Fallback probes if needed.
    acpi_tables = {}  # tag -> list of table blobs
    enumerated_any = False
    for ptag in ("ACPI_be", "ACPI_le"):
        try:
            ids = enum_acpi_ids(PROVIDERS[ptag])
            enumerated_any = True
            for dw in ids:
                tag = dword_to_acpi_tag(dw)
                tbl = get_table(PROVIDERS[ptag], dw)
                if not tbl and len(tag) == 4:
                    # try both endian interpretations if direct fetch returned empty
                    for enc_id in (dword_le(tag.encode()), dword_be(tag.encode())):
                        tbl = get_table(PROVIDERS[ptag], enc_id)
                        if tbl:
                            break
                if tbl:
                    acpi_tables.setdefault(tag, []).append(tbl)
        except OSError:
            continue

    if not acpi_tables:
        # Fallback: probe a set of common ACPI signatures directly
        for name_b in ACPI_TARGETS:
            name = name_b.decode()
            got_tbl = b""
            for ptag in ("ACPI_be", "ACPI_le"):
                for enc_id in (dword_le(name_b), dword_be(name_b)):
                    tbl = get_table(PROVIDERS[ptag], enc_id)
                    if tbl:
                        got_tbl = tbl
                        break
                if got_tbl:
                    break
            if got_tbl:
                acpi_tables.setdefault(name, []).append(got_tbl)
        if acpi_tables:
            print("[ACPI] Retrieved by direct signature probe (fallback).")
        else:
            print("[ACPI] No ACPI tables retrieved (provider likely blocked).")

    if acpi_tables:
        total_blobs = sum(len(v) for v in acpi_tables.values())
        src_note = "via enumeration" if enumerated_any else "via fallback probes"
        print(f"[ACPI] OEMID scan for all tables ({len(acpi_tables)} types, {total_blobs} blobs) {src_note}:")
        waet_reported = False
        for name in sorted(acpi_tables.keys()):
            blobs = acpi_tables[name]
            for idx, hdr in enumerate(blobs, 1):
                disp_name = f"{name}#{idx}" if len(blobs) > 1 else name
                if len(hdr) < ACPI_HDR_SIZE:
                    print(f"  {disp_name:6s}: present, header too small")
                    continue
                oemid, oemtid, length, chk_ok, chk_byte = parse_acpi_header(hdr)
                # keyword hits on OEMID (plus sequence-only detection limited to OEMID)
                matches = [kw.decode() for kw in KEYWORDS if kw.decode() in (oemid.lower())]
                seq_hits = detect_sequences_in_ascii(oemid)
                all_hits = matches + seq_hits
                mtxt = "none" if not all_hits else ", ".join(all_hits)
                line = (f"  {disp_name:6s}: OEMID='{oemid}' OEMTableID='{oemtid}' "
                        f"matches=[{mtxt}] len={length} checksum_ok={chk_ok} ({chk_byte})")
                if matches:
                    CC.red(line)
                    for kw in matches:
                        detections.append(f"ACPI {disp_name} OEMID contains '{kw}'")
                else:
                    print(line)

                # Full-table blob scan for keywords ONLY (no sequences)
                tbl_hits = scan_blob(hdr, include_sequences=False, boundary_keywords=BOUNDARY_KEYWORDS)
                if tbl_hits:
                    for h in tbl_hits[:10]:
                        CC.red(f"    [ACPI/{disp_name}] @0x{h['offset']:X} '{h['keyword']}'  ctx=\"{h['context']}\"")
                    detections.append(
                        f"ACPI {disp_name} blob matches: " + ", ".join(sorted({h['keyword'] for h in tbl_hits}))
                    )

                if name == "WAET" and not waet_reported:
                    detections.append("WAET table present (Windows ACPI Emulated Devices; common in VMs)")
                    waet_reported = True
    else:
        print("[ACPI] Skipped detailed scan.")

    # ================================#
    #              HPET
    # ================================#
    def _hpet_fetch_raw():
        # Try both provider encodings and both endian interpretations of 'HPET'
        name_b = b"HPET"
        for ptag in ("ACPI_be", "ACPI_le"):
            for enc_id in (dword_le(name_b), dword_be(name_b)):
                try:
                    data = get_table(PROVIDERS[ptag], enc_id)
                    if data:
                        return data
                except Exception:
                    continue
        return b""

    def _hpet_checksum_ok(b: bytes) -> bool:
        return (sum(b) & 0xFF) == 0

    def _hpet_decode(b: bytes):
        if len(b) < 56:
            raise ValueError("HPET too short ({} bytes)".format(len(b)))
        sig = b[0:4].decode("ascii", errors="replace")
        length = struct.unpack_from("<I", b, 4)[0]
        revision = b[8]
        chksum = b[9]
        oem_id = b[10:16].decode("ascii", errors="ignore").strip()
        oem_table_id = b[16:24].decode("ascii", errors="ignore").strip()
        oem_rev = struct.unpack_from("<I", b, 24)[0]
        creator_id = b[28:32].decode("ascii", errors="ignore").strip()
        creator_rev = struct.unpack_from("<I", b, 32)[0]

        hwid = struct.unpack_from("<I", b, 36)[0]
        gas_space = b[40]
        gas_bit_width = b[41]
        gas_bit_offset = b[42]
        gas_access_size = b[43]
        address = struct.unpack_from("<Q", b, 44)[0]
        sequence_number = b[52]
        minimum_clock_ticks = struct.unpack_from("<H", b, 53)[0]
        flags = b[55]

        vendor_id = (hwid >> 16) & 0xFFFF
        revision_id = hwid & 0xFF
        cmp_raw = (hwid >> 8) & 0x1F
        counter_is_64 = ((hwid >> 13) & 0x1) == 1
        legacy_irq = ((hwid >> 15) & 0x1) == 1

        vendor_name = {
            0x8086: "Intel (8086)",
            0x1022: "AMD (1022)",
        }.get(vendor_id, "0x{0:04X}".format(vendor_id))

        return {
            "Header": {
                "Signature": sig,
                "Length": length,
                "Revision": revision,
                "Checksum": chksum,
                "ChecksumOK": _hpet_checksum_ok(b),
                "OEMID": oem_id,
                "OEMTableID": oem_table_id,
                "OEMRevision": "0x{0:08X}".format(oem_rev),
                "CreatorID": creator_id,
                "CreatorRevision": "0x{0:08X}".format(creator_rev),
            },
            "HPET": {
                "HardwareBlockID": "0x{0:08X}".format(hwid),
                "HardwareBlockIDRaw": hwid,
                "VendorIDName": vendor_name,
                "VendorIDRaw": vendor_id,
                "RevisionID": revision_id,
                "ComparatorFieldRaw": cmp_raw,
                "CounterIs64Bit": counter_is_64,
                "LegacyReplacementCapable": legacy_irq,
                "GAS_SpaceID": gas_space,
                "GAS_RegBitWidth": gas_bit_width,
                "GAS_RegBitOffset": gas_bit_offset,
                "GAS_AccessSize": gas_access_size,
                "Address": address,
                "SequenceNumber": sequence_number,
                "MinimumClockTicks": minimum_clock_ticks,
                "FlagsNum": flags,
            },
            "RawBytes": b,
        }

    def _hpet_classify(info):
        t = info["HPET"]
        score = 0
        reasons = []
        if t["GAS_RegBitWidth"] != 0x40:
            score += 2
            reasons.append("Register Bit Width={} (expected 64 on many bare-metal systems)".format(t["GAS_RegBitWidth"]))
        if t["FlagsNum"] != 0x00:
            score += 2
            reasons.append("Flags=0x{0:02X} (page-protect set; unusual on bare metal)".format(t["FlagsNum"]))
        if t["ComparatorFieldRaw"] == 15:
            score += 1
            reasons.append("ComparatorFieldRaw=15 (observed in VMware example)")
        if t["VendorIDRaw"] not in (0x8086, 0x1022):
            score += 1
            reasons.append("VendorID=0x{0:04X} atypical for modern x86 CPUs".format(t["VendorIDRaw"]))
        if score >= 4:
            label = "Likely VM"
        elif score >= 2:
            label = "Unclear"
        else:
            label = "Likely bare metal"
        return score, label, reasons

    # Run HPET analysis
    print("\n[HPET] Scoring-based heuristic")
    _hpet_data = _hpet_fetch_raw()
    if not _hpet_data:
        CC.yellow("  HPET table not present — suspicious on many systems")
        detections.append("HPET ACPI table missing (suspicious)")
    else:
        try:
            _hpet_info = _hpet_decode(_hpet_data)
            # Preserve detailed information similar to the standalone script
            h = _hpet_info["Header"]; t = _hpet_info["HPET"]
            print(f"  Signature              : {h['Signature']}")
            print(f"  Length                 : {h['Length']}")
            print(f"  Revision               : {h['Revision']}")
            print(f"  Checksum               : {h['Checksum']}  (OK={h['ChecksumOK']})")
            print(f"  OEMID / TableID        : {h['OEMID']} / {h['OEMTableID']}")
            print(f"  OEMRevision            : {h['OEMRevision']}")
            print(f"  CreatorID / Revision   : {h['CreatorID']} / {h['CreatorRevision']}")
            print()
            print(f"  HardwareBlockID        : {t['HardwareBlockID']}")
            print(f"  VendorID               : {t['VendorIDName']} (raw=0x{t['VendorIDRaw']:04X})")
            print(f"  RevisionID             : {t['RevisionID']}")
            print(f"  ComparatorFieldRaw     : {t['ComparatorFieldRaw']}")
            print(f"  CounterIs64Bit         : {t['CounterIs64Bit']}")
            print(f"  LegacyReplacementCapable: {t['LegacyReplacementCapable']}")
            print(f"  GAS Space/Width/Offset : 0x{t['GAS_SpaceID']:02X} / {t['GAS_RegBitWidth']} / {t['GAS_RegBitOffset']}")
            print(f"  GAS AccessSize         : 0x{t['GAS_AccessSize']:02X}")
            print(f"  Address                : 0x{t['Address']:016X}")
            print(f"  SequenceNumber         : {t['SequenceNumber']}")
            print(f"  MinimumClockTicks      : 0x{t['MinimumClockTicks']:04X}")
            print(f"  Flags                  : 0x{t['FlagsNum']:02X}")
            score, label, reasons = _hpet_classify(_hpet_info)
            if label == "Likely VM":
                CC.red(f"\n  VM-Likelihood: {label} (score={score})")
            elif label == "Unclear":
                CC.yellow(f"\n  VM-Likelihood: {label} (score={score})")
            else:
                CC.green(f"\n  VM-Likelihood: {label} (score={score})")
            for r in reasons:
                print(f"    - {r}")
            # Only add to detections if not clearly bare metal
            if label != "Likely bare metal":
                detections.append(f"HPET heuristic: {label} (score={score})")
        except Exception:
            print("  HPET present but parse failed")

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

    # DISPLAY ADAPTER CHIP TYPE (Win7+ friendly via registry)
    print("\n[DISPLAY ADAPTER] Chip type and Adapter string from registry")
    def _decode_wide_bin(val):
        try:
            if isinstance(val, (bytes, bytearray)):
                s = bytes(val)
                # Attempt UTF-16LE; many systems store REG_BINARY wide strings here
                try:
                    return s.decode("utf-16le", errors="ignore").strip("\x00").strip()
                except Exception:
                    return s.decode("latin-1", errors="ignore").strip("\x00").strip()
            if isinstance(val, str):
                return val
        except Exception:
            pass
        return None

    def _keyword_hits_in_text(text: str):
        if not text:
            return []
        hits = []
        low = text.lower()
        try:
            for kw in KEYWORDS:
                k = kw.decode()
                if kw in BOUNDARY_KEYWORDS:
                    try:
                        pat = re.compile(r"(?<![A-Za-z0-9])" + re.escape(k) + r"(?![A-Za-z0-9])")
                        if pat.search(low):
                            hits.append(k)
                    except Exception:
                        pass
                else:
                    if k in low:
                        hits.append(k)
        except Exception:
            pass
        # dedupe preserve order
        seen = set(); out = []
        for h in hits:
            if h not in seen:
                seen.add(h); out.append(h)
        return out

    try:
        import winreg
        base = r"SYSTEM\CurrentControlSet\Control\Video"
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
        idx = 0
        any_found = False
        while True:
            try:
                guid = winreg.EnumKey(root, idx); idx += 1
            except OSError:
                break
            try:
                guid_key = winreg.OpenKey(root, guid)
            except OSError:
                continue
            # subkeys like 0000, 0001 ...
            sidx = 0
            while True:
                try:
                    sub = winreg.EnumKey(guid_key, sidx); sidx += 1
                except OSError:
                    break
                try:
                    k = winreg.OpenKey(guid_key, sub)
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
                name = vals.get("DriverDesc") or vals.get("Device Description") or "<unknown>"
                chip = _decode_wide_bin(vals.get("HardwareInformation.ChipType")) or "<not set>"
                adapter = _decode_wide_bin(vals.get("HardwareInformation.AdapterString")) or "<not set>"
                if name or chip or adapter:
                    any_found = True
                    # Detection: keywords and sequences in chip type (and adapter as secondary)
                    chip_kw = _keyword_hits_in_text(chip)
                    chip_seq = detect_sequences_in_ascii(chip)
                    adapter_kw = _keyword_hits_in_text(adapter)

                    if chip_kw or adapter_kw:
                        print(name)
                        print(f"  Chip type: {chip}")
                        print(f"  Adapter string: {adapter}")
                        print(f"  Key: {guid}\\{sub}\n")
                        CC.red("  [!] Keyword hit in display adapter metadata")
                        if chip_kw:
                            detections.append("Display adapter chip-type keywords: " + ", ".join(chip_kw))
                        if adapter_kw:
                            detections.append("Display adapter adapter-string keywords: " + ", ".join(adapter_kw))
                    elif chip_seq:
                        print(name)
                        print(f"  Chip type: {chip}")
                        print(f"  Adapter string: {adapter}")
                        print(f"  Key: {guid}\\{sub}\n")
                        CC.yellow("  [!] Sequence pattern(s) in chip type: " + ", ".join(chip_seq))
                        detections.append("Display adapter chip-type sequences: " + ", ".join(chip_seq))
            winreg.CloseKey(guid_key)
        winreg.CloseKey(root)
        if not any_found:
            print("  No display adapter registry entries found under Control\\Video.")
    except Exception:
        print("  Display adapter registry scan failed or inaccessible.")

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

    # VENDOR-SPECIFIC INDICATORS
    print("\n[SOFT] Vendor-specific Indicators - PCI ID's & OUIs")
    # 1) PCI Vendor IDs via WMIC/PowerShell/Registry fallbacks
    vendor_hits = []
    vendor_map = {
        "15ad": "VMware",
        "1414": "Microsoft Hyper-V",
        "80ee": "VirtualBox",
        "1af4": "QEMU/virtio",
        "1b36": "Red Hat (QEMU)",
        "5853": "Xen/XenSource",
        "1ab8": "Parallels",
        "1234": "Bochs/QEMU std VGA",
    }

    # WMIC path (legacy but present on many Win7/10)
    try:
        exe = shutil.which("wmic")
        if exe:
            out = _run([exe, "path", "Win32_PnPEntity", "get", "PNPDeviceID,Name", "/format:csv"])
            for line in out.splitlines():
                L = line.strip()
                if not L or "," not in L:
                    continue
                # CSV: Node,Name,PNPDeviceID (order can vary; use contains)
                parts = [p.strip() for p in L.split(",")]
                if len(parts) < 3:
                    continue
                name = parts[-2]
                pnp  = parts[-1]
                if "PCI\\VEN_" in pnp.upper():
                    m = re.search(r"VEN_([0-9A-Fa-f]{4})", pnp)
                    if m:
                        ven = m.group(1).lower()
                        if ven in vendor_map:
                            vendor_hits.append((vendor_map[ven], ven, name))
    except Exception:
        pass

    # PowerShell fallback (no admin needed)
    if not vendor_hits:
        ps = (
            "Get-PnpDevice -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.InstanceId + '|' + $_.FriendlyName }"
        )
        txt = ps_text(ps)
        if txt:
            for line in txt.splitlines():
                if "|" not in line:
                    continue
                inst, name = line.split("|", 1)
                up = inst.upper()
                if "PCI\\VEN_" in up:
                    m = re.search(r"VEN_([0-9A-Fa-f]{4})", up)
                    if m:
                        ven = m.group(1).lower()
                        if ven in vendor_map:
                            vendor_hits.append((vendor_map[ven], ven.lower(), name.strip()))

    # Registry fallback
    if not vendor_hits:
        try:
            import winreg
            base = r"SYSTEM\CurrentControlSet\Enum\PCI"
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(root, i); i += 1
                except OSError:
                    break
                m = re.search(r"VEN_([0-9A-Fa-f]{4})", sub)
                if not m:
                    continue
                ven = m.group(1).lower()
                if ven not in vendor_map:
                    continue
                try:
                    k = winreg.OpenKey(root, sub)
                except OSError:
                    continue
                j = 0
                while True:
                    try:
                        inst = winreg.EnumKey(k, j); j += 1
                    except OSError:
                        break
                    try:
                        kk = winreg.OpenKey(k, inst)
                        name, _ = winreg.QueryValueEx(kk, "FriendlyName")
                    except Exception:
                        name = sub
                    vendor_hits.append((vendor_map[ven], ven, str(name)))
                winreg.CloseKey(k)
            winreg.CloseKey(root)
        except Exception:
            pass

    if vendor_hits:
        for vendor, ven, name in vendor_hits:
            CC.red(f"  PCI Vendor: {vendor} (VEN_{ven.upper()}) -> {name}")
            detections.append(f"PCI vendor indicates {vendor}: VEN_{ven.upper()} ({name})")
    else:
        print("  No VM PCI vendor IDs detected from available sources")

    # 2) VMware-specific MAC OUIs and DXGI check
    macs = _get_mac_addresses()
    mac_hits = _vmware_oui_matches(macs)
    if mac_hits:
        for m in mac_hits:
            CC.red(f"  VM OUI MAC detected: {m}")
    else:
        print("  No VM MAC OUIs detected")
    dxgi_hit, dxgi_name = _check_dxgi_adapter_vmware()
    if dxgi_hit:
        CC.red(f"  DXGI Adapter indicates VMware: {dxgi_name}")
    else:
        print("  DXGI Adapter does not indicate VMware or unavailable")

if __name__ == "__main__":
    main()
