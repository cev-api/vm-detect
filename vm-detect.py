import os
import subprocess
import winreg
import ctypes
from datetime import datetime
from colorama import init, Fore, Back, Style, just_fix_windows_console

# Initialize Colorama
init(autoreset=True, convert=True, strip=False)
just_fix_windows_console()

def set_window_title(title):
    # Encode the title to ANSI
    title_ansi = title.encode('ansi', 'ignore')
    ctypes.windll.kernel32.SetConsoleTitleA(title_ansi)
    
set_window_title('VM Detect')

def print_banner():
    print(
        Fore.MAGENTA
        + r"""
 __   ____  __   ___      _          _   
 \ \ / /  \/  | |   \ ___| |_ ___ __| |_ 
  \ V /| |\/| | | |) / -_)  _/ -_) _|  _|
   \_/ |_|  |_| |___/\___|\__\___\__|\__|

"""
        + Style.RESET_ALL
    )
    
# General File Timestamp Utilities
def silent_getctime(path):
    try:
        return datetime.fromtimestamp(os.path.getctime(path))
    except:
        return None

# Forensic Install Date Detection
def get_user_folder_timestamp():
    return silent_getctime(os.environ.get("USERPROFILE", ""))

def get_ntuser_dat_timestamp():
    return silent_getctime(os.path.join(os.environ.get("USERPROFILE", ""), "NTUSER.DAT"))

def get_logfile_timestamp():
    for path in ["C:\\Windows\\Panther\\setupact.log", "C:\\Windows\\setupact.log"]:
        ts = silent_getctime(path)
        if ts:
            return ts
    return None

def get_os_install_date_wmi():
    try:
        output = subprocess.check_output(['wmic', 'os', 'get', 'installdate'], stderr=subprocess.DEVNULL)
        lines = output.decode(errors="ignore").splitlines()
        for line in lines:
            if line.strip().isdigit():
                raw = line.strip()
                return datetime.strptime(raw, "%Y%m%d%H%M%S.%f")
    except:
        return None

def get_systeminfo_install_date():
    try:
        output = subprocess.check_output(['systeminfo'], stderr=subprocess.DEVNULL, shell=True)
        decoded = output.decode(errors='ignore')
        for line in decoded.splitlines():
            if "Original Install Date" in line:
                _, date_str = line.split(":", 1)
                date_str = date_str.strip()
                for fmt in ("%m/%d/%Y, %I:%M:%S %p", "%d/%m/%Y, %I:%M:%S %p", "%d/%m/%Y, %H:%M:%S", "%m/%d/%Y, %H:%M:%S"):
                    try:
                        return datetime.strptime(date_str, fmt)
                    except:
                        continue
    except:
        return None

def get_registry_install_date():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "InstallDate")
        winreg.CloseKey(key)
        return datetime.fromtimestamp(value)
    except:
        return None

def get_pca_logs_info():
    timestamps = []
    entry_counts = []
    suspicious_logs = []
    base_path = os.path.join("C:\\Windows\\AppCompat\\PCA")
    files = ["PcaGeneralDb0.txt", "PcaAppLaunchDic.txt"]

    for fname in files:
        fpath = os.path.join(base_path, fname)
        try:
            if os.path.exists(fpath):
                ts = silent_getctime(fpath)
                timestamps.append((fname, ts))
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    count = sum(1 for _ in f)
                    entry_counts.append((fname, count))
                    if count < 10:
                        suspicious_logs.append(fname)
        except:
            continue

    earliest = min((ts for _, ts in timestamps), default=None)
    is_pca_suspicious = bool(suspicious_logs)
    return earliest, timestamps, entry_counts, suspicious_logs, is_pca_suspicious

def is_installation_older_than_30_days():
    timestamps = []

    for label, getter in [
        ("User Folder", get_user_folder_timestamp),
        ("NTUSER.DAT", get_ntuser_dat_timestamp),
        ("Setup Log", get_logfile_timestamp),
        ("Systeminfo Install Date", get_systeminfo_install_date),
        ("WMI OS Install Date", get_os_install_date_wmi),
        ("Registry InstallDate", get_registry_install_date),
    ]:
        ts = getter()
        if ts:
            timestamps.append((label, ts))

    pca_earliest, pca_timestamps, entry_counts, suspicious_logs, is_pca_suspicious = get_pca_logs_info()
    if pca_earliest:
        timestamps.append(("PCA Logs", pca_earliest))

    if not timestamps:
        return None

    oldest_label, oldest_time = min(timestamps, key=lambda x: x[1])
    days_old = (datetime.now() - oldest_time).days

    print(Fore.MAGENTA + "[+] Forensic Install Timestamp Report:")
    for label, ts in timestamps:
        print(f"  - {label:25}: {ts} ({(datetime.now() - ts).days} days ago)")

    print(Fore.MAGENTA + "[+] Oldest Detected Timestamp:" + Style.RESET_ALL + f" {oldest_label} -> {oldest_time}")
    print(Fore.MAGENTA + f"[+] System is {'OLDER' if days_old > 30 else 'NOT older'} than 30 days.")

    if pca_timestamps:
        print(Fore.MAGENTA + "[+] PCA Logs Summary:")
        for fname, ts in pca_timestamps:
            print(f"    - {fname} Created: {ts} ({(datetime.now() - ts).days} days ago)")
        for fname, count in entry_counts:
            print(f"    - {fname} Entry Count: {count}")
        for fname in suspicious_logs:
            print(f"    - [!] {fname} has suspiciously few entries (possible reset or new install)")

    if is_pca_suspicious:
        print("[!] PCA logs suggest suspiciously low usage — system may be fresh or scrubbed.")

    return days_old > 30


# VM Detection
def get_mac_addresses():
    macs = []
    try:
        for line in os.popen("getmac"):
            if '-' in line:
                mac = line.strip().split()[0]
                if len(mac) == 17:
                    macs.append(mac)
    except:
        pass
    return macs

def check_vmware_mac(macs):
    vmware_ouis = {"00:05:69", "00:0C:29", "00:1C:14", "00:50:56"}
    for mac in macs:
        prefix = mac.upper()[0:8]
        if prefix in vmware_ouis:
            return True
    return False

def check_dxgi_adapter():
    try:
        import comtypes
        from comtypes.client import CreateObject
        dxgi = CreateObject("DXGI.Factory")
        adapter = dxgi.EnumAdapters(0)
        desc = adapter.GetDesc()
        if "VMware" in desc.Description:
            return True
    except:
        pass
    return False

# Clean Artifact Check (Fresh System)
def check_system_artifacts():
    suspicious = []
    paths = [
        os.environ.get("TEMP", ""),
        "C:\\Windows\\Temp",
        os.path.join(os.environ.get("APPDATA", ""), "Microsoft\\Windows\\Recent"),
        "C:\\Windows\\Prefetch"
    ]
    for path in paths:
        try:
            if os.path.exists(path):
                files = os.listdir(path)
                if len(files) < 5:
                    suspicious.append(path)
        except:
            continue
    return suspicious

# Combined Evaluation
def evaluate_environment():
    vm_detected = False
    is_fresh_environment = False

    macs = get_mac_addresses()
    if check_vmware_mac(macs):
        print(Fore.MAGENTA + "[+] VMware MAC address detected.")
        vm_detected = True

    if check_dxgi_adapter():
        print(Fore.MAGENTA + "[+] VMware graphics adapter detected via DXGI.")
        vm_detected = True

    artifacts = check_system_artifacts()
    if artifacts:
        print(Fore.MAGENTA + "[+] Suspiciously clean system artifacts detected:")
        for path in artifacts:
            print(f"    {path}")
        is_fresh_environment = True

    print(Fore.MAGENTA + "[+] Virtual Machine Detected:" if vm_detected else Fore.MAGENTA + "[+] No VM Indicators Found.")
    print(Fore.MAGENTA + "[+] System Appears Fresh/Clean:" if is_fresh_environment else Fore.MAGENTA + "[+] System Has Historical Use Evidence.")

    return vm_detected, is_fresh_environment

# Entry Point
if __name__ == "__main__":
    print_banner()
    result = is_installation_older_than_30_days()
    print(Fore.MAGENTA + "\nFinal Verdict:" + Style.RESET_ALL + f"{'✔️ Older than 30 days' if result else '❌ Not older than 30 days' if result is False else '❓ Unknown'}")
    evaluate_environment()
    print("\nPress Enter To Quit")
    input()
