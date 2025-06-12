# VM Detect

![Screenshot](https://i.imgur.com/n91q2wq.png)

VM Detect is a Python script designed to detect if a Windows system is running in a virtual machine (VM) and to determine if the system has been recently installed or reset. The script uses various forensic techniques to gather information about the system's installation date and checks for artifacts that might indicate a fresh or scrubbed environment.

## Features

- **VM Detection**: Identifies if the system is running in a VM by checking MAC addresses and graphics adapters.
- **Installation Date Detection**: Uses multiple methods to determine the system's installation date, including registry entries, log files, and WMI queries.
- **Artifact Checking**: Checks for suspiciously clean system artifacts that might indicate a fresh or scrubbed environment.

## Output

The script outputs the following information:

- Forensic install timestamp report.
- Oldest detected timestamp.
- System age in days.
- VM detection results.
- System artifact check results.
- Final verdict on system age and freshness.

## Caveats 

- This script is designed for Windows 11 and relies on PCA logs which is not available in all versions of Windows.
- This script is not fool-proof do not rely on it
