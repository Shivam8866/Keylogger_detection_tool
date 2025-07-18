# Keylogger_detection_tool
A lightweight Python GUI application to help identify potentially suspicious or malicious processes running on your system — particularly those that may be indicative of keyloggers or spyware.

## 🛠 Features

- Simple and intuitive **Tkinter-based GUI**
- Scans all currently running processes using **psutil**
- Flags suspicious processes based on:
  - Unknown or uncommon executable names
  - Executables running from potentially suspicious directories (`AppData`, `Temp`, `Downloads`, etc.)
- Outputs a detailed report of suspicious findings
- Whitelisting support for known safe processes

## Requirements

- Python 3.x
- `psutil` library
- `tkinter` (usually pre-installed with Python on most systems)

> If `tkinter` is not available, install it using your system's package manager:
> - For Ubuntu/Debian:
>   ```
>   sudo apt-get install python3-tk
>   ```
> - For Windows: Tkinter comes pre-installed with Python.

Install required Python package:

```
pip install psutil
```
Once launched:

Click "Start Scan"

The tool will list all suspicious processes not found in the whitelist or running from risky directories.

Review the output to investigate further.
```
Sample Output
Scanning running processes...

[!] Suspicious process:
    Name: Code.exe
    Path: C:\Users\YourName\AppData\Local\Programs\Microsoft VS Code\Code.exe

[!] Suspicious process:
    Name: someunknown.exe
    Path: N/A
```
Safe Process Whitelist
The following processes are considered safe by default:

explorer.exe, svchost.exe, chrome.exe, firefox.exe, python.exe, notepad.exe, cmd.exe, conhost.exe, System Idle Process, System

You can customize this whitelist by editing the self.safe_processes set inside the Python script.

Disclaimer
This tool uses simple heuristics and does not guarantee detection of all malicious or keylogging software. It is meant as a basic helper and should not replace dedicated antivirus or anti-malware software.

License
This project is open-source and available for educational and personal use. Modify it freely to suit your needs.
