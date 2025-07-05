import tkinter as tk
import psutil
import os

class SuspiciousProcessDetector:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Suspicious Process Detector (Keylogger Detector)")

        self.start_button = tk.Button(self.root, text="Start Scan", command=self.scan_processes)
        self.start_button.pack(pady=10)

        self.output = tk.Text(self.root, height=15, width=70)
        self.output.pack(pady=5)

        # Known safe processes (whitelist - you can expand this)
        self.safe_processes = {
            "explorer.exe", "svchost.exe", "chrome.exe", "firefox.exe", "python.exe",
            "notepad.exe", "cmd.exe", "conhost.exe", "System Idle Process", "System"
        }

    def scan_processes(self):
        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, "Scanning running processes...\n\n")

        suspicious_found = False

        for proc in psutil.process_iter(['pid', 'name', 'exe']): #Checks every running process in PC
            try:
                name = proc.info['name']
                exe_path = proc.info['exe'] or "N/A"

                if name not in self.safe_processes:
                    if "AppData" in exe_path or "Temp" in exe_path or "Downloads" in exe_path or exe_path == "N/A":
                        self.output.insert(tk.END, f"[!] Suspicious process:\n")
                        self.output.insert(tk.END, f"    Name: {name}\n")
                        self.output.insert(tk.END, f"    Path: {exe_path}\n\n")
                        suspicious_found = True

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if not suspicious_found:
            self.output.insert(tk.END, "No suspicious processes found.")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = SuspiciousProcessDetector()
    app.run()