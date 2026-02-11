# Victim Workspace - Desktop Payload

This directory contains the **Desktop Ransomware** payload simulation. It is designed to demonstrate persistent system lockdown and file encryption.

## Components

- `builder.py`: The **Stealth Dropper Generator**. Run this first! It patches `ransomware.py` with your C2 configuration and mimics a legitimate installer (e.g., NVIDIA Driver).
- `ransomware.py`: The core payload. Handles encryption (AES-256), system locking (Kiosk Mode), and communication.
- `watchdog.py`: A persistence process that monitors `ransomware.py` and restarts it if the user tries to kill it.

## 🚀 Deployment Guide

### 1. Build the Payload
1.  Ensure the C2 Server is running (to get the Public Key).
2.  Run the builder:
    ```bash
    python builder.py
    ```
3.  Enter your **C2 Server IP** when prompted.
4.  The script will generate a new file: `installer.py`.

### 2. Infection (Simulation)
transfer `installer.py` to the target Windows/Linux machine and execute it.
- **Fake UI**: It will show a fake "Driver Installation" progress bar.
- **Silent Drop**: In the background, it installs the ransomware and watchdog to `%APPDATA%` (Windows) or `~/.config` (Linux).
- **Persistence**: It adds Registry Run keys or Autostart entries to survive reboots.

### 3. The Attack
- **Recon**: The malware scans the home directory and sends the file list to the C2.
- **Wait**: It waits silently until the Attacker selects targets on the Dashboard.
- **Lockdown**: Once triggered, it encrypts files, shreds the originals, and locks the screen with a "Ransom Note" UI.

## 🛡️ Decryption
Do **NOT** delete the malware files manually!
1.  Go to the C2 Dashboard.
2.  Click **"RELEASE KEY"** for this victim.
3.  The malware will automatically receive the key, decrypt all files, remove persistence hooks, and self-destruct.

## Features
- **Anti-Forensics**: Securely overwrites files before deletion.
- **Voice Threats**: text-to-Speech engine announces execution status.
- **Input Blocking**: Disables Task Manager, Alt+F4, and Windows Keys during lockdown.
