# Cerberus Ransomware Simulation 🐕🔥

[![Education Only](https://img.shields.io/badge/Purpose-Educational-red.svg?style=flat-square)](#-disclaimer)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

> **⚠️ DISCLAIMER: FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.**
> **DO NOT USE ON UNAUTHORIZED SYSTEMS.**
> This project is a sophisticated malware simulation designed for academic research in System Security. It demonstrates advanced concepts including **Hybrid Cryptography**, **C2 Infrastructure**, **Anti-Forensics**, and **Human-Operated Targeting**. The author takes no responsibility for misuse.

---

## 📖 Overview

**Cerberus** is a sophisticated, end-to-end ransomware simulation framework. It demonstrates the lifecycle of a modern cyber-attack, from the initial delivery via a "Trojaned" installer or **Mobile Phishing PWA** to persistent system lockdown and remote command-and-control (C2) management.

### Key Capabilities
- **Cross-Platform Payload**: Works on Windows (Registry Persistence) and Linux (`~/.config` Persistence).
- **Mobile Surveillance**: Featuring a **Progressive Web App (PWA)** that simulates a malicious Android app installation to bypass security checks.
- **Advanced Crypto**: Uses **AES-256-GCM** for file encryption and **RSA-2048** for secure key exchange.
- **Live Recon**: Real-time camera streaming, keylogging, and file system browsing from the C2 Dashboard.

---

## 🏗️ Technical Architecture

### 1. The Infection Lifecycle
![Attack Lifecycle Flowchart](https://i.ibb.co/3ykJ8bX/flowchart.jpg)

### 2. Core Components

#### 🕵️ C2 Server (`attacker/c2_server.py`)
The "brain" of the operation.
- **Hybrid Key Management**: Generates **RSA-2048** keys to securely wrap and exfiltrate the victim's unique AES keys.
- **Human-Operated Targeting (Recon Mode)**: Victims **beacon** their home directory structure to the C2. The attacker manually selects target directories via the [Target Selection UI](/target_selection).
- **Live Monitoring**: 
    - **Camera Stream**: Real-time MJPEG stream from infected mobile devices.
    - **Keylogger**: WebSocket-based real-time capture of desktop and mobile keystrokes.
    - **Doomsday Timer**: Server-enforced countdown that deletes the private key upon expiry.
- **PWA Delivery System**: Hosts a malicious **Web Manifest** and **Service Worker** to trick Android devices into installing the payload as a native-feeling app (bypassing APK parsing errors).

#### 📱 Mobile Payload (DigiLocker Phishing)
- **Native UI Simulation**: The phishing portal mimics the Android System UI (Action Bars, Status Bars) to mask the browser environment.
- **Mock Installer**: A realistic "Package Installer" overlay that simulates an APK installation process within the browser.
- **PWA "WebAPK"**: If installed, it launches in **Standalone Mode** (fullscreen, no URL bar) with a real app icon.

#### 📦 Stealth Dropper (`victim/builder.py`)
- **Dynamic Configuration**: Patches the payload with your C2 IP, RSA Key, and Target Folder.
- **Social Engineering**: Mimics a **NVIDIA GeForce Driver Update** installation while silently deploying the malware.

#### 🐕 Watchdog Persistence (`victim/watchdog.py`)
- **Resilience**: A separate process that instantly respawns the ransomware if terminated.
- **OS Hooks**: Installs into `~/.config/autostart` (Linux) or `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (Windows).

#### 💀 Advanced Payload (`victim/ransomware.py`)
- **Cryptography**: **AES-256-GCM** encryption for all files matching target extensions.
- **Anti-Forensics**: **Secure File Shredding** (overwriting data) before deletion to prevent recovery.
- **System Lockdown**: Disables Task Manager, Alt+F4, and keeps the window always-on-top.
- **Psychological Warfare**: Voice Synthesis (TTS) announcements and "Ragebait" UI messages.

---

## 🚀 Setup & Usage

### Step 1: Start the C2 (Attacker)
Go to the `attacker/` directory, install dependencies, and run the server.
```bash
cd attacker
pip install -r requirements.txt
python c2_server.py
```
*Note: Copy the **Public Key** printed in the console.*

### Step 2: Build the Dropper (Victim)
Run `builder.py`. It will ask for the C2 IP and automatically inject the Public Key into a new `installer.py`.
```bash
cd victim
python builder.py
```

### Step 3: Deployment
- **Desktop**: Execute `installer.py` on the target machine.
- **Mobile**: Generate a Phishing QR Code from the Dashboard and scan it with the victim's phone.

### Step 4: Management
Access the dashboard at `http://[C2_IP]:5000` to:
- Select target folders for encryption.
- View live camera feeds and keylogs.
- Manage "Doomsday" timers and release decryption keys.

---

## 🛡️ Defensive & Safety Measures

- **Safeguards**: The malware is configured to **ONLY** encrypt files in the `test_data` folder by default (configurable).
- **Decryption**: The "Release Key" button on the dashboard triggers an immediate, automatic decryption and cleanup on the victim machine.
- **Logs**: Detailed execution logs are stored in `%APPDATA%\Cerberus\cerberus_log.txt`.

---

