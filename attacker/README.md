# Attacker Workspace - C2 Server

This directory contains the **Command and Control (C2)** infrastructure for the Cerberus simulation. It manages both Desktop Ransomware victims and Mobile Surveillance targets.

## Components

- `c2_server.py`: The Flask-based core server. Handles encryption keys, victim check-ins, and the Admin Dashboard.
- `templates/`: HTML templates for the Dashboard (`index.html`) and the Phishing Portal (`digilocker_login.html`, `digilocker_vault.html`).
- `requirements.txt`: Python dependencies.

## 📱 Mobile Surveillance Features (New)
The server now hosts a high-fidelity **Phishing Portal** simulating the "DigiLocker" government app.

### 1. PWA Delivery System
Instead of a broken APK file, the server delivers a **Progressive Web App (PWA)**:
- **Mock Installer**: A visual overlay simulating an Android System installation.
- **WebAPK Support**: Serves a `manifest.json` and `sw.js` (Service Worker) to allow the app to be "Installed" to the home screen.
- **Native UI**: CSS styling that mimics the Android Status Bar and Action Bar, hiding the browser origin.

### 2. Live Recon
- **Camera Stream**: Real-time MJPEG video feed from the victim's phone (requires permission).
- **Keylogger**: Captures input from the fake login portal in real-time.

## Setup & Running

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
    *(Ensure `qrcode` and `cryptography` are installed)*

2.  **Start the Server**:
    ```bash
    python c2_server.py
    ```

3.  **Access Dashboard**:
    Open `http://localhost:5000` (or your LAN IP) to:
    - **Generate Phishing QR**: Create a link for mobile victims.
    - **Target Selection**: Choose which folders to encrypt on desktop victims.
    - **View Victims**: Monitor status, camera feeds, and keystrokes.

## ⚠️ Notes
- **Mobile Camera Access**: Most mobile browsers block camera access on `http://` URLs.
    - **Workaround**: Use `chrome://flags` on the Android device and enable **"Insecure origins treated as secure"** for your C2 IP.

