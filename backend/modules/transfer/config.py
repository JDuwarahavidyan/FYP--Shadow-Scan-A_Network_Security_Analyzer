# modules/config.py
# ============================================================
# 🔧 Raspberry Pi SSH + File Path Configuration
# ============================================================

PI_HOST = "192.168.1.27"     # ✅ your Raspberry Pi IP
PI_USER = "kali"             # ✅ your Pi username
PI_PASS = "kali"             # ✅ your Pi password
SSH_PORT = 22

# === Remote directories on Raspberry Pi ===
REMOTE_CAPTURE_DIR = "/home/kali/IoT-Privacy/Capture"
CAPTURE_ARCHIVE_DIR = "/home/kali/IoT-Privacy/Archive"

# === Local directory on Windows backend ===
LOCAL_DOWNLOAD_DIR = "downloads"  # backend/downloads/
