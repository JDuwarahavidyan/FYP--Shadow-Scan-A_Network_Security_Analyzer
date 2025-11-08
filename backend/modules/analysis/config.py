import os

# === General Project Paths ===
BASE_DIR = os.path.abspath(os.getcwd())
DOWNLOAD_DIR = os.path.join(BASE_DIR, "downloads")


# === Analysis Settings ===
ALLOWED_EXTENSIONS = [".cap", ".pcap"]
