# test_download.py
from modules.transfer.transfer_manager import download_file_from_pi

if __name__ == "__main__":
    try:
        print("🔍 Testing capture download from Raspberry Pi...")
        local_file = download_file_from_pi()
        print(f"✅ SUCCESS: File downloaded → {local_file}")
    except Exception as e:
        print(f"❌ ERROR: {e}")
