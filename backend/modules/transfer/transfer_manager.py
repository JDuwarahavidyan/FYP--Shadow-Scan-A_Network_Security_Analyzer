# modules/transfer/transfer_manager.py
import os
import stat
import paramiko
import time
from datetime import datetime
from modules.transfer.config import (
    REMOTE_CAPTURE_DIR,
    CAPTURE_ARCHIVE_DIR,
    LOCAL_DOWNLOAD_DIR,
)

from modules.config import PI_HOST, PI_USER, PI_PASS, SSH_PORT


class TransferError(Exception):
    """Custom error for file transfer operations"""

    pass


def _connect_ssh():
    """Create and return an SSH client connection to Raspberry Pi"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(PI_HOST, port=SSH_PORT, username=PI_USER, password=PI_PASS, timeout=10)
    return ssh


def get_latest_remote_capture(sftp, remote_dir=REMOTE_CAPTURE_DIR, pattern=".cap"):
    """
    Return full remote path of the newest capture file in remote_dir.
    Looks for files like 'capture-*.cap'
    """
    try:
        print(f"[DEBUG] Checking for capture files in: {remote_dir}")
        entries = sftp.listdir_attr(remote_dir)
    except IOError as e:
        raise TransferError(f"Cannot list remote dir {remote_dir}: {e}")

    cap_files = [
        e
        for e in entries
        if stat.S_ISREG(e.st_mode)
        and e.filename.startswith("capture-")
        and e.filename.endswith(pattern)
    ]
    if not cap_files:
        raise TransferError(f"No capture files found in {remote_dir}")

    cap_files.sort(key=lambda e: e.st_mtime, reverse=True)
    newest = cap_files[0]
    remote_path = f"{remote_dir.rstrip('/')}/{newest.filename}"
    print(f"[DEBUG] Latest capture file found: {remote_path}")
    return remote_path


def download_file_from_pi(remote_path=None, local_dir=LOCAL_DOWNLOAD_DIR, timeout=60):
    """
    Downloads the latest capture file from Raspberry Pi → backend (Windows).
    After download:
       Moves it into Archive/<DDMMYYYY>/<HHMM>/ on the Pi.
       Cleans up /Capture/ (removes leftover capture-* files).
    """
    ssh = None
    sftp = None
    try:
        print("[DEBUG] Connecting to Raspberry Pi via SSH...")
        ssh = _connect_ssh()
        sftp = ssh.open_sftp()

        # === Find latest capture file ===
        if not remote_path:
            remote_path = get_latest_remote_capture(sftp)

        # === Validate existence ===
        try:
            sftp.stat(remote_path)
        except IOError as e:
            raise TransferError(f"Remote file not found: {remote_path}. Error: {e}")

        # === Prepare local path (keep same name) ===
        os.makedirs(local_dir, exist_ok=True)
        base_name = os.path.basename(remote_path)
        local_path = os.path.join(local_dir, base_name)

        print(f"[INFO] Downloading {remote_path} → {local_path}")
        sftp.get(remote_path, local_path)

        # === Verify downloaded file ===
        if not os.path.exists(local_path) or os.path.getsize(local_path) == 0:
            raise TransferError("Downloaded file is empty or missing.")

        # === Build dated archive path ===
        now = datetime.now()
        date_folder = now.strftime("%d%m%Y")  # e.g. 07112025
        time_folder = now.strftime("%H%M")  # e.g. 1431
        archive_path = f"{CAPTURE_ARCHIVE_DIR.rstrip('/')}/{date_folder}/{time_folder}"
        remote_archive_path = f"{archive_path}/{base_name}"

        print(f"[DEBUG] Moving remote file to archive: {remote_archive_path}")

        # === Ensure folder structure and move ===
        mkdir_cmd = f"sudo mkdir -p {archive_path}"
        mv_cmd = f"sudo mv -f {remote_path} {remote_archive_path}"
        full_cmd = f"{mkdir_cmd} && {mv_cmd}"

        # --- Retry move if file not found immediately ---
        for attempt in range(3):
            stdin, stdout, stderr = ssh.exec_command(full_cmd)
            exit_code = stdout.channel.recv_exit_status()
            if exit_code == 0:
                break
            else:
                err_msg = stderr.read().decode().strip()
                print(f"[WARN] Move attempt {attempt+1} failed: {err_msg}")
                time.sleep(1)  # wait before retry
        else:
            raise TransferError(f"Failed to move file after retries: {err_msg}")

        # === Cleanup Capture directory ===
        cleanup_cmd = f"sudo rm -f {REMOTE_CAPTURE_DIR.rstrip('/')}/capture-*.*"
        print(f"[DEBUG] Cleaning up capture folder: {cleanup_cmd}")
        ssh.exec_command(cleanup_cmd)

        print(f"[SUCCESS] File downloaded → {local_path}")
        print(f"[SUCCESS] Remote file archived under {archive_path}")
        print("[CLEANUP] Capture directory cleaned successfully.")
        return os.path.abspath(local_path)

    except paramiko.SSHException as e:
        raise TransferError(f"SSH connection failed: {e}")

    except Exception as e:
        raise TransferError(str(e))

    finally:
        if sftp:
            try:
                sftp.close()
            except Exception:
                pass
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass
