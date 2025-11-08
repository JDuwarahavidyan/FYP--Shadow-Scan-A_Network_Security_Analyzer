# modules/capture/capture_manager.py

from flask import Blueprint, jsonify, Response, request
from datetime import datetime
import threading
import paramiko
import time
import json
import queue

from modules.capture.utils import strip_ansi_codes
from modules.capture.config import SCRIPT_PATH
from modules.capture.log_queue import log_queue
from modules.config import PI_HOST, PI_USER, PI_PASS
from modules.transfer.transfer_manager import download_file_from_pi, TransferError


# ============================================================
# BLUEPRINT INITIALIZATION
# ============================================================
capture_bp = Blueprint("capture", __name__, url_prefix="/api/capture")


def init_capture_globals(globals_dict):
    """Inject shared global objects from server.py"""
    global process_active, client, lock, packet_count, capture_session
    process_active = globals_dict["process_active"]
    client = globals_dict["client"]
    lock = globals_dict["lock"]
    packet_count = globals_dict["packet_count"]
    capture_session = globals_dict["capture_session"]


# ============================================================
# Helper — Clear Log Queue
# ============================================================
def clear_log_queue():
    while not log_queue.empty():
        try:
            log_queue.get_nowait()
        except queue.Empty:
            break


# ============================================================
# LIST ACCESS POINTS
# ============================================================
@capture_bp.route("/list-aps", methods=["POST"])
def list_aps():
    clear_log_queue()
    global process_active
    data = request.get_json() or {}
    iface = data.get("interface", "wlan1")

    process_active = True
    log_queue.put("[/] Initializing Wifi Sniffing on Raspberry Pi ...")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(PI_HOST, username=PI_USER, password=PI_PASS)

        cmd = f"sudo python3 {SCRIPT_PATH}"
        log_queue.put(f"[$] Activating Passive WiFi Sniffer - By Team Shadow-Scan <-")

        stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)

        aps_json = "[]"
        json_detected = False

        for raw_line in iter(stdout.readline, ""):
            clean = strip_ansi_codes(raw_line.strip())
            if not clean:
                continue

            if clean.startswith("###JSON###"):
                aps_json = clean.replace("###JSON###", "").strip()
                json_detected = True
                continue

            log_queue.put(clean)

        ssh.close()

        aps = []
        if json_detected:
            try:
                aps = json.loads(aps_json)
            except Exception as parse_err:
                log_queue.put(f"[!] Failed to parse JSON: {parse_err}")
        else:
            log_queue.put("[!] No AP JSON detected. Returning empty list.")

        summary_msg = f"[✓] Scan complete — found {len(aps)} access points."
        log_queue.put(summary_msg)
        log_queue.put("[*] Choose your Access Point to capture packets.")

        return jsonify({"ok": True, "aps": aps}), 200

    except Exception as e:
        log_queue.put(f"[!] Error fetching AP list: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

    finally:
        process_active = False


# ============================================================
# START CAPTURE
# ============================================================
@capture_bp.route("/start", methods=["POST"])
def start_capture():
    global client, process_active, capture_session, packet_count

    data = request.get_json() or {}
    iface = data.get("interface", "wlan1")
    bssid = data.get("bssid")
    channel = data.get("channel")

    if not bssid or not channel:
        return jsonify({"ok": False, "error": "Missing BSSID or Channel"}), 400

    with lock:
        if process_active:
            return jsonify({"ok": False, "error": "Capture already running"}), 400
        process_active = True
        capture_session = f"cap-{int(time.time())}"
        packet_count = 0
        while not log_queue.empty():
            log_queue.get()

    def run_capture():
        global client, process_active, packet_count
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(PI_HOST, username=PI_USER, password=PI_PASS)

            cmd = f"sudo python3 {SCRIPT_PATH} --bssid {bssid} --channel {channel}"

            stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)

            for line in iter(stdout.readline, ""):
                if not process_active:
                    break
                clean_line = strip_ansi_codes(line.strip())
                if clean_line:
                    log_queue.put(clean_line)
                    if "packet" in clean_line.lower():
                        packet_count += 1

        except Exception as e:
            log_queue.put(f"[✗] Capture error: {e}")
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass
            with lock:
                process_active = False
            log_queue.put("[-] Capture process stopped.")

    thread = threading.Thread(target=run_capture, daemon=True)
    thread.start()

    return jsonify({
        "ok": True,
        "sessionId": capture_session,
        "startedAt": datetime.now().isoformat()
    }), 200


# ============================================================
# STOP CAPTURE
# ============================================================
@capture_bp.route("/stop/<session_id>", methods=["POST"])
def stop_capture(session_id):
    global client, process_active, packet_count

    with lock:
        if not process_active:
            return jsonify({"ok": False, "error": "No active capture"}), 400
        process_active = True  # keep active until done

    try:
        log_queue.put("🛑 Sending stop command to Raspberry Pi...")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(PI_HOST, username=PI_USER, password=PI_PASS)
        ssh.exec_command("sudo pkill -f 'wifi_sniff.py' || true; sudo pkill -f 'airodump-ng' || true")
        ssh.close()

        time.sleep(3)
        local_path = None

        try:
            local_path = download_file_from_pi()
        except TransferError as e:
            log_queue.put(f"[!] File transfer failed: {e}")
        except Exception as e:
            log_queue.put(f"[✗] Unexpected transfer error: {e}")

        time.sleep(0.5)
        with lock:
            process_active = False

        return jsonify({
            "ok": True,
            "fileUrl": local_path or None,
            "meta": {"packetCount": packet_count, "duration": 0}
        }), 200

    except Exception as e:
        with lock:
            process_active = False
        log_queue.put(f"[✗] Stop error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


# ============================================================
# STREAM LOGS (SSE)
# ============================================================
@capture_bp.route("/logs", methods=["GET"])
def stream_logs():
    def generate():
        while True:
            try:
                line = log_queue.get(timeout=1)
                clean = strip_ansi_codes(line).replace('"', '\\"')
                yield f'data: {{"type":"log","message":"{clean}"}}\n\n'
            except queue.Empty:
                if not process_active and log_queue.empty():
                    yield f'data: {{"type":"info","message":"[✓] Process finished"}}\n\n'
                    break
                continue

    response = Response(generate(), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


# ============================================================
# RESET CAPTURE SESSION
# ============================================================
@capture_bp.route("/reset", methods=["POST"])
def reset_capture():
    global process_active, packet_count, client

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(PI_HOST, username=PI_USER, password=PI_PASS, timeout=10)
        ssh.exec_command("sudo pkill -f 'wifi_sniff.py' || true; sudo pkill -f 'airodump-ng' || true")
        ssh.close()

        process_active = False
        packet_count = 0
        client = None

        while not log_queue.empty():
            try:
                log_queue.get_nowait()
            except:
                break

        return jsonify({"ok": True, "message": "Session fully reset"}), 200

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ============================================================
# MOCK PARSER (Placeholder)
# ============================================================
@capture_bp.route("/parse", methods=["POST"])
def parse_capture():
    data = request.get_json()
    file_url = data.get("fileUrl")
    time.sleep(1)
    return jsonify({
        "summary": {
            "totalPackets": packet_count or 1000,
            "protocols": {"TCP": 45, "UDP": 30, "ICMP": 15, "Other": 10}
        },
        "flows": [
            {"src": "192.168.1.10", "dst": "8.8.8.8", "protocol": "DNS", "packets": 124},
            {"src": "192.168.1.15", "dst": "192.168.1.1", "protocol": "HTTP", "packets": 856}
        ],
        "topHosts": ["192.168.1.10", "192.168.1.15", "192.168.1.20"]
    }), 200
