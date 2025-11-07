# capture_manager.py
from flask import jsonify, Response, request
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


# Globals (will be injected from server.py)
process_active = None
client = None
lock = None
packet_count = None
capture_session = None


def register_routes(app, globals_dict):
    global process_active, client, lock, packet_count, capture_session
    process_active = globals_dict["process_active"]
    client = globals_dict["client"]
    lock = globals_dict["lock"]
    packet_count = globals_dict["packet_count"]
    capture_session = globals_dict["capture_session"]

    # ============================================================
    # 1️⃣ LIST ACCESS POINTS
    # ============================================================
    @app.route("/api/capture/list-aps", methods=["POST"])
    def list_aps():
        global process_active
        data = request.get_json() or {}
        iface = data.get("interface", "wlan1")

        process_active = True
        log_queue.put("📡 Initializing Access Point Scan on Raspberry Pi...")

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(PI_HOST, username=PI_USER, password=PI_PASS)

            cmd = f"sudo python3 {SCRIPT_PATH}"
            log_queue.put(f"🚀 Executing command: {cmd}")

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
                    log_queue.put(f"⚠️ Failed to parse JSON: {parse_err}")
            else:
                log_queue.put("⚠️ No AP JSON detected. Returning empty list.")

            summary_msg = f"✅ Scan complete — found {len(aps)} access points."
            log_queue.put(summary_msg)
            log_queue.put("📡 Choose your AP to capture packets")

            return jsonify({"ok": True, "aps": aps}), 200

        except Exception as e:
            log_queue.put(f"❌ Error fetching AP list: {e}")
            return jsonify({"ok": False, "error": str(e)}), 500

        finally:
            process_active = False


    # ============================================================
    # 2️⃣ START CAPTURE
    # ============================================================
    @app.route("/api/capture/start", methods=["POST"])
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
                log_queue.put(f"🚀 Starting capture via: {cmd}")

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
                log_queue.put(f"❌ Capture error: {e}")
            finally:
                if client:
                    try:
                        client.close()
                    except Exception:
                        pass
                with lock:
                    process_active = False
                log_queue.put("🔚 Capture process stopped.")

        thread = threading.Thread(target=run_capture, daemon=True)
        thread.start()

        return jsonify({
            "ok": True,
            "sessionId": capture_session,
            "startedAt": datetime.now().isoformat()
        }), 200


    
    # ============================================================
    # 3️⃣ STOP CAPTURE
    # ============================================================
    @app.route("/api/capture/stop/<session_id>", methods=["POST"])
    def stop_capture(session_id):
        """
        Stops remote capture, ensures all processes are killed,
        downloads latest .cap to backend, and flushes logs immediately.
        """
        from modules.transfer.transfer_manager import download_file_from_pi, TransferError

        global client, process_active, packet_count

        with lock:
            if not process_active:
                return jsonify({"ok": False, "error": "No active capture"}), 400
            process_active = True  # keep active until we're done

        try:
            log_queue.put("🛑 Sending stop command to Raspberry Pi...")

            # === Stop remote capture ===
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(PI_HOST, username=PI_USER, password=PI_PASS)

            kill_cmd = (
                "sudo pkill -f 'wifi_sniff.py' || true; "
                "sudo pkill -f 'airodump-ng' || true"
            )
            ssh.exec_command(kill_cmd)
            time.sleep(3)
            ssh.close()

            log_queue.put("✅ Capture processes stopped on Raspberry Pi.")
            log_queue.put("⬇️ Attempting file download to backend...")

            local_path = None
            try:
                local_path = download_file_from_pi()
                log_queue.put(f"✅ File successfully transferred: {local_path}")
            except TransferError as e:
                log_queue.put(f"⚠️ File transfer failed: {e}")
            except Exception as e:
                log_queue.put(f"❌ Unexpected transfer error: {e}")

            log_queue.put("🎯 Capture fully stopped and file saved locally.")
            log_queue.put("🔚 Capture process stopped.")

            # === Flush logs immediately to SSE ===
            # This forces all queued messages to reach the frontend before stopping
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
            log_queue.put(f"❌ Stop error: {e}")
            return jsonify({"ok": False, "error": str(e)}), 500




    # ============================================================
    # 4️⃣ STREAM LOGS (SSE)
    # ============================================================
    @app.route("/api/capture/logs")
    def stream_logs():
        def generate():
            idle_loops = 0
            while idle_loops < 5 or process_active or not log_queue.empty():
                try:
                    line = log_queue.get(timeout=1)
                    idle_loops = 0
                    clean = strip_ansi_codes(line)
                    yield f'data: {{"type":"log","message":"{clean}"}}\n\n'
                except queue.Empty:
                    idle_loops += 1
                    continue
            yield f'data: {{"type":"info","message":"🔚 Process finished"}}\n\n'

            return Response(generate(), mimetype="text/event-stream")



    # ============================================================
    # 5️⃣ MOCK PARSER
    # ============================================================
    @app.route("/api/capture/parse", methods=["POST"])
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