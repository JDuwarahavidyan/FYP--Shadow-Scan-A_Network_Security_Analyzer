# server.py
from flask import Flask, Response, jsonify, request
from flask_cors import CORS
import paramiko
import threading
import time
from datetime import datetime
import queue
import re

app = Flask(__name__)
# Allow your Vite frontend (localhost:5173) or all origins for testing
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# === Raspberry Pi SSH Configuration ===
PI_HOST = "192.168.1.27"  
PI_USER = "kali"          
PI_PASS = "kali"          
SCRIPT_PATH = "/home/kali/IoT-Privacy/code/PacketCapture/wifi_cap.py"

# === Global State ===
client = None
process_active = False
capture_session = None
packet_count = 0
lock = threading.Lock()
log_queue = queue.Queue()


def strip_ansi_codes(text):
    """Remove ANSI color codes from log lines."""
    ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    """
    Starts wifi_cap.py on the Raspberry Pi in auto mode.
    Expects JSON: {"interface": "wlan1", "bssid": "...", "channel": "..."}
    Returns: {"ok": true, "sessionId": "...", "startedAt": "..."}
    """
    global client, process_active, capture_session, packet_count

    data = request.get_json() or {}
    iface = data.get("interface", "wlan1")
    bssid = data.get("bssid")
    channel = data.get("channel")

    with lock:
        if process_active:
            return jsonify({"ok": False, "error": "Capture already running"}), 400
        process_active = True
        capture_session = f"cap-{int(time.time())}"
        packet_count = 0
        while not log_queue.empty():
            log_queue.get()  # clear old logs

    def run_capture():
        global client, process_active, packet_count
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(PI_HOST, username=PI_USER, password=PI_PASS)

            # Build command for auto/non-interactive mode
            cmd = f"sudo python3 {SCRIPT_PATH} --auto --iface {iface}"
            if bssid and channel:
                cmd += f" --bssid {bssid} --channel {channel}"

            log_queue.put(f"Starting capture via: {cmd}")
            stdin, stdout, stderr = client.exec_command(cmd)

            # Stream lines to queue
            for line in iter(stdout.readline, ""):
                if not process_active:
                    break
                clean_line = strip_ansi_codes(line.strip())
                if clean_line:
                    log_queue.put(clean_line)
                    if "packet" in clean_line.lower():
                        packet_count += 1

        except Exception as e:
            log_queue.put(f"Capture error: {e}")
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass
            with lock:
                process_active = False
            log_queue.put("Capture process stopped.")

    # Start thread
    thread = threading.Thread(target=run_capture, daemon=True)
    thread.start()

    return jsonify({
        "ok": True,
        "sessionId": capture_session,
        "startedAt": datetime.now().isoformat()
    }), 200


@app.route("/api/capture/stop/<session_id>", methods=["POST"])
def stop_capture(session_id):
    """
    Stops the running wifi_cap.py process on the Raspberry Pi.
    Returns: {"ok": true, "fileUrl": "...", "meta": {...}}
    """
    global client, process_active, packet_count

    with lock:
        if not process_active:
            return jsonify({"ok": False, "error": "No active capture"}), 400
        process_active = False

    try:
        if client:
            client.exec_command("sudo pkill -f wifi_cap.py")
            time.sleep(0.5)
            client.close()

        file_url = f"/captures/capture-{session_id}.cap"
        log_queue.put("Capture stopped and file saved.")

        return jsonify({
            "ok": True,
            "fileUrl": file_url,
            "meta": {
                "packetCount": packet_count,
                "duration": 0
            }
        }), 200
    except Exception as e:
        log_queue.put(f"❌ Stop error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/capture/logs")
def stream_logs():
    """
    Streams capture logs via Server-Sent Events (SSE).
    """
    def generate():
        while process_active or not log_queue.empty():
            try:
                line = log_queue.get(timeout=1)
                clean = strip_ansi_codes(line)
                yield f'data: {{"type":"log","message":"{clean}"}}\n\n'
            except queue.Empty:
                continue
        yield f'data: {{"type":"info","message":"🔚 Capture process stopped"}}\n\n'

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/capture/parse", methods=["POST"])
def parse_capture():
    """
    Parses a capture file and returns summary.
    Expects JSON: {"fileUrl": "..."}
    Returns: mock summary for now.
    """
    data = request.get_json()
    file_url = data.get("fileUrl")

    time.sleep(1)  # simulate parsing delay

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


if __name__ == "__main__":
    print("🚀 Flask server started on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
