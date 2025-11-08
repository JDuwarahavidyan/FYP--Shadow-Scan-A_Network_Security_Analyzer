# analysis_manager.py
from flask import Blueprint, jsonify
from scapy.all import rdpcap
from datetime import datetime
import os
from modules.analysis.config import DOWNLOAD_DIR, ALLOWED_EXTENSIONS


analysis_bp = Blueprint("analysis", __name__)

@analysis_bp.route("/api/analysis/latest", methods=["GET"])
def analyze_latest_capture():
    """
    Analyze the latest .cap file in the downloads folder
    and return packet count + metadata.
    """
    try:
        if not os.path.exists(DOWNLOAD_DIR):
            return jsonify({"ok": False, "error": "Downloads directory not found"}), 404

        # Find the latest capture file (by modification time)
        cap_files = [
            os.path.join(DOWNLOAD_DIR, f)
            for f in os.listdir(DOWNLOAD_DIR)
            if os.path.splitext(f)[1].lower() in ALLOWED_EXTENSIONS
        ]
        if not cap_files:
            return jsonify({"ok": False, "error": "No capture files found"}), 404

        latest_file = max(cap_files, key=os.path.getmtime)

        # Load and count packets using Scapy
        packets = rdpcap(latest_file)
        packet_count = len(packets)

        # Build structured response
        return jsonify({
            "ok": True,
            "file": os.path.basename(latest_file),
            "packetCount": packet_count,
            "analyzedAt": datetime.now().isoformat(),
        }), 200

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
