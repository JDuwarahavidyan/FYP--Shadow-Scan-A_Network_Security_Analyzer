# modules/analysis/analysis_manager.py
from flask import Blueprint, jsonify, request
from scapy.all import rdpcap, Dot11
import os

analysis_bp = Blueprint("analysis", __name__, url_prefix="/api/analysis")

DOWNLOAD_DIR = os.path.join(os.getcwd(), "downloads")


def _normalize_mac(mac):
    """Return lowercase MAC string without separators for comparison."""
    if not mac:
        return None
    return mac.replace(":", "").replace("-", "").lower()


def _is_broadcast(mac):
    """Return True if MAC is broadcast (ff:ff:ff:ff:ff:ff)."""
    return mac.lower() in {"ff:ff:ff:ff:ff:ff", "ffffffffffff"}


@analysis_bp.route("/analyze", methods=["POST"])
def analyze_capture():
    """
    Analyze the given .cap file:
      • Filter only packets involving the specified BSSID (like wlan.addr == <bssid>)
      • Count MAC-layer frame types
      • Extract top communicating hosts & flows
      • Keep human-readable MAC format (with colons)
    """
    try:
        data = request.get_json() or {}
        file_url = data.get("fileUrl")
        ssid = data.get("ssid")
        bssid = data.get("bssid")

        if not file_url:
            return jsonify({"ok": False, "error": "Missing fileUrl"}), 400

        if not bssid:
            return jsonify({"ok": False, "error": "Missing BSSID"}), 400

        # --- Resolve Path ---
        if not os.path.isabs(file_url):
            file_path = os.path.join(DOWNLOAD_DIR, os.path.basename(file_url))
        else:
            file_path = file_url

        if not os.path.exists(file_path):
            return jsonify({"ok": False, "error": f"File not found: {file_path}"}), 404

        # --- Read Packets ---
        all_packets = rdpcap(file_path)
        total_before_filter = len(all_packets)
        bssid_norm = _normalize_mac(bssid)

        print(f"[DEBUG] Loaded {total_before_filter} packets")
        print(f"[DEBUG] Filtering by wlan.addr == {bssid}")

        # --- Filter Packets (wlan.addr == bssid) ---
        filtered_packets = []
        for pkt in all_packets:
            if pkt.haslayer(Dot11):
                dot11 = pkt[Dot11]
                for addr in [dot11.addr1, dot11.addr2, dot11.addr3, getattr(dot11, "addr4", None)]:
                    if addr and _normalize_mac(addr) == bssid_norm:
                        filtered_packets.append(pkt)
                        break  # Include packet once only
        packets = filtered_packets
        total_after_filter = len(packets)

        print(f"[DEBUG] After filter: {total_after_filter} packets remain")

        # --- Initialize Stats ---
        packet_types = {"Management": 0, "Control": 0, "Data": 0}
        flows = {}
        host_counts = {}

        # --- Analyze MAC Layer ---
        for pkt in packets:
            if not pkt.haslayer(Dot11):
                continue

            dot11 = pkt[Dot11]
            frame_type = getattr(dot11, "type", None)

            if frame_type == 0:
                packet_types["Management"] += 1
            elif frame_type == 1:
                packet_types["Control"] += 1
            elif frame_type == 2:
                packet_types["Data"] += 1

            src = dot11.addr2
            dst = dot11.addr1
            if not src or not dst:
                continue
            if _is_broadcast(src) or _is_broadcast(dst):
                continue

            src_norm = _normalize_mac(src)
            dst_norm = _normalize_mac(dst)

            # Only include flows where one side is the BSSID
            if not (src_norm == bssid_norm or dst_norm == bssid_norm):
                continue
            if src_norm == dst_norm:
                continue

            # Record directional flow
            flows[(src, dst)] = flows.get((src, dst), 0) + 1

            # Track communication peers (non-bssid)
            peer = dst if src_norm == bssid_norm else src
            if not _is_broadcast(peer):
                host_counts[peer] = host_counts.get(peer, 0) + 1

        # --- Frame Type Percentages ---
        total_classified = sum(packet_types.values()) or 1
        packet_type_percent = {
            k: round((v / total_classified) * 100, 2)
            for k, v in packet_types.items()
        }

        # --- Prepare Output ---
        top_flows = sorted(flows.items(), key=lambda x: x[1], reverse=True)[:10]
        flow_data = [
            {"src": s, "dst": d, "packets": c}
            for (s, d), c in top_flows
        ]

        # Top 10 communicating hosts (exclude BSSID)
        top_hosts = sorted(
            [(mac, count) for mac, count in host_counts.items() if _normalize_mac(mac) != bssid_norm],
            key=lambda x: x[1],
            reverse=True,
        )
        communicated_hosts = [mac for mac, _ in top_hosts[:10]]

        # --- Response ---
        return jsonify({
            "ok": True,
            "ssid": ssid,
            "bssid": bssid,  # preserve original colon style
            "summary": {
                "totalBeforeFilter": total_before_filter,
                "totalPacketsAfterFilter": total_after_filter,
                "packetTypes": packet_types,
                "packetTypePercentages": packet_type_percent,
            },
            "flows": flow_data,
            "communicatedHosts": communicated_hosts,
        }), 200

    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500
