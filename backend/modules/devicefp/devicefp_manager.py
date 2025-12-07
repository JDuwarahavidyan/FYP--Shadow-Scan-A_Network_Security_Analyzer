from flask import Blueprint, request, jsonify
import os
import json
from scapy.all import rdpcap, Dot11
from collections import defaultdict
import time
import requests

devicefp_bp = Blueprint("devicefp", __name__)

# Device -> list of MAC addresses (Option B)
DEVICE_MACS = {
    "plug": ["c0:f8:53:de:cf:2a", "c0:f8:53:df:18:ea"],
    "wall_socket": ["d8:d6:68:06:6d:65"],
    "tabel_lamp": ["3c:0b:59:8f:25:42"],
    "switch": ["38:2c:e5:1d:02:fb", "38:2c:e5:1c:cf:6e"],
    "air_purifier": ["50:ec:50:94:7b:a3"],
    "motion_sensor": ["f8:17:2d:b6:38:de", "f8:17:2d:b4:3d:5a"],
    "door_sensor": ["18:de:50:54:8e:e9", "18:de:50:50:39:37"],
    "baby_cam": ["78:8b:2a:9c:80:1e"],
    "camera": ["5c:4e:ee:ce:f8:3b"],
    "power_strip": ["fc:3c:d7:53:f6:79"],
}


def normalize_mac(mac):
    """Normalize MAC address to lowercase with colons"""
    if not mac:
        return None
    mac = mac.replace(" ", "").replace("-", ":").lower()
    bare = mac.replace(":", "")
    if len(bare) == 12:
        mac = ":".join([bare[i : i + 2] for i in range(0, 12, 2)])
    return mac


def format_device_name(device_name):
    if not device_name:
        return "Unknown"
    return device_name.replace("_", " ").title()


def get_vendor_from_api(mac_address):
    """Get vendor information from MAC lookup API (best-effort)"""
    try:
        url = f"https://api.maclookup.app/v2/macs/{mac_address}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if data.get("found") and "company" in data:
                print(f"[*] API Vendor lookup for {mac_address}: {data['company']}")
                return data["company"]

        return None
    except Exception as e:
        print(f"[WARNING] Failed to lookup vendor for {mac_address}: {e}")
        return None


def calculate_confidence(stats):
    packet_count = stats["packet_count"]
    has_data = stats["data_packets"] > 0
    connected_to_router = stats["connected_to_router"]

    confidence = 0.5
    if packet_count > 100:
        confidence += 0.3
    elif packet_count > 50:
        confidence += 0.2
    elif packet_count > 10:
        confidence += 0.1

    if has_data:
        confidence += 0.1
    if connected_to_router:
        confidence += 0.1

    return min(confidence, 1.0)


def analyze_device_fingerprints(file_path, bssid=None):
    """
    Analyze pcap and return one entry per MAC (with device type/name).
    Stats are keyed by normalized MAC address to avoid aggregation across multiple MACs with the same device name.

    Args:
        file_path: Path to the pcap file
        bssid: Router BSSID (optional, defaults to configured router)
    """
    try:
        # Default BSSID if not provided
        if not bssid:
            bssid = "14:eb:b6:be:d7:1e"  # Default router

        print(f"[*] Reading pcap file: {file_path}")
        packets = rdpcap(file_path)
        print(f"[*] Total packets in file: {len(packets)}")

        # Build mac->device mapping from DEVICE_MACS
        mac_to_device = {}
        for device_name, mac_list in DEVICE_MACS.items():
            for mac in mac_list:
                nm = normalize_mac(mac)
                if nm:
                    mac_to_device[nm] = device_name

        normalized_bssid = normalize_mac(bssid)

        print(f"[*] Looking for router BSSID: {normalized_bssid}")
        print(f"[*] Configured devices: {len(DEVICE_MACS)}")
        print(f"[*] Configured MAC addresses: {len(mac_to_device)}")

        # Device stats keyed by MAC (not device name)
        device_stats = defaultdict(
            lambda: {
                "device_name": "Unknown",
                "mac": "",
                "packet_count": 0,
                "data_packets": 0,
                "management_packets": 0,
                "control_packets": 0,
                "first_seen": None,
                "last_seen": None,
                "signal_strength": [],
                "connected_to_router": False,
                "vendor": "Unknown",
            }
        )

        total_packets = len(packets)
        processed_packets = 0
        router_packets = 0

        for packet in packets:
            processed_packets += 1
            if processed_packets % 1000 == 0:
                print(f"[*] Processed {processed_packets}/{total_packets} packets...")

            if not packet.haslayer(Dot11):
                continue

            # Normalize MACs from packet fields
            src_mac = (
                normalize_mac(packet[Dot11].addr2) if packet[Dot11].addr2 else None
            )
            dst_mac = (
                normalize_mac(packet[Dot11].addr1) if packet[Dot11].addr1 else None
            )
            bss_mac = (
                normalize_mac(packet[Dot11].addr3) if packet[Dot11].addr3 else None
            )

            if normalized_bssid in [src_mac, dst_mac, bss_mac]:
                router_packets += 1

            timestamp = packet.time

            packet_type = packet[Dot11].type
            if packet_type == 0:
                frame_type = "management"
            elif packet_type == 1:
                frame_type = "control"
            elif packet_type == 2:
                frame_type = "data"
            else:
                frame_type = "unknown"

            signal_strength = getattr(packet, "dBm_AntSignal", None)

            # For each MAC in this frame, analyze it (known or unknown device)
            for mac_addr in [src_mac, dst_mac, bss_mac]:
                if not mac_addr:
                    continue

                # Skip the router itself
                if mac_addr == normalized_bssid:
                    continue

                # Check if device is in our configured list, otherwise mark as "new_device"
                if mac_addr in mac_to_device:
                    device_name = mac_to_device[mac_addr]
                else:
                    # Unknown device - only process if connected to router
                    if normalized_bssid not in [src_mac, dst_mac, bss_mac]:
                        continue
                    device_name = "new_device"

                stats = device_stats[mac_addr]
                stats["device_name"] = device_name
                stats["mac"] = mac_addr
                stats["packet_count"] += 1

                if frame_type == "data":
                    stats["data_packets"] += 1
                elif frame_type == "management":
                    stats["management_packets"] += 1
                elif frame_type == "control":
                    stats["control_packets"] += 1

                if stats["first_seen"] is None or timestamp < stats["first_seen"]:
                    stats["first_seen"] = timestamp
                if stats["last_seen"] is None or timestamp > stats["last_seen"]:
                    stats["last_seen"] = timestamp

                if signal_strength is not None:
                    stats["signal_strength"].append(signal_strength)

                if normalized_bssid in [src_mac, dst_mac, bss_mac]:
                    stats["connected_to_router"] = True

                # Vendor lookup per MAC (only once)
                if stats["vendor"] == "Unknown":
                    api_vendor = get_vendor_from_api(mac_addr)
                    if api_vendor:
                        stats["vendor"] = api_vendor
                        print(
                            f"[*] Found vendor for {device_name} ({mac_addr}): {api_vendor}"
                        )

        print(f"[*] Processed {processed_packets} packets")
        print(f"[*] Found {router_packets} packets involving router {normalized_bssid}")

        # Build results list: one entry per MAC that had traffic
        results = []
        seen_macs = set()
        for mac_addr, stats in device_stats.items():
            if stats["packet_count"] <= 0:
                continue

            seen_macs.add(mac_addr)

            avg_signal = None
            if stats["signal_strength"]:
                avg_signal = sum(stats["signal_strength"]) / len(
                    stats["signal_strength"]
                )

            total_device_packets = stats["packet_count"]
            data_percentage = (
                (stats["data_packets"] / total_device_packets) * 100
                if total_device_packets
                else 0
            )
            mgmt_percentage = (
                (stats["management_packets"] / total_device_packets) * 100
                if total_device_packets
                else 0
            )
            ctrl_percentage = (
                (stats["control_packets"] / total_device_packets) * 100
                if total_device_packets
                else 0
            )

            first_seen = (
                time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(float(stats["first_seen"]))
                )
                if stats["first_seen"]
                else "N/A"
            )
            last_seen = (
                time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(float(stats["last_seen"]))
                )
                if stats["last_seen"]
                else "N/A"
            )

            device_info = {
                "device_name": format_device_name(stats["device_name"]),
                "mac_address": stats["mac"],
                "vendor": stats["vendor"],
                "total_packets": total_device_packets,
                "packet_types": {
                    "data": {
                        "count": stats["data_packets"],
                        "percentage": round(data_percentage, 2),
                    },
                    "management": {
                        "count": stats["management_packets"],
                        "percentage": round(mgmt_percentage, 2),
                    },
                    "control": {
                        "count": stats["control_packets"],
                        "percentage": round(ctrl_percentage, 2),
                    },
                },
                "first_seen": first_seen,
                "last_seen": last_seen,
                "avg_signal_strength": (
                    round(avg_signal, 2) if avg_signal is not None else None
                ),
                "connected_to_router": stats["connected_to_router"],
                "confidence": calculate_confidence(stats),
            }
            results.append(device_info)

        # Diagnostics: configured vs observed MACs
        configured_macs = set(mac_to_device.keys())
        observed_macs = set(seen_macs)
        known_observed = observed_macs & configured_macs
        new_devices = observed_macs - configured_macs
        not_seen = configured_macs - observed_macs

        print(f"[*] Known devices observed: {len(known_observed)}")
        if new_devices:
            print(f"[*] New/Unknown devices found: {len(new_devices)}")
            print(f"    MACs: {new_devices}")
        if not_seen:
            print(
                f"[*] Configured MACs not observed in capture ({len(not_seen)}): {not_seen}"
            )

        return results

    except Exception as e:
        print(f"[ERROR] Error analyzing file: {str(e)}")
        raise e


@devicefp_bp.route("/analyze-latest", methods=["POST"])
def analyze_latest_capture():
    """Analyze the newest capture file from downloads folder with provided or default BSSID"""
    try:
        data = request.get_json() or {}
        bssid = data.get("bssid")

        downloads_dir = r"D:\University of Ruhuna FoE\Common Modules\EE7802 Undergraduate Project\Shadow-Scan\backend\downloads"

        if not os.path.exists(downloads_dir):
            return jsonify({"error": "Downloads directory not found"}), 404

        capture_files = [
            f for f in os.listdir(downloads_dir) if f.endswith((".cap", ".pcap"))
        ]
        if not capture_files:
            return (
                jsonify({"error": "No capture files found in downloads directory"}),
                404,
            )

        # Pick the newest file by modification time
        capture_files_full = [os.path.join(downloads_dir, f) for f in capture_files]
        latest_file = max(capture_files_full, key=os.path.getmtime)

        print(f"[*] Analyzing newest file: {latest_file}")
        if bssid:
            print(f"[*] Using provided BSSID: {bssid}")
        else:
            print(f"[*] Using default BSSID")

        devices = analyze_device_fingerprints(latest_file, bssid)

        response = {
            "status": "success",
            "total_devices_found": len(devices),
            "router_bssid": bssid if bssid else "14:eb:b6:be:d7:1e",
            "devices": devices,
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_analyzed": latest_file,
            "available_files": capture_files,
        }

        print(f"[*] Analysis complete. Found {len(devices)} devices")
        return jsonify(response)

    except Exception as e:
        print(f"[ERROR] Analysis failed: {str(e)}")
        return jsonify({"status": "error", "error": str(e)}), 500
