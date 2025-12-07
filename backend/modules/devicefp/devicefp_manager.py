from flask import Blueprint, request, jsonify
import os
import json
from scapy.all import rdpcap, Dot11
from collections import defaultdict
import time
import requests

devicefp_bp = Blueprint("devicefp", __name__)

# Device MAC address mapping
DEVICE_MACS = {
    "plug": "c0:f8:53:de:cf:2a",
    "plug": "c0:f8:53:df:18:ea",
    "wall_socket": "d8:d6:68:06:6d:65",
    "tabel_lamp": "3c:0b:59:8f:25:42",
    "switch": "38:2c:e5:1d:02:fb",
    "switch": "38:2c:e5:1c:cf:6e",
    "air_purifier": "50:ec:50:94:7b:a3",
    "motion_sensor": "f8:17:2d:b6:38:de",
    "motion_sensor": "f8:17:2d:b4:3d:5a",
    "door_sensor": "18:de:50:54:8e:e9",
    "door_sensor": "18:de:50:50:39:37",
    "baby_cam": "78:8b:2a:9c:80:1e",
    "camera": "5c:4e:ee:ce:f8:3b",
    "power_strip": "fc:3c:d7:53:f6:79",
}

BSSID = "14:eb:b6:be:d7:1e"  # router


def normalize_mac(mac):
    """Normalize MAC address to lowercase with colons"""
    if not mac:
        return None
    # Remove any spaces and convert to lowercase
    mac = mac.replace(" ", "").replace("-", ":").lower()
    # Ensure proper colon format
    if len(mac.replace(":", "")) == 12:
        mac = ":".join([mac.replace(":", "")[i : i + 2] for i in range(0, 12, 2)])
    return mac


def format_device_name(device_name):
    """Format device name for display - capitalize and replace underscores with spaces"""
    if not device_name:
        return "Unknown"
    # Replace underscores with spaces and capitalize each word
    formatted_name = device_name.replace("_", " ").title()
    return formatted_name


def get_vendor_from_api(mac_address):
    """Get vendor information from MAC lookup API"""
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
    """Calculate confidence score based on packet count and activity"""
    packet_count = stats["packet_count"]
    has_data = stats["data_packets"] > 0
    connected_to_router = stats["connected_to_router"]

    confidence = 0.5  # Base confidence

    # Increase confidence based on packet count
    if packet_count > 100:
        confidence += 0.3
    elif packet_count > 50:
        confidence += 0.2
    elif packet_count > 10:
        confidence += 0.1

    # Increase confidence if has data packets
    if has_data:
        confidence += 0.1

    # Increase confidence if connected to router
    if connected_to_router:
        confidence += 0.1

    return min(confidence, 1.0)  # Cap at 1.0


def analyze_device_fingerprints(file_path):
    """Analyze pcap file and identify devices based on MAC addresses"""
    try:
        print(f"[*] Reading pcap file: {file_path}")
        packets = rdpcap(file_path)
        print(f"[*] Total packets in file: {len(packets)}")

        # Device statistics
        device_stats = defaultdict(
            lambda: {
                "name": "Unknown",
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

        # Reverse MAC lookup for faster searching
        mac_to_device = {mac.lower(): name for name, mac in DEVICE_MACS.items()}
        normalized_bssid = normalize_mac(BSSID)

        print(f"[*] Looking for router BSSID: {normalized_bssid}")
        print(f"[*] Looking for {len(DEVICE_MACS)} known devices...")

        total_packets = len(packets)
        processed_packets = 0
        router_packets = 0

        for packet in packets:
            processed_packets += 1

            if processed_packets % 1000 == 0:
                print(f"[*] Processed {processed_packets}/{total_packets} packets...")

            if packet.haslayer(Dot11):
                # Get MAC addresses from different fields
                src_mac = (
                    normalize_mac(packet[Dot11].addr2) if packet[Dot11].addr2 else None
                )
                dst_mac = (
                    normalize_mac(packet[Dot11].addr1) if packet[Dot11].addr1 else None
                )
                bss_mac = (
                    normalize_mac(packet[Dot11].addr3) if packet[Dot11].addr3 else None
                )

                # Check for router packets
                if normalized_bssid in [src_mac, dst_mac, bss_mac]:
                    router_packets += 1

                # Get packet timestamp
                timestamp = packet.time

                # Check packet type
                packet_type = packet[Dot11].type
                packet_subtype = packet[Dot11].subtype

                # Classify packet type
                if packet_type == 0:  # Management frame
                    frame_type = "management"
                elif packet_type == 1:  # Control frame
                    frame_type = "control"
                elif packet_type == 2:  # Data frame
                    frame_type = "data"
                else:
                    frame_type = "unknown"

                # Get signal strength if available
                signal_strength = None
                if hasattr(packet, "dBm_AntSignal"):
                    signal_strength = packet.dBm_AntSignal

                # Check all MAC addresses (src, dst, bss) for known devices
                for mac_addr in [src_mac, dst_mac, bss_mac]:
                    if mac_addr and mac_addr in mac_to_device:
                        device_name = mac_to_device[mac_addr]
                        stats = device_stats[device_name]
                        stats["name"] = device_name
                        stats["mac"] = mac_addr
                        stats["packet_count"] += 1

                        # Update packet type counts
                        if frame_type == "data":
                            stats["data_packets"] += 1
                        elif frame_type == "management":
                            stats["management_packets"] += 1
                        elif frame_type == "control":
                            stats["control_packets"] += 1

                        # Update timestamps
                        if (
                            stats["first_seen"] is None
                            or timestamp < stats["first_seen"]
                        ):
                            stats["first_seen"] = timestamp
                        if stats["last_seen"] is None or timestamp > stats["last_seen"]:
                            stats["last_seen"] = timestamp

                        # Update signal strength
                        if signal_strength is not None:
                            stats["signal_strength"].append(signal_strength)

                        # Check if connected to router
                        if normalized_bssid in [src_mac, dst_mac, bss_mac]:
                            stats["connected_to_router"] = True

                        # Set vendor - try API first, fallback to device type mapping
                        if (
                            stats["vendor"] == "Unknown"
                        ):  # Only lookup if not already set
                            api_vendor = get_vendor_from_api(mac_addr)
                            if api_vendor:
                                stats["vendor"] = api_vendor
                                print(
                                    f"[*] Found vendor for {device_name} ({mac_addr}): {api_vendor}"
                                )

        print(f"[*] Processed {processed_packets} packets")
        print(f"[*] Found {router_packets} packets involving router {normalized_bssid}")

        # Convert to list and calculate percentages - only devices with traffic
        results = []
        for device_name, stats in device_stats.items():
            if stats["packet_count"] > 0:  # Only include devices with traffic
                # Calculate average signal strength
                avg_signal = None
                if stats["signal_strength"]:
                    avg_signal = sum(stats["signal_strength"]) / len(
                        stats["signal_strength"]
                    )

                # Calculate packet type percentages
                total_device_packets = stats["packet_count"]
                data_percentage = (
                    (stats["data_packets"] / total_device_packets) * 100
                    if total_device_packets > 0
                    else 0
                )
                mgmt_percentage = (
                    (stats["management_packets"] / total_device_packets) * 100
                    if total_device_packets > 0
                    else 0
                )
                ctrl_percentage = (
                    (stats["control_packets"] / total_device_packets) * 100
                    if total_device_packets > 0
                    else 0
                )

                # Format timestamps - fix EDecimal issue
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
                    "device_name": format_device_name(stats["name"]),
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
                    "avg_signal_strength": round(avg_signal, 2) if avg_signal else None,
                    "connected_to_router": stats["connected_to_router"],
                    "confidence": calculate_confidence(stats),
                }
                results.append(device_info)

        return results

    except Exception as e:
        print(f"[ERROR] Error analyzing file: {str(e)}")
        raise e


@devicefp_bp.route("/analyze-latest", methods=["GET"])
def analyze_latest_capture():
    """Analyze the latest capture file from downloads folder"""
    try:
        downloads_dir = r"D:\University of Ruhuna FoE\Common Modules\EE7802 Undergraduate Project\Shadow-Scan\backend\downloads"

        if not os.path.exists(downloads_dir):
            return jsonify({"error": "Downloads directory not found"}), 404

        # Find all capture files
        capture_files = [
            f for f in os.listdir(downloads_dir) if f.endswith((".cap", ".pcap"))
        ]

        if not capture_files:
            return (
                jsonify({"error": "No capture files found in downloads directory"}),
                404,
            )

        # Use the first capture file found (you can modify this logic)
        latest_file = os.path.join(downloads_dir, capture_files[0])

        print(f"[*] Analyzing latest file: {latest_file}")
        # Analyze the pcap file
        devices = analyze_device_fingerprints(latest_file)

        response = {
            "status": "success",
            "total_devices_found": len(devices),
            "router_bssid": BSSID,
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
