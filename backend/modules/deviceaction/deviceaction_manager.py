import pandas as pd
import numpy as np
import json
import os
from scapy.all import rdpcap, Dot11
from flask import Blueprint, request, jsonify

deviceaction_bp = Blueprint("deviceaction", __name__)


# Feature Extraction


def extract_features_for_mac_pair(packets, mac1, mac2, label, window_size=1.0):
    pkt_list = []
    t0 = float(packets[0].time)

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]
        src, dst = dot11.addr2, dot11.addr1

        # Device-specific MAC filtering
        if label == "air_purefier":
            if ((src, dst) not in [(mac1, mac2), (mac2, mac1)]) and (dst != mac1):
                continue
        else:
            if (src, dst) not in [(mac1, mac2), (mac2, mac1)]:
                continue

        if len(pkt_list) > 0:
            last_len = pkt_list[-1]["frame_len"]
            ref1 = 1 if (len(pkt) == last_len == 10) else 0
        else:
            ref1 = 0

        pkt_list.append(
            {
                "time": float(pkt.time) - t0,
                "frame_len": len(pkt),
                "ref": 1 if len(pkt) in [269, 91] else 0,
                "ref1": ref1,
                "src_mac": src,
                "dst_mac": dst,
                "retry": 1 if dot11.FCfield & 0x8 else 0,
            }
        )

    if not pkt_list:
        return pd.DataFrame()

    pkt_list.sort(key=lambda x: x["time"])
    times = np.array([p["time"] for p in pkt_list])
    features = []

    j = 0
    for i in range(len(times)):
        while j < len(times) and times[j] - times[i] <= window_size:
            j += 1

        end_time = times[i] + window_size
        mask = (times >= times[i]) & (times <= end_time)
        window_pkts = [pkt_list[k] for k in np.where(mask)[0]]

        if not window_pkts:
            continue

        ref = 1 if any(p["ref"] == 1 for p in window_pkts) else 0
        ref1 = 1 if any(p["ref1"] == 1 for p in window_pkts) else 0

        features.append(
            {
                "label": label,
                "window_start": times[i],
                "window_end": end_time,
                "ref": ref,
                "ref1": ref1,
            }
        )

    return pd.DataFrame(features)


# Classification Rules


def classify_device(device_name, row):
    if device_name in [
        "plug",
        "wall_plug",
        "tabel_lamp",
        "switch",
        "motion_sensor",
        "door_sensor",
    ]:
        return "triggering" if row.get("ref") == 1 else "not_triggering"

    elif device_name == "air_purefier":
        return "triggering" if row.get("ref1") == 1 else "not_triggering"

    else:
        return "unknown_device"


# Main Processing


def process_pcap_auto(pcap_file, config_json, window_size=1.0, summary_window=0.5):
    try:
        packets = rdpcap(pcap_file)
    except Exception:
        return None

    # Load JSON config
    with open(config_json, "r") as f:
        device_configs = json.load(f)

    all_results = []

    for device in device_configs:
        name = device["device_name"]
        mac1 = device["mac1"]
        mac2 = device["mac2"]
        label = device["label"]

        df = extract_features_for_mac_pair(packets, mac1, mac2, label, window_size)
        if df.empty:
            continue

        df["device"] = name
        df["predicted"] = df.apply(lambda r: classify_device(name, r), axis=1)
        all_results.append(df)

    if not all_results:
        return None

    final_df = pd.concat(all_results).sort_values("window_start").reset_index(drop=True)

    trigger_sequence = []

    for device, device_df in final_df.groupby("device"):
        max_time = device_df["window_end"].max()
        best_window = None
        best_trigger_count = 0
        current_start = 0.0

        while current_start < max_time:
            current_end = current_start + summary_window
            mask = (device_df["window_start"] >= current_start) & (
                device_df["window_start"] < current_end
            )
            window_df = device_df[mask]

            trigger_count = sum(window_df["predicted"] == "triggering")

            if trigger_count > best_trigger_count:
                best_trigger_count = trigger_count
                best_window = {
                    "device": device,
                    "start": round(float(current_start), 3),
                    "end": round(float(current_end), 3),
                    "trigger_count": int(trigger_count),
                }

            current_start += summary_window

        if best_window:
            trigger_sequence.append(best_window)

    # Sort by time
    trigger_sequence = sorted(trigger_sequence, key=lambda x: x["start"])

    # Add order number
    for idx, item in enumerate(trigger_sequence, start=1):
        item["order"] = idx

    # Save JSON output
    with open("trigger_sequence.json", "w") as f:
        json.dump(trigger_sequence, f, indent=4)

    return trigger_sequence


def format_device_name(device_name):
    """Format device name for display - capitalize and replace underscores with spaces"""
    if not device_name:
        return "Unknown"
    # Replace underscores with spaces and capitalize each word
    formatted_name = device_name.replace("_", " ").title()
    return formatted_name


def analyze_device_actions(detected_devices, pcap_file, config_json_path):
    """
    Analyze device actions based on detected devices from fingerprinting

    Args:
        detected_devices: List of devices from device fingerprinting
        pcap_file: Path to the pcap file
        config_json_path: Path to device_config.json

    Returns:
        List of devices with action analysis results
    """
    try:
        # Read packets
        packets = rdpcap(pcap_file)

        # Load device configuration
        with open(config_json_path, "r") as f:
            device_configs = json.load(f)

        # Create a mapping of MAC addresses to device configs
        mac_to_config = {}
        for config in device_configs:
            mac_to_config[config["mac1"].lower()] = config

        # Process trigger sequence
        trigger_sequence = process_pcap_auto(
            pcap_file, config_json_path, summary_window=1.0
        )

        # Create a mapping of device names to trigger counts
        trigger_map = {}
        if trigger_sequence:
            for trigger in trigger_sequence:
                device_name = trigger["device"]
                if device_name not in trigger_map:
                    trigger_map[device_name] = 0
                trigger_map[device_name] += trigger["trigger_count"]

        # Enhance detected devices with action analysis
        enriched_devices = []
        for device in detected_devices:
            device_copy = device.copy()
            mac_lower = device["mac_address"].lower()

            # Get original device name (before formatting)
            original_name = None
            for config in device_configs:
                if config["mac1"].lower() == mac_lower:
                    original_name = config["device_name"]
                    break

            # Determine if device is triggerable
            is_triggerable = original_name in [
                "plug",
                "wall_plug",
                "tabel_lamp",
                "switch",
                "motion_sensor",
                "door_sensor",
                "air_purefier",
            ]

            if is_triggerable and original_name:
                # Get trigger count
                trigger_count = trigger_map.get(original_name, 0)
                device_copy["is_active"] = device["connected_to_router"]
                device_copy["is_triggered"] = trigger_count > 0
                device_copy["trigger_count"] = trigger_count
                device_copy["actions"] = []

                if trigger_count > 0:
                    device_copy["actions"].append(f"Triggered (Count: {trigger_count})")

                # Add packet type actions
                if device["packet_types"]["data"]["count"] > 0:
                    device_copy["actions"].append("Data Transmission")
                if device["packet_types"]["management"]["count"] > 0:
                    device_copy["actions"].append("Management Packets")
                if device["packet_types"]["control"]["count"] > 0:
                    device_copy["actions"].append("Control Packets")

            else:
                # Non-triggerable devices (cameras, etc.)
                device_copy["is_active"] = device["connected_to_router"]
                device_copy["is_triggered"] = None  # Not applicable for cameras
                device_copy["trigger_count"] = 0
                device_copy["actions"] = []

                # Add packet type actions
                if device["packet_types"]["data"]["count"] > 0:
                    device_copy["actions"].append("Data Transmission")
                if device["packet_types"]["management"]["count"] > 0:
                    device_copy["actions"].append("Management Packets")
                if device["packet_types"]["control"]["count"] > 0:
                    device_copy["actions"].append("Control Packets")

            enriched_devices.append(device_copy)

        return enriched_devices

    except Exception as e:
        print(f"[ERROR] Device action analysis failed: {str(e)}")
        raise e


@deviceaction_bp.route("/analyze-actions", methods=["POST"])
def analyze_actions_endpoint():
    """
    Endpoint to analyze device actions based on fingerprinted devices
    Expects JSON body with:
    - devices: List of detected devices from fingerprinting
    - pcap_file: Path to the pcap file (optional, will use latest if not provided)
    """
    try:
        data = request.get_json()

        if not data or "devices" not in data:
            return jsonify({"error": "No devices provided"}), 400

        detected_devices = data["devices"]

        # Determine pcap file path
        if "pcap_file" in data and data["pcap_file"]:
            pcap_file = data["pcap_file"]
        else:
            # Use latest file from downloads
            downloads_dir = r"D:\University of Ruhuna FoE\Common Modules\EE7802 Undergraduate Project\Shadow-Scan\backend\downloads"
            capture_files = [
                f for f in os.listdir(downloads_dir) if f.endswith((".cap", ".pcap"))
            ]
            if not capture_files:
                return jsonify({"error": "No capture files found"}), 404
            pcap_file = os.path.join(downloads_dir, capture_files[0])

        # Config file path
        config_json = r"D:\University of Ruhuna FoE\Common Modules\EE7802 Undergraduate Project\Shadow-Scan\backend\device_config.json"

        if not os.path.exists(config_json):
            return jsonify({"error": "Device configuration file not found"}), 404

        print(f"[*] Analyzing device actions for {len(detected_devices)} devices")
        print(f"[*] Using pcap file: {pcap_file}")

        # Analyze device actions
        enriched_devices = analyze_device_actions(
            detected_devices, pcap_file, config_json
        )

        # Calculate statistics
        active_count = sum(1 for d in enriched_devices if d.get("is_active", False))
        triggered_count = sum(
            1 for d in enriched_devices if d.get("is_triggered", False)
        )

        response = {
            "status": "success",
            "total_devices": len(enriched_devices),
            "active_devices": active_count,
            "triggered_devices": triggered_count,
            "devices": enriched_devices,
            "pcap_file": pcap_file,
        }

        print(
            f"[*] Action analysis complete. {triggered_count} devices triggered out of {len(enriched_devices)} total"
        )
        return jsonify(response)

    except Exception as e:
        print(f"[ERROR] Action analysis endpoint failed: {str(e)}")
        return jsonify({"status": "error", "error": str(e)}), 500


# # Main

# if __name__ == "__main__":
#     config_json = "device_config.json"
#     pcap_file = "capture-03.cap"
#     process_pcap_auto(pcap_file, config_json, summary_window=1)
