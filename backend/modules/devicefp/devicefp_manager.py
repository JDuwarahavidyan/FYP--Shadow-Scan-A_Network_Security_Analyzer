from flask import Blueprint, request, jsonify
import os
import time
from scapy.all import rdpcap, Dot11
from collections import defaultdict
import requests

devicefp_bp = Blueprint("devicefp", __name__)

# -------------------------------------------------------------------
# Known device MACs
# -------------------------------------------------------------------
DEVICE_MACS = {
    "plug": ["c0:f8:53:de:cf:2a", "c0:f8:53:df:18:ea", "3c:0b:59:4b:8c:27"],
    "wall_socket": ["d8:d6:68:06:6d:65", "d8:d6:68:97:fb:2d"],
    "tabel_lamp": ["3c:0b:59:8f:25:42"],
    "switch": ["38:2c:e5:1d:02:fb", "38:2c:e5:1c:cf:6e"],
    "air_purifier": ["50:ec:50:94:7b:a3"],
    "motion_sensor": ["f8:17:2d:b6:38:de", "f8:17:2d:b4:3d:5a"],
    "door_sensor": ["18:de:50:54:8e:e9", "18:de:50:50:39:37"],
    "baby_cam": ["78:8b:2a:9c:80:1e"],
    "camera": ["5c:4e:ee:ce:f8:3b"],
    "power_strip": ["fc:3c:d7:53:f6:79"],
}

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    mac = mac.replace(" ", "").replace("-", ":").lower()
    bare = mac.replace(":", "")
    if len(bare) == 12:
        mac = ":".join([bare[i : i + 2] for i in range(0, 12, 2)])
    return mac


def is_multicast_mac(mac: str) -> bool:
    """
    Multicast MACs have the least significant bit of the first octet set.
    This will catch 01:00:5e:.. (IPv4 mcast), 33:33:.. (IPv6 mcast), etc.
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x01)
    except Exception:
        return False


def get_vendor_from_api(mac_address: str) -> str | None:
    try:
        url = f"https://api.maclookup.app/v2/macs/{mac_address}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("found") and "company" in data:
                return data["company"]
        return None
    except Exception:
        return None


def calculate_confidence(stats: dict) -> float:
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


def is_locally_administered(mac: str) -> bool:
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except Exception:
        return False


def mac_to_oui(mac: str | None) -> str | None:
    if not mac:
        return None
    parts = mac.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return None


def build_mac_mappings():
    mac_to_device = {}
    oui_fallback_map = defaultdict(list)
    configured_macs = set()

    for device_name, mac_list in DEVICE_MACS.items():
        for mac in mac_list:
            nm = normalize_mac(mac)
            if not nm:
                continue
            mac_to_device[nm] = device_name
            configured_macs.add(nm)
            oui = mac_to_oui(nm)
            if oui:
                oui_fallback_map[oui].append(device_name)

    return mac_to_device, dict(oui_fallback_map), configured_macs

# -------------------------------------------------------------------
# Core MAC filter: ONLY devices connected to our router BSSID,
# ignore multicast/broadcast/randomized etc.
# -------------------------------------------------------------------
def should_process_mac(
    mac_addr,
    mac_to_device,
    normalized_bssid,
    src_mac,
    dst_mac,
    bss_mac,
    packet_type,
    packet_subtype,
    include_unknown=True,
    ignore_randomized=False,
    oui_fallback_map=None,
    use_oui_fallback=False,
):
    if not mac_addr:
        return False, None

    mac_addr = mac_addr.lower()

    # Skip broadcast
    if mac_addr == "ff:ff:ff:ff:ff:ff":
        return False, None

    # Skip multicast (e.g., 01:00:5e:.., 33:33:..)
    if is_multicast_mac(mac_addr):
        # DEBUG
        # print(f"[-] Skipping multicast MAC {mac_addr}")
        return False, None

    # Skip router's own MAC – we don't fingerprint the AP itself
    if mac_addr == normalized_bssid:
        return False, None

    # Optional: skip locally-administered / randomized MACs
    if ignore_randomized and is_locally_administered(mac_addr):
        # DEBUG
        # print(f"[-] Skipping randomized MAC {mac_addr}")
        return False, None

    # If it's in our configured list, always process
    if mac_addr in mac_to_device:
        return True, mac_to_device[mac_addr]

    # OUI fallback: treat same OUI as same device type
    if use_oui_fallback and oui_fallback_map:
        oui = mac_to_oui(mac_addr)
        if oui and oui in oui_fallback_map:
            mapped = oui_fallback_map[oui][0]
            return True, mapped + " (oui_fallback)"

    # If we don't want unknowns at all, stop here
    if not include_unknown:
        return False, None

    # For unknown MACs: only accept as "new_device" if we see them in
    # actual traffic WITH the router BSSID (data or association/auth).
    connected = False
    if bss_mac and normalized_bssid and bss_mac == normalized_bssid:
        if src_mac == mac_addr or dst_mac == mac_addr:
            if packet_type == 2:  # data frame
                connected = True
            else:
                # management frames that are part of association/auth
                if packet_type == 0 and packet_subtype in (0, 1, 2, 3, 11):
                    connected = True

    if connected:
        return True, "new_device"

    return False, None

# -------------------------------------------------------------------
# Main fingerprint analysis
# -------------------------------------------------------------------
def analyze_device_fingerprints(
    file_path,
    bssid=None,
    include_unknown=True,
    ignore_randomized=False,
    oui_fallback=False,
):
    try:
        if not bssid:
            bssid = "14:eb:b6:be:d7:1e"

        print(f"[*] Reading pcap file: {file_path}")
        packets = rdpcap(file_path)
        print(f"[*] Total packets in file: {len(packets)}")

        mac_to_device, oui_fallback_map, configured_macs = build_mac_mappings()
        normalized_bssid = normalize_mac(bssid)

        print(f"[*] Looking for router BSSID: {normalized_bssid}")
        print(f"[*] Configured devices: {len(DEVICE_MACS)}")
        print(f"[*] Configured MAC addresses: {len(mac_to_device)}")
        if oui_fallback:
            print(f"[*] OUI fallback enabled with {len(oui_fallback_map)} OUIs.")

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

        packets_processed = 0
        router_packets = 0

        total_data_packets = 0
        total_management_packets = 0
        total_control_packets = 0

        processed_macs = set()
        observed_configured = set()
        discovered_new_devices = set()

        # -----------------------------------------------------------
        # Scan packets – ONLY keep frames where the router BSSID
        # appears in src/dst/bss. Everything else is skipped.
        # -----------------------------------------------------------
        for packet in packets:
            packets_processed += 1

            if not packet.haslayer(Dot11):
                continue

            src_mac = normalize_mac(packet[Dot11].addr2) if packet[Dot11].addr2 else None
            dst_mac = normalize_mac(packet[Dot11].addr1) if packet[Dot11].addr1 else None
            bss_mac = normalize_mac(packet[Dot11].addr3) if packet[Dot11].addr3 else None

            # Skip frames that do NOT involve the router at all
            if normalized_bssid not in [src_mac, dst_mac, bss_mac]:
                continue

            router_packets += 1

            timestamp = packet.time
            try:
                ptype = int(packet[Dot11].type)
                psub = int(packet[Dot11].subtype)
            except Exception:
                ptype = None
                psub = None

            if ptype == 0:
                frame_type = "management"
                total_management_packets += 1
            elif ptype == 1:
                frame_type = "control"
                total_control_packets += 1
            elif ptype == 2:
                frame_type = "data"
                total_data_packets += 1
            else:
                frame_type = "unknown"

            signal_strength = getattr(packet, "dBm_AntSignal", None)

            # Try src, dst and bss MACs – but they will be filtered
            # further by should_process_mac (multicast, router, etc.)
            for mac_addr in [src_mac, dst_mac, bss_mac]:
                if not mac_addr:
                    continue

                if mac_addr == normalized_bssid:
                    continue

                process, device_name = should_process_mac(
                    mac_addr=mac_addr,
                    mac_to_device=mac_to_device,
                    normalized_bssid=normalized_bssid,
                    src_mac=src_mac,
                    dst_mac=dst_mac,
                    bss_mac=bss_mac,
                    packet_type=ptype,
                    packet_subtype=psub,
                    include_unknown=include_unknown,
                    ignore_randomized=ignore_randomized,
                    oui_fallback_map=oui_fallback_map,
                    use_oui_fallback=oui_fallback,
                )

                if not process:
                    continue

                stats = device_stats[mac_addr]

                if mac_addr not in processed_macs:
                    processed_macs.add(mac_addr)

                    if mac_addr in configured_macs:
                        observed_configured.add(mac_addr)

                    if device_name == "new_device":
                        discovered_new_devices.add(mac_addr)

                    stats["device_name"] = device_name
                    stats["mac"] = mac_addr

                    if stats["first_seen"] is None:
                        stats["first_seen"] = timestamp

                    if stats["vendor"] == "Unknown":
                        api_vendor = get_vendor_from_api(mac_addr)
                        if api_vendor:
                            stats["vendor"] = api_vendor
                            print(f"[*] Found vendor for {device_name} ({mac_addr}): {api_vendor}")

                stats["packet_count"] += 1
                if frame_type == "data":
                    stats["data_packets"] += 1
                elif frame_type == "management":
                    stats["management_packets"] += 1
                elif frame_type == "control":
                    stats["control_packets"] += 1

                if stats["last_seen"] is None or timestamp > stats["last_seen"]:
                    stats["last_seen"] = timestamp

                if signal_strength is not None:
                    stats["signal_strength"].append(signal_strength)

                stats["connected_to_router"] = True

        print(f"[*] Scanned {packets_processed} packets (router-involved frames: {router_packets})")
        print(
            f"[*] Totals: data={total_data_packets}, "
            f"management={total_management_packets}, control={total_control_packets}"
        )

        # ------------------------------------------------------------------
        # Build nice output device list
        # ------------------------------------------------------------------
        base_counts = defaultdict(int)
        for mac_addr, stats in device_stats.items():
            if stats["packet_count"] <= 0:
                continue
            base_type = stats["device_name"] or "unknown"
            base_type = base_type.split("(")[0].strip()
            base_type = base_type.split()[0].strip() if base_type.split() else base_type
            base_counts[base_type] += 1

        type_indices = defaultdict(int)
        results = []

        for mac_addr, stats in device_stats.items():
            if stats["packet_count"] <= 0:
                continue

            base_type = stats["device_name"]
            if not base_type:
                base_type = "unknown"
            else:
                base_type = base_type.split("(")[0].strip()
                base_type = base_type.split()[0].strip() if base_type.split() else base_type

            if base_type == "baby_cam":
                output_device_name = "Baby Cam"
                device_type_for_output = "Camera"
            else:
                device_type_for_output = base_type.title()
                if base_counts.get(base_type, 0) > 1:
                    type_indices[base_type] += 1
                    idx = type_indices[base_type]
                    output_device_name = f"{device_type_for_output} {idx}"
                else:
                    output_device_name = device_type_for_output

            avg_signal = None
            if stats["signal_strength"]:
                avg_signal = sum(stats["signal_strength"]) / len(stats["signal_strength"])

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
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(stats["first_seen"])))
                if stats["first_seen"]
                else None
            )
            last_seen = (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(stats["last_seen"])))
                if stats["last_seen"]
                else None
            )

            # DEBUG: show raw timestamps and formatted ones
            print(
                f"[*] Device {output_device_name} ({stats['mac']}): "
                f"first_seen_raw={stats['first_seen']} last_seen_raw={stats['last_seen']} "
                f"first_seen={first_seen} last_seen={last_seen}"
            )

            device_info = {
                "device_name": output_device_name,
                "device_type": device_type_for_output,
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
                "avg_signal_strength": round(avg_signal, 2) if avg_signal is not None else None,
                "connected_to_router": stats["connected_to_router"],
                "confidence": calculate_confidence(stats),
            }
            results.append(device_info)

        not_seen = (
            sorted(list(configured_macs - observed_configured))
            if "observed_configured" in locals()
            else []
        )
        known_observed = (
            sorted(list(observed_configured))
            if "observed_configured" in locals()
            else []
        )
        new_devices = (
            sorted(list(discovered_new_devices))
            if "discovered_new_devices" in locals()
            else []
        )

        diagnostics = {
            "configured_macs_total": len(configured_macs),
            "configured_macs_not_seen": not_seen,
            "configured_macs_observed": known_observed,
            "new_devices": new_devices,
            "packets_processed": packets_processed,
            "router_packets": router_packets,
            "total_data_packets": total_data_packets,
            "total_management_packets": total_management_packets,
            "total_control_packets": total_control_packets,
        }

        return {"devices": results, "diagnostics": diagnostics}

    except Exception as e:
        print(f"[ERROR] {e}")
        raise e

# -------------------------------------------------------------------
# Flask route
# -------------------------------------------------------------------
@devicefp_bp.route("/analyze-latest", methods=["POST"])
def analyze_latest_capture():
    try:
        data = request.get_json() or {}
        bssid = data.get("bssid")
        include_unknown = data.get("include_unknown", True)
        ignore_randomized = data.get("ignore_randomized", False)
        oui_fallback = data.get("oui_fallback", False)

        downloads_dir = r"D:\University of Ruhuna FoE\Common Modules\EE7802 Undergraduate Project\Shadow-Scan\backend\downloads"
        if not os.path.exists(downloads_dir):
            return jsonify({"error": "Downloads directory not found"}), 404

        capture_files = [f for f in os.listdir(downloads_dir) if f.endswith((".cap", ".pcap"))]
        if not capture_files:
            return jsonify({"error": "No capture files found in downloads directory"}), 404

        capture_files_full = [os.path.join(downloads_dir, f) for f in capture_files]
        latest_file = max(capture_files_full, key=os.path.getmtime)

        print(f"[*] Analyzing newest file: {latest_file}")
        if bssid:
            print(f"[*] Using provided BSSID: {bssid}")
        else:
            print("[*] Using default BSSID")

        analysis = analyze_device_fingerprints(
            latest_file,
            bssid=bssid,
            include_unknown=include_unknown,
            ignore_randomized=ignore_randomized,
            oui_fallback=oui_fallback,
        )

        response = {
            "status": "success",
            "total_devices_found": len(analysis["devices"]),
            "router_bssid": bssid if bssid else "14:eb:b6:be:d7:1e",
            "devices": analysis["devices"],
            "diagnostics": analysis["diagnostics"],
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_analyzed": latest_file,
            "available_files": capture_files,
        }

        print(f"[*] Analysis complete. Found {len(analysis['devices'])} devices")
        return jsonify(response)

    except Exception as e:
        print(f"[ERROR] Analysis failed: {str(e)}")
        return jsonify({"status": "error", "error": str(e)}), 500
