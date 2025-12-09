from flask import Blueprint, request, jsonify
import os
import time
from scapy.all import rdpcap, Dot11
import pandas as pd
import numpy as np
import math
import re

deviceaction_bp = Blueprint("deviceaction", __name__)


def extract_features_for_mac_pair(packets, mac1, mac2, label, window_size=1.0):
    pkt_list = []
    if not packets:
        return pd.DataFrame()
    t0 = float(packets[0].time)
    last_pkt_time = None

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]
        src, dst = dot11.addr2, dot11.addr1

        if label == "air_purifier":
            if ((src, dst) not in [(mac1, mac2), (mac2, mac1)]) and (dst != mac1):
                continue
        else:
            if (src, dst) not in [(mac1, mac2), (mac2, mac1)]:
                continue

        if last_pkt_time is not None:
            iat = float(pkt.time) - last_pkt_time
            last_len = pkt_list[-1]["frame_len"]
            ref1 = 1 if (len(pkt) == last_len == 10 and iat < 0.001) else 0
        else:
            ref1 = 0

        last_pkt_time = float(pkt.time)

        pkt_list.append(
            {
                "time": float(pkt.time) - t0,
                "frame_len": len(pkt),
                "ref": 1 if len(pkt) in [269, 91] else 0,
                "ref1": ref1,
                "ref2": 1 if len(pkt) in [301, 269, 317] else 0,
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
        ref2 = 1 if any(p["ref2"] == 1 for p in window_pkts) else 0

        features.append(
            {
                "label": label,
                "window_start": times[i],
                "window_end": end_time,
                "ref": ref,
                "ref1": ref1,
                "ref2": ref2,
            }
        )

    return pd.DataFrame(features)


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

    elif device_name == "air_purifier":
        return "triggering" if row.get("ref1") == 1 else "not_triggering"

    elif device_name in ["power_strip"]:
        return "triggering" if row.get("ref2") == 1 else "not_triggering"

    else:
        return "unknown_device"


def normalize_mac(mac):
    if not mac:
        return None
    mac = mac.replace(" ", "").replace("-", ":").lower()
    bare = mac.replace(":", "")
    if len(bare) == 12:
        mac = ":".join([bare[i : i + 2] for i in range(0, 12, 2)])
    return mac


def normalize_label(name_raw):
    if not name_raw:
        return ""
    return name_raw.lower().replace(" ", "_")


def format_device_name_for_output(name_raw):
    if not name_raw:
        return ""
    s = str(name_raw).strip().replace("_", " ")
    return " ".join(part.capitalize() for part in s.split())


def detect_traffic_type_from_counts(packet_types):
    if not packet_types or not isinstance(packet_types, dict):
        return "Unknown"

    ctrl = packet_types.get("control", {}).get("count", 0)
    data = packet_types.get("data", {}).get("count", 0)
    mgmt = packet_types.get("management", {}).get("count", 0)
    total = ctrl + data + mgmt
    if total == 0:
        return "No Traffic"

    ctrl_p = ctrl / total * 100
    data_p = data / total * 100
    mgmt_p = mgmt / total * 100

    if mgmt_p > 70 and data_p < 5:
        return "Beacon / Association"
    if data_p > 70:
        return "High Data / Streaming"
    if data_p > 30 and data_p <= 70:
        return "Data Transmission"
    if data_p >= 5 and data_p <= 30 and mgmt_p < 40:
        return "IoT Background Traffic"
    if ctrl_p > 50 and data_p < 10:
        return "Keep-Alive / Heartbeat"
    if (mgmt_p > 20 and data_p > 20) or (ctrl_p > 20 and data_p > 20):
        return "Mixed Activity"
    return "Unknown"


def calculate_prediction_confidence(
    trigger_count, total_windows, data_packet_ratio, total_packets
):
    if total_windows and total_windows > 0:
        trigger_density = trigger_count / float(total_windows)
        trigger_density = max(0.0, min(1.0, trigger_density))
    else:
        trigger_density = 1.0 if trigger_count > 0 else 0.0

    try:
        if total_windows and total_windows > 0:
            pkt_per_window = float(total_packets) / float(total_windows)
        else:
            pkt_per_window = float(total_packets)
    except Exception:
        pkt_per_window = float(total_packets or 0)

    try:
        packet_strength = 1.0 / (1.0 + math.exp(-0.7 * (pkt_per_window - 1.0)))
    except Exception:
        packet_strength = 0.0
    packet_strength = max(0.0, min(1.0, packet_strength))

    try:
        dr = float(data_packet_ratio) if data_packet_ratio is not None else 0.0
    except Exception:
        dr = 0.0
    dr = max(0.0, min(1.0, dr))

    score = 0.6 * trigger_density + 0.25 * packet_strength + 0.15 * dr
    score = max(0.0, min(1.0, score))
    return round(score, 3)


def detect_actions_for_device(
    frontend_info, device_df, filtered_packets, mac, router_mac, summary_window=1.0
):
    actions = []
    if not mac:
        return actions

    packet_types = (
        frontend_info.get("packet_types") or frontend_info.get("packetTypes") or None
    )
    data_count = mgmt_count = ctrl_count = 0
    total_count = 0

    if packet_types and isinstance(packet_types, dict):
        data_count = packet_types.get("data", {}).get("count", 0)
        mgmt_count = packet_types.get("management", {}).get("count", 0)
        ctrl_count = packet_types.get("control", {}).get("count", 0)
        total_count = data_count + mgmt_count + ctrl_count

    if total_count == 0:
        for pkt in filtered_packets:
            if not pkt.haslayer(Dot11):
                continue
            dot11 = pkt[Dot11]
            a1 = normalize_mac(dot11.addr1) if dot11.addr1 else None
            a2 = normalize_mac(dot11.addr2) if dot11.addr2 else None
            a3 = normalize_mac(dot11.addr3) if dot11.addr3 else None
            addrs = {a for a in (a1, a2, a3) if a}
            if mac not in addrs:
                continue
            t = dot11.type
            if t == 0:
                mgmt_count += 1
            elif t == 1:
                ctrl_count += 1
            elif t == 2:
                data_count += 1
        total_count = data_count + mgmt_count + ctrl_count

    data_ratio = (data_count / total_count) if total_count > 0 else 0.0
    mgmt_ratio = (mgmt_count / total_count) if total_count > 0 else 0.0
    ctrl_ratio = (ctrl_count / total_count) if total_count > 0 else 0.0
    total_packets = total_count

    pkt_times = []
    frame_lens = []
    for pkt in filtered_packets:
        if not pkt.haslayer(Dot11):
            continue
        dot11 = pkt[Dot11]
        a1 = normalize_mac(dot11.addr1) if dot11.addr1 else None
        a2 = normalize_mac(dot11.addr2) if dot11.addr2 else None
        a3 = normalize_mac(dot11.addr3) if dot11.addr3 else None
        addrs = {a for a in (a1, a2, a3) if a}
        if mac not in addrs:
            continue
        pkt_times.append(float(pkt.time))
        frame_lens.append(len(pkt))

    avg_frame_len = float(sum(frame_lens)) / len(frame_lens) if frame_lens else None
    pkt_rate = 0.0
    if pkt_times and len(pkt_times) > 1:
        duration = max(pkt_times) - min(pkt_times)
        if duration > 0:
            pkt_rate = len(pkt_times) / duration

    total_windows = 0
    triggering_windows = 0
    if device_df is not None and not device_df.empty:
        max_time = device_df["window_end"].max()
        total_windows = (
            int(math.ceil(max_time / summary_window))
            if max_time and summary_window > 0
            else 0
        )
        triggering_windows = (
            int(sum(device_df.get("ref", 0) == 1) + sum(device_df.get("ref1", 0) == 1))
            if total_windows > 0
            else 0
        )

    def norm01(x, mn, mx):
        if mx <= mn:
            return 0.0
        return max(0.0, min(1.0, (x - mn) / float(mx - mn)))

    if data_ratio > 0.7 and pkt_rate > 1.0 and avg_frame_len and avg_frame_len > 400:
        conf = (
            0.6 * norm01(data_ratio, 0.7, 1.0)
            + 0.3 * norm01(pkt_rate, 1.0, 10.0)
            + 0.1 * norm01(avg_frame_len, 400, 1500)
        )
        actions.append(
            {
                "action": "High Data / Streaming",
                "confidence": round(max(0.0, min(1.0, conf)), 3),
                "evidence": {
                    "data_ratio": round(data_ratio, 3),
                    "avg_frame_len": round(avg_frame_len, 1) if avg_frame_len else None,
                    "pkt_rate": round(pkt_rate, 2),
                    "total_packets": int(total_packets),
                },
            }
        )

    if data_ratio > 0.3 and total_packets > 20:
        conf = (
            0.5 * norm01(data_ratio, 0.3, 0.7)
            + 0.3 * norm01(total_packets, 20, 500)
            + 0.2 * norm01(avg_frame_len or 0, 80, 1000)
        )
        actions.append(
            {
                "action": "Data Transmission",
                "confidence": round(max(0.0, min(1.0, conf)), 3),
                "evidence": {
                    "data_ratio": round(data_ratio, 3),
                    "total_packets": int(total_packets),
                    "avg_frame_len": round(avg_frame_len, 1) if avg_frame_len else None,
                },
            }
        )

    if mgmt_ratio > 0.6 or (mgmt_ratio > 0.3 and total_packets < 50):
        conf = 0.6 * norm01(mgmt_ratio, 0.3, 1.0) + 0.4 * norm01(total_packets, 0, 200)
        actions.append(
            {
                "action": "Management Packets / Beaconing",
                "confidence": round(max(0.0, min(1.0, conf)), 3),
                "evidence": {
                    "management_ratio": round(mgmt_ratio, 3),
                    "total_packets": int(total_packets),
                },
            }
        )

    probe_count = 0
    for pkt in filtered_packets:
        if not pkt.haslayer(Dot11):
            continue
        dot11 = pkt[Dot11]
        a1 = normalize_mac(dot11.addr1) if dot11.addr1 else None
        a2 = normalize_mac(dot11.addr2) if dot11.addr2 else None
        a3 = normalize_mac(dot11.addr3) if dot11.addr3 else None
        addrs = {a for a in (a1, a2, a3) if a}
        if mac not in addrs:
            continue
        try:
            if dot11.type == 0 and dot11.subtype == 4:
                probe_count += 1
        except Exception:
            pass
    if probe_count > 5:
        conf = min(1.0, probe_count / 50.0 + 0.3)
        actions.append(
            {
                "action": "Probe / Scanning",
                "confidence": round(conf, 3),
                "evidence": {"probe_count": int(probe_count)},
            }
        )

    assoc_count = 0
    auth_count = 0
    for pkt in filtered_packets:
        if not pkt.haslayer(Dot11):
            continue
        dot11 = pkt[Dot11]
        a1 = normalize_mac(dot11.addr1) if dot11.addr1 else None
        a2 = normalize_mac(dot11.addr2) if dot11.addr2 else None
        a3 = normalize_mac(dot11.addr3) if dot11.addr3 else None
        addrs = {a for a in (a1, a2, a3) if a}
        if mac not in addrs:
            continue
        try:
            if dot11.type == 0 and dot11.subtype in (0, 11):
                assoc_count += 1
            if dot11.type == 0 and dot11.subtype == 11:
                auth_count += 1
        except Exception:
            pass
    if assoc_count + auth_count > 2:
        conf = min(1.0, (assoc_count + auth_count) / 10.0 + 0.4)
        actions.append(
            {
                "action": "Association / Authentication (Pairing)",
                "confidence": round(conf, 3),
                "evidence": {
                    "assoc_count": int(assoc_count),
                    "auth_count": int(auth_count),
                },
            }
        )

    small_frames = sum(1 for l in frame_lens if l < 60) if frame_lens else 0
    small_ratio = (small_frames / len(frame_lens)) if frame_lens else 0.0
    if small_ratio > 0.5 and total_packets > 10 and data_ratio < 0.2:
        conf = 0.6 * norm01(small_ratio, 0.5, 1.0) + 0.4 * norm01(
            total_packets, 10, 200
        )
        actions.append(
            {
                "action": "Keep-Alive / Heartbeat",
                "confidence": round(max(0.0, min(1.0, conf)), 3),
                "evidence": {
                    "small_frame_ratio": round(small_ratio, 3),
                    "total_packets": int(total_packets),
                },
            }
        )

    if ctrl_ratio > 0.25:
        conf = min(1.0, ctrl_ratio * 1.2)
        actions.append(
            {
                "action": "Control Frames (ACK / RTS / CTS)",
                "confidence": round(conf, 3),
                "evidence": {
                    "control_ratio": round(ctrl_ratio, 3),
                    "total_packets": int(total_packets),
                },
            }
        )

    large_frames = sum(1 for l in frame_lens if l > 1000) if frame_lens else 0
    if data_ratio > 0.6 and large_frames > 50:
        conf = min(1.0, 0.4 + norm01(large_frames, 50, 500))
        actions.append(
            {
                "action": "Firmware / OTA (possible)",
                "confidence": round(conf, 3),
                "evidence": {
                    "large_frames": int(large_frames),
                    "data_ratio": round(data_ratio, 3),
                },
            }
        )

    vendor = (
        (frontend_info.get("vendor") or frontend_info.get("manufacturer") or "").lower()
        if frontend_info
        else ""
    )
    is_camera_vendor = any(
        k in vendor
        for k in [
            "camera",
            "hikvision",
            "dahua",
            "mi",
            "xiaomi",
            "zheng",
            "zyxel",
            "alibeam",
            "alobeam",
            "zheng",
        ]
    )
    if (
        data_ratio > 0.6
        and pkt_rate > 0.5
        and (is_camera_vendor or avg_frame_len and avg_frame_len > 400)
    ):
        conf = (
            0.5 * norm01(data_ratio, 0.6, 1.0)
            + 0.3 * norm01(pkt_rate, 0.5, 10.0)
            + 0.2 * (0.9 if is_camera_vendor else 0.3)
        )
        actions.append(
            {
                "action": "Camera Streaming (possible)",
                "confidence": round(max(0.0, min(1.0, conf)), 3),
                "evidence": {
                    "data_ratio": round(data_ratio, 3),
                    "pkt_rate": round(pkt_rate, 2),
                    "vendor": frontend_info.get("vendor"),
                },
            }
        )

    mcast_count = sum(
        1
        for pkt in filtered_packets
        if pkt.haslayer(Dot11)
        and normalize_mac(pkt[Dot11].addr1)
        and (
            normalize_mac(pkt[Dot11].addr1).startswith("ff:ff:ff")
            or normalize_mac(pkt[Dot11].addr1).startswith("33:33")
        )
        and mac
        in {
            normalize_mac(pkt[Dot11].addr1),
            normalize_mac(pkt[Dot11].addr2),
            normalize_mac(pkt[Dot11].addr3),
        }
    )
    if mcast_count > 5:
        conf = min(1.0, 0.3 + norm01(mcast_count, 5, 200))
        actions.append(
            {
                "action": "ARP / Local Discovery (possible)",
                "confidence": round(conf, 3),
                "evidence": {"mcast_count": int(mcast_count)},
            }
        )

    actuation_windows = 0
    if device_df is not None and not device_df.empty:
        for _, r in device_df.iterrows():
            if r.get("ref") == 1 or r.get("ref1") == 1:
                actuation_windows += 1
    if actuation_windows > 0 and (total_packets < 200 or data_ratio < 0.2):
        conf = min(1.0, 0.3 + norm01(actuation_windows, 1, 10))
        actions.append(
            {
                "action": "Power Toggle / Actuation",
                "confidence": round(conf, 3),
                "evidence": {
                    "actuation_windows": int(actuation_windows),
                    "total_packets": int(total_packets),
                },
            }
        )

    spike_detected = False
    if device_df is not None and not device_df.empty:
        counts = [
            (r.get("ref") == 1 or r.get("ref1") == 1) for _, r in device_df.iterrows()
        ]
        spike_detected = any(counts)
    if spike_detected and (total_packets < 300):
        conf = 0.5
        actions.append(
            {
                "action": "Motion Trigger (for sensors)",
                "confidence": round(conf, 3),
                "evidence": {
                    "spike_detected": True,
                    "total_packets": int(total_packets),
                },
            }
        )

    if total_packets < 10 and data_ratio < 0.2:
        conf = min(1.0, 0.8 - 0.05 * total_packets)
        actions.append(
            {
                "action": "Idle / Low Activity",
                "confidence": round(conf, 3),
                "evidence": {"total_packets": int(total_packets)},
            }
        )

    if (data_ratio > 0.15 and mgmt_ratio > 0.15 and ctrl_ratio > 0.05) or (
        data_ratio > 0.2 and mgmt_ratio > 0.2
    ):
        conf = min(1.0, 0.4 + 0.5 * (data_ratio + mgmt_ratio))
        actions.append(
            {
                "action": "Mixed Activity",
                "confidence": round(conf, 3),
                "evidence": {
                    "data_ratio": round(data_ratio, 3),
                    "management_ratio": round(mgmt_ratio, 3),
                    "control_ratio": round(ctrl_ratio, 3),
                },
            }
        )

    actions = sorted(actions, key=lambda x: x.get("confidence", 0), reverse=True)
    return actions


def process_pcap_auto(
    pcap_file,
    devices_from_frontend,
    window_size=1.0,
    summary_window=0.5,
    router_bssid=None,
):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        raise RuntimeError(f"Failed to read pcap '{pcap_file}': {e}")

    device_configs = []
    configured_macs = set()
    frontend_map = {}
    type_to_entries = {}

    for d in devices_from_frontend:
        mac = normalize_mac(
            d.get("mac_address") or d.get("mac") or d.get("macAddress") or ""
        )
        if not mac:
            continue
        ui_name = d.get("device_name") or d.get("device") or d.get("label") or ""
        device_type = (
            d.get("device_type")
            or d.get("deviceType")
            or normalize_label(ui_name)
            or ""
        )
        device_type = normalize_label(device_type)

        device_configs.append(
            {
                "device_name": ui_name,
                "device_type": device_type,
                "mac1": mac,
                "mac2": None,
                "label": device_type,
            }
        )
        configured_macs.add(mac)

        d_copy = dict(d)
        d_copy["device_type"] = device_type
        d_copy["device_name"] = ui_name
        frontend_map[mac] = d_copy

        if device_type not in type_to_entries:
            type_to_entries[device_type] = []
        type_to_entries[device_type].append({"mac": mac, "ui_name": ui_name})

    def make_display_name_for_mac(label, ui_name, mac):
        friendly_type = format_device_name_for_output(label)
        entries = type_to_entries.get(label, [])
        count = len(entries)

        if count <= 1:
            return friendly_type

        if ui_name:
            m = re.search(r"_([0-9]+)$", ui_name.strip())
            if m:
                return f"{friendly_type} ({int(m.group(1))})"

        for pos, e in enumerate(entries, start=1):
            if normalize_mac(e.get("mac")) == mac:
                return f"{friendly_type} ({pos})"

        return f"{friendly_type} (1)"

    normalized_router = normalize_mac(router_bssid) if router_bssid else None

    if not normalized_router:
        counter = {}
        for pkt in packets:
            if not pkt.haslayer(Dot11):
                continue
            a1 = normalize_mac(pkt[Dot11].addr1) if pkt[Dot11].addr1 else None
            a2 = normalize_mac(pkt[Dot11].addr2) if pkt[Dot11].addr2 else None
            a3 = normalize_mac(pkt[Dot11].addr3) if pkt[Dot11].addr3 else None
            if a1 in configured_macs:
                if a2 and a2 not in configured_macs:
                    counter[a2] = counter.get(a2, 0) + 1
                if a3 and a3 not in configured_macs:
                    counter[a3] = counter.get(a3, 0) + 1
            if a2 in configured_macs:
                if a1 and a1 not in configured_macs:
                    counter[a1] = counter.get(a1, 0) + 1
                if a3 and a3 not in configured_macs:
                    counter[a3] = counter.get(a3, 0) + 1
            if a3 in configured_macs:
                if a1 and a1 not in configured_macs:
                    counter[a1] = counter.get(a1, 0) + 1
                if a2 and a2 not in configured_macs:
                    counter[a2] = counter.get(a2, 0) + 1
        if counter:
            normalized_router = max(counter.items(), key=lambda x: x[1])[0]

    for conf in device_configs:
        conf["mac2"] = normalized_router

    interested_macs = set(configured_macs)
    if normalized_router:
        interested_macs.add(normalized_router)

    filtered_packets = []
    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        a1 = normalize_mac(pkt[Dot11].addr1) if pkt[Dot11].addr1 else None
        a2 = normalize_mac(pkt[Dot11].addr2) if pkt[Dot11].addr2 else None
        a3 = normalize_mac(pkt[Dot11].addr3) if pkt[Dot11].addr3 else None
        if (
            (a1 in interested_macs)
            or (a2 in interested_macs)
            or (a3 in interested_macs)
        ):
            filtered_packets.append(pkt)

    device_packet_counts = {}
    for conf in device_configs:
        mac1 = conf["mac1"]
        mac2 = conf["mac2"]
        if not mac1:
            continue
        count = 0
        for pkt in filtered_packets:
            if not pkt.haslayer(Dot11):
                continue
            a1 = normalize_mac(pkt[Dot11].addr1) if pkt[Dot11].addr1 else None
            a2 = normalize_mac(pkt[Dot11].addr2) if pkt[Dot11].addr2 else None
            a3 = normalize_mac(pkt[Dot11].addr3) if pkt[Dot11].addr3 else None
            addrs = {a for a in (a1, a2, a3) if a}
            if mac2 and mac1 in addrs and mac2 in addrs:
                count += 1
        device_packet_counts[mac1] = count

    all_results = []
    for device in device_configs:
        device_type = device["device_type"]
        mac1 = device["mac1"]
        mac2 = device["mac2"]
        label = device["label"]

        if not mac2:
            continue

        df = extract_features_for_mac_pair(
            filtered_packets, mac1, mac2, label, window_size
        )
        if df.empty:
            continue

        df["mac"] = mac1
        df["device"] = device["device_name"] or mac1
        df["device_type"] = device_type
        df["label"] = label
        df["predicted"] = df.apply(lambda r: classify_device(device_type, r), axis=1)
        all_results.append(df)

    if not all_results:
        return {
            "trigger_sequence": [],
            "total_devices": len(device_configs),
            "router_bssid": normalized_router,
        }

    final_df = pd.concat(all_results).sort_values("window_start").reset_index(drop=True)

    trigger_sequence = []
    seen_pairs = []
    for _, row in final_df.iterrows():
        pair = (row["label"], row["mac"])
        if pair not in seen_pairs:
            seen_pairs.append(pair)

    for label, mac in seen_pairs:
        device_df = final_df[(final_df["label"] == label) & (final_df["mac"] == mac)]
        max_time = device_df["window_end"].max()
        current_start = 0.0

        best_window = None
        first_window_found = False
        rep_device_name = (
            device_df["device"].iloc[0]
            if "device" in device_df.columns and len(device_df)
            else None
        )

        while current_start < max_time:
            current_end = current_start + summary_window
            mask = (device_df["window_start"] >= current_start) & (
                device_df["window_start"] < current_end
            )
            window_df = device_df[mask]

            trigger_count = int(sum(window_df["predicted"] == "triggering"))

            if trigger_count > 0:
                if label == "air_purifier":
                    if (
                        best_window is None
                        or trigger_count > best_window["trigger_count"]
                    ):
                        best_window = {
                            "label": label,
                            "device_name": rep_device_name,
                            "device_type": label,
                            "mac_address": mac,
                            "start": round(float(current_start), 3),
                            "end": round(float(current_end), 3),
                            "trigger_count": int(trigger_count),
                        }
                else:
                    if not first_window_found:
                        trigger_sequence.append(
                            {
                                "label": label,
                                "device_name": rep_device_name,
                                "device_type": label,
                                "mac_address": mac,
                                "start": round(float(current_start), 3),
                                "end": round(float(current_end), 3),
                                "trigger_count": int(trigger_count),
                            }
                        )
                        first_window_found = True

            current_start += summary_window

        if label == "air_purifier" and best_window is not None:
            trigger_sequence.append(best_window)

    enriched_sequence = []
    for entry in trigger_sequence:
        mac = entry.get("mac_address")
        if not mac:
            rows = final_df[final_df["label"] == entry.get("label")]
            if not rows.empty:
                mac = rows["mac"].iloc[0]

        frontend_info = frontend_map.get(mac, {}) if mac else {}

        vendor = (
            frontend_info.get("vendor")
            or frontend_info.get("manufacturer")
            or frontend_info.get("vendor_name")
            or "Unknown"
        )
        last_seen = (
            frontend_info.get("last_seen")
            or frontend_info.get("lastSeen")
            or frontend_info.get("lastSeenAt")
            or None
        )
        ui_name = frontend_info.get("device_name") or entry.get("device_name") or ""
        device_type_label = (
            frontend_info.get("device_type")
            or entry.get("device_type")
            or entry.get("label")
            or ""
        )

        friendly_device_type = format_device_name_for_output(device_type_label)
        display_device_name = make_display_name_for_mac(device_type_label, ui_name, mac)
        total_packets = device_packet_counts.get(mac, 0) if mac else 0
        packet_types = (
            frontend_info.get("packet_types")
            or frontend_info.get("packetTypes")
            or None
        )
        data_ratio = None
        if packet_types and isinstance(packet_types, dict):
            data_count = packet_types.get("data", {}).get("count", 0)
            total_count = (
                packet_types.get("data", {}).get("count", 0)
                + packet_types.get("management", {}).get("count", 0)
                + packet_types.get("control", {}).get("count", 0)
            )
            data_ratio = (data_count / total_count) if total_count > 0 else 0.0

        device_rows = final_df[final_df["label"] == entry.get("label")]
        max_time = device_rows["window_end"].max() if not device_rows.empty else 0
        total_windows = (
            int(math.ceil(max_time / summary_window))
            if max_time and summary_window > 0
            else 0
        )

        trigger_count = int(entry.get("trigger_count", 0))

        pred_conf = calculate_prediction_confidence(
            trigger_count,
            total_windows,
            data_ratio if data_ratio is not None else 0.0,
            total_packets,
        )

        per_device_filtered = []
        if mac:
            for pkt in filtered_packets:
                if not pkt.haslayer(Dot11):
                    continue
                a1 = normalize_mac(pkt[Dot11].addr1) if pkt[Dot11].addr1 else None
                a2 = normalize_mac(pkt[Dot11].addr2) if pkt[Dot11].addr2 else None
                a3 = normalize_mac(pkt[Dot11].addr3) if pkt[Dot11].addr3 else None
                addrs = {a for a in (a1, a2, a3) if a}
                if mac in addrs:
                    per_device_filtered.append(pkt)

        actions = detect_actions_for_device(
            frontend_info,
            device_rows,
            per_device_filtered,
            mac,
            normalized_router,
            summary_window,
        )

        enriched = {
            "device_name": display_device_name,
            "device_type": friendly_device_type,
            "label": entry.get("label"),
            "mac_address": mac,
            "start": entry.get("start"),
            "end": entry.get("end"),
            "trigger_count": trigger_count,
            "vendor": vendor,
            "isTriggered": "yes" if trigger_count > 0 else "no",
            "isActive": "yes",
            "last_seen": last_seen,
            "total_packets": int(total_packets),
            "prediction_confidence": pred_conf,
            "actions": actions,
        }
        enriched_sequence.append(enriched)

    enriched_sequence = sorted(enriched_sequence, key=lambda x: x["start"] or 0)
    for idx, item in enumerate(enriched_sequence, start=1):
        item["order"] = idx

    return {
        "trigger_sequence": enriched_sequence,
        "total_devices": len(device_configs),
        "router_bssid": normalized_router,
    }


@deviceaction_bp.route("/analyze-actions", methods=["POST"])
def analyze_actions_endpoint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "error": "No JSON body provided"}), 400

        devices = data.get("devices")
        if not devices or not isinstance(devices, list):
            return (
                jsonify(
                    {
                        "status": "error",
                        "error": "Missing 'devices' array in request body",
                    }
                ),
                400,
            )

        pcap_file = data.get("pcap_file")
        bssid = data.get("bssid")

        if not pcap_file:
            downloads_dir = r"D:\University of Ruhuna FoE\Common Modules\EE7802 Undergraduate Project\Shadow-Scan\backend\downloads"
            if not os.path.exists(downloads_dir):
                return (
                    jsonify(
                        {"status": "error", "error": "Downloads directory not found"}
                    ),
                    404,
                )

            capture_files = [
                f for f in os.listdir(downloads_dir) if f.endswith((".cap", ".pcap"))
            ]
            if not capture_files:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "error": "No capture files found in downloads directory",
                        }
                    ),
                    404,
                )

            capture_files_full = [os.path.join(downloads_dir, f) for f in capture_files]
            pcap_file = max(capture_files_full, key=os.path.getmtime)

        analysis = process_pcap_auto(
            pcap_file=pcap_file,
            devices_from_frontend=devices,
            window_size=1.0,
            summary_window=1.0,
            router_bssid=bssid,
        )

        trigger_sequence = analysis.get("trigger_sequence", [])
        router_bssid = analysis.get("router_bssid")
        total_devices = analysis.get("total_devices", 0)

        triggered_map = {}
        for item in trigger_sequence:
            mac = item.get("mac_address")
            if not mac:
                continue
            triggered_map[mac] = max(
                triggered_map.get(mac, 0), item.get("trigger_count", 0)
            )

        devices_processed = []
        for d in devices:
            mac = normalize_mac(
                d.get("mac_address") or d.get("mac") or d.get("macAddress") or ""
            )
            ui_name = d.get("device_name") or d.get("device") or ""
            device_type = (
                d.get("device_type")
                or d.get("deviceType")
                or normalize_label(ui_name)
                or ""
            )
            last_seen = (
                d.get("last_seen") or d.get("lastSeen") or d.get("lastSeenAt") or None
            )

            vendor = (
                d.get("vendor")
                or d.get("manufacturer")
                or d.get("vendor_name")
                or "Unknown"
            )

            packet_types = d.get("packet_types") or d.get("packetTypes") or None
            total_packets_frontend = None
            if packet_types and isinstance(packet_types, dict):
                total_packets_frontend = (
                    packet_types.get("data", {}).get("count", 0)
                    + packet_types.get("management", {}).get("count", 0)
                    + packet_types.get("control", {}).get("count", 0)
                )

            trigger_count = triggered_map.get(mac, 0)
            triggered_flag = "yes" if trigger_count > 0 else "no"

            actions = detect_actions_for_device(
                d, None, [], mac, router_bssid, summary_window=1.0
            )

            devices_processed.append(
                {
                    "device_name": ui_name,
                    "device_type": device_type,
                    "mac_address": mac,
                    "last_seen": last_seen,
                    "vendor": vendor,
                    "total_packets": (
                        int(total_packets_frontend)
                        if total_packets_frontend is not None
                        else 0
                    ),
                    "isTriggered": triggered_flag,
                    "trigger_count": int(trigger_count),
                    "isActive": "yes",
                    "actions": actions,
                }
            )

        device_sequence = []
        for item in trigger_sequence:
            name = item.get("device_name") or item.get("mac_address")
            device_sequence.append(name)

        response = {
            "status": "success",
            "pcap_file": pcap_file,
            "router_bssid": router_bssid,
            "trigger_sequence": trigger_sequence,
            "device_sequence": device_sequence,
            "devices_processed": devices_processed,
            "total_devices_processed": total_devices,
            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return jsonify(response)

    except Exception as e:
        print(f"[ERROR] analyze-actions failed: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500
