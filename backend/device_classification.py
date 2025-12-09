import pandas as pd
import numpy as np
import json
from scapy.all import rdpcap, Dot11


# Feature Extraction

def extract_features_for_mac_pair(packets, mac1, mac2, label, window_size=1.0):
    pkt_list = []
    t0 = float(packets[0].time)
    last_pkt_time = None

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]
        src, dst = dot11.addr2, dot11.addr1

        # Device-specific MAC filtering
        if label == "air_purifier":
            if ((src, dst) not in [(mac1, mac2), (mac2, mac1)]) and (dst != mac1):
                continue
        else:
            if (src, dst) not in [(mac1, mac2), (mac2, mac1)]:
                continue

        # Calculate inter-arrival time (IAT)
        if last_pkt_time is not None:
            iat = float(pkt.time) - last_pkt_time
            last_len = pkt_list[-1]["frame_len"]
            ref1 = 1 if (len(pkt) == last_len == 10 and iat < 0.001) else 0
        else:
            ref1 = 0

        last_pkt_time = float(pkt.time)

        pkt_list.append({
            "time": float(pkt.time) - t0,
            "frame_len": len(pkt),
            "ref": 1 if len(pkt) in [269, 91] else 0,
            "ref1": ref1,
            "ref2": 1 if len(pkt) in [301, 269, 317] else 0,
            "src_mac": src,
            "dst_mac": dst,
            "retry": 1 if dot11.FCfield & 0x8 else 0
        })

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

        features.append({
            "label": label,
            "window_start": times[i],
            "window_end": end_time,
            "ref": ref,
            "ref1": ref1,
            "ref2": ref2
        })

    return pd.DataFrame(features)



# Classification Rules

def classify_device(device_name, row):
    if device_name in ["plug", "wall_plug", "tabel_lamp", "switch",
                       "motion_sensor", "door_sensor"]:
        return "triggering" if row.get("ref") == 1 else "not_triggering"

    elif device_name == "air_purifier":
        return "triggering" if row.get("ref1") == 1 else "not_triggering"

    elif device_name in ["power_strip"]:
        return "triggering" if row.get("ref2") == 1 else "not_triggering"
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

    for label, device_df in final_df.groupby("label"):
        max_time = device_df["window_end"].max()
        current_start = 0.0

        best_window = None  # For air_purifier
        first_window_found = False  # For other devices

        while current_start < max_time:
            current_end = current_start + summary_window
            mask = (device_df["window_start"] >= current_start) & \
                   (device_df["window_start"] < current_end)
            window_df = device_df[mask]

            trigger_count = sum(window_df["predicted"] == "triggering")

            if trigger_count > 0:
                # air_purifier → take window with max triggers
                if label == "air_purifier":
                    if best_window is None or trigger_count > best_window["trigger_count"]:
                        best_window = {
                            "label": label,
                            "device": device_df["device"].iloc[0],
                            "start": round(float(current_start), 3),
                            "end": round(float(current_end), 3),
                            "trigger_count": int(trigger_count)
                        }
                else:
                    # other devices → take first triggering window only
                    if not first_window_found:
                        trigger_sequence.append({
                            "label": label,
                            "device": device_df["device"].iloc[0],
                            "start": round(float(current_start), 3),
                            "end": round(float(current_end), 3),
                            "trigger_count": int(trigger_count)
                        })
                        first_window_found = True

            current_start += summary_window

        if label == "air_purifier" and best_window is not None:
            trigger_sequence.append(best_window)

    # Sort by start time
    trigger_sequence = sorted(trigger_sequence, key=lambda x: x["start"])

    # Add order number
    for idx, item in enumerate(trigger_sequence, start=1):
        item["order"] = idx

    # Save JSON output
    with open("trigger_sequence.json", "w") as f:
        json.dump(trigger_sequence, f, indent=4)

    return trigger_sequence



# Main

if __name__ == "__main__":
    config_json = "device_config.json"
    pcap_file = "capture-01.cap"
    process_pcap_auto(pcap_file, config_json, summary_window=10)
