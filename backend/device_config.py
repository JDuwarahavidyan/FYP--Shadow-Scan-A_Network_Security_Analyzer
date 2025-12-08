import json



def generate_device_config_json(output_path="device_config.json"):
    """
    Create a structured JSON file for device configurations.
    Each entry defines one device with its name, MAC addresses, and optional label.
    """

    

    device_data = [

    # -------------------------
    #       PLUG DEVICES
    # -------------------------
    {"device_name": "plug",               "mac1": "c0:f8:53:de:cf:2a", "mac2": "14:eb:b6:be:d7:1e", "label": "plug_2"},
    {"device_name": "plug",               "mac1": "3c:0b:59:4b:8c:27", "mac2": "14:eb:b6:be:d7:1e", "label": "plug_1"},

    # -------------------------
    #      WALL SOCKETS
    # -------------------------
    {"device_name": "wall_socket",        "mac1": "d8:d6:68:06:6d:65", "mac2": "14:eb:b6:be:d7:1e", "label": "wall_socket_2"},
    {"device_name": "wall_socket",        "mac1": "d8:d6:68:97:fb:2d", "mac2": "14:eb:b6:be:d7:1e", "label": "wall_socket_1"},

    # -------------------------
    #         SWITCHES
    # -------------------------
    {"device_name": "switch",             "mac1": "38:2c:e5:1d:02:fb", "mac2": "14:eb:b6:be:d7:1e", "label": "switch_2"},
    {"device_name": "switch",             "mac1": "38:2c:e5:1c:cf:6e", "mac2": "14:eb:b6:be:d7:1e", "label": "switch_1"},

    # -------------------------
    #      MOTION SENSORS
    # -------------------------
    {"device_name": "motion_sensor",      "mac1": "f8:17:2d:b4:3d:5a", "mac2": "14:eb:b6:be:d7:1e", "label": "motion_sensor_1"},
    {"device_name": "motion_sensor",      "mac1": "f8:17:2d:b6:38:de", "mac2": "14:eb:b6:be:d7:1e", "label": "motion_sensor_2"},

    # -------------------------
    #       DOOR SENSORS
    # -------------------------
    {"device_name": "door_sensor",        "mac1": "18:de:50:54:8e:e9", "mac2": "14:eb:b6:be:d7:1e", "label": "door_sensor_2"},
    {"device_name": "door_sensor",        "mac1": "18:de:50:50:39:37", "mac2": "14:eb:b6:be:d7:1e", "label": "door_sensor_1"},

    # -------------------------
    #         OTHERS
    # -------------------------
    {"device_name": "tabel_lamp",         "mac1": "3c:0b:59:8f:25:42", "mac2": "14:eb:b6:be:d7:1e", "label": "tabel_lamp"},
    {"device_name": "air_purifier",       "mac1": "50:ec:50:94:7b:a3", "mac2": "14:eb:b6:be:d7:1e", "label": "air_purifier"},
    {"device_name": "power_strip",        "mac1": "fc:3c:d7:53:f6:79", "mac2": "14:eb:b6:be:d7:1e", "label": "power_strip"},
    {"device_name": "tempurature_sensor", "mac1": "38:2c:e5:55:51:60", "mac2": "14:eb:b6:be:d7:1e", "label": "temp_sensor"},
    ]



    with open(output_path, "w") as f:
        json.dump(device_data, f, indent=4)

    print(f"✅ Device configuration saved to: {output_path}")


if __name__ == "__main__":
    generate_device_config_json()

