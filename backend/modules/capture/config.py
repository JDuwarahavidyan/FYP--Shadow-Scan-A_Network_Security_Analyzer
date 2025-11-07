SCRIPT_PATH = "/home/kali/IoT-Privacy/code/PacketCapture/wifi_sniff.py"

client = None
process_active = False
capture_session = None
packet_count = 0
lock = None  # initialized in server.py
log_queue = None  # initialized in server.py
