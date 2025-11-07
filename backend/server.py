from flask import Flask
from flask_cors import CORS
import threading
import modules.config as config

# Import from your capture module
from modules.capture import config
from modules.capture.log_queue import log_queue
from modules.capture.capture_manager import register_routes

# ============================================================
# APP SETUP
# ============================================================
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# ============================================================
# GLOBAL INITIALIZATION
# ============================================================
config.lock = threading.Lock()  # Initialize global lock

globals_dict = {
    "process_active": config.process_active,
    "client": config.client,
    "lock": config.lock,
    "packet_count": config.packet_count,
    "capture_session": config.capture_session
}

# ============================================================
# REGISTER ROUTES
# ============================================================
register_routes(app, globals_dict)

# ============================================================
# MAIN ENTRY
# ============================================================
if __name__ == "__main__":
    print("🚀 Flask server started on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
