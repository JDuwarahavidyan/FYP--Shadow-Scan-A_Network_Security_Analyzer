# server.py
from flask import Flask
from flask_cors import CORS
import threading
import modules.config as config

# Import Blueprints
from modules.capture.capture_manager import capture_bp, init_capture_globals
from modules.analysis.analysis_manager import analysis_bp
from modules.devicefp.devicefp_manager import devicefp_bp


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

# Inject shared globals into capture manager
init_capture_globals(globals_dict)

# ============================================================
# REGISTER BLUEPRINTS
# ============================================================
app.register_blueprint(capture_bp)
app.register_blueprint(analysis_bp)
app.register_blueprint(devicefp_bp, url_prefix='/api/devicefp')

# ============================================================
# MAIN ENTRY
# ============================================================
if __name__ == "__main__":
    print("[*] Flask server started on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
