# Shadow-Scan Backend Setup

This is the Flask backend server that connects to your Raspberry Pi to capture network packets and stream live logs to the frontend.

## Prerequisites

- Python 3.8 or higher
- Virtual environment (recommended)
- Raspberry Pi with SSH access
- Network connectivity to Raspberry Pi

## Setup Instructions

### 1. Create and Activate Virtual Environment

```bash
# Create virtual environment
python -m venv iot

# Activate on Windows (Command Prompt)
iot\Scripts\activate.bat

# Activate on Windows (PowerShell)
iot\Scripts\Activate.ps1

# Activate on Linux/Mac
source iot/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Raspberry Pi Connection

Edit `server.py` and update these variables:

```python
PI_HOST = "192.168.1.27"  # Your Pi's IP address
PI_USER = "kali"          # Your Pi username
PI_PASS = "kali"          # Your Pi password
SCRIPT_PATH = "/home/kali/IoT-Privacy/code/PacketCapture/wifi_cap.py"
```

### 4. Run the Server

```bash
python server.py
```

The server will start on `http://localhost:5000`

## API Endpoints

### Start Capture

- **POST** `/api/capture/start`
- Body: `{"device": "raspberrypi-1", "interface": "wlan0"}`
- Returns: `{"ok": true, "sessionId": "cap-123456", "startedAt": "2025-11-05T..."}`

### Stop Capture

- **POST** `/api/capture/stop/<session_id>`
- Returns: `{"ok": true, "fileUrl": "...", "meta": {"packetCount": 1234, "duration": 0}}`

### Stream Logs (SSE)

- **GET** `/api/capture/logs`
- Returns: Server-Sent Events stream with real-time logs

### Parse Capture

- **POST** `/api/capture/parse`
- Body: `{"fileUrl": "/captures/capture-123.cap"}`
- Returns: `{"summary": {...}, "flows": [...], "topHosts": [...]}`

## Troubleshooting

### Cannot connect to Raspberry Pi

- Verify Pi IP address is correct
- Check SSH credentials
- Ensure Pi is on the same network
- Test SSH connection manually: `ssh kali@192.168.1.27`

### Port 5000 already in use

- Stop other applications using port 5000
- Or change the port in `server.py`:
  ```python
  app.run(host="0.0.0.0", port=5001, debug=True)
  ```

### CORS errors

- Ensure frontend is running on `http://localhost:5173`
- If using different port, update CORS origins in `server.py`

## Development Notes

- The server uses Server-Sent Events (SSE) for real-time log streaming
- Packet capture runs in a background thread
- SSH connection is managed via paramiko library
- CORS is enabled for frontend communication
