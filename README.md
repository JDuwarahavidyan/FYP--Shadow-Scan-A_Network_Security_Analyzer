# Shadow-Scan - IoT Network Packet Capture System

Real-time packet capture and analysis system for IoT devices using Raspberry Pi.

## Quick Start

### Backend Setup (Flask Server)

1. Navigate to backend folder:

   ```cmd
   cd backend
   ```

2. Create and activate virtual environment:

   ```cmd
   python -m venv iot
   iot\Scripts\activate.bat
   ```

3. Install dependencies:

   ```cmd
   pip install -r requirements.txt
   ```

4. Configure Raspberry Pi settings in `server.py`:

   ```python
   PI_HOST = "192.168.1.27"  # Your Pi's IP
   PI_USER = "kali"
   PI_PASS = "kali"
   ```

5. Run the server:
   ```cmd
   python server.py
   ```
   Server starts at `http://localhost:5000`

### Frontend Setup (React + Vite)

1. Navigate to frontend folder (new terminal):

   ```cmd
   cd frontend
   ```

2. Install dependencies:

   ```cmd
   npm install
   ```

3. Run development server:
   ```cmd
   npm run dev
   ```
   Frontend starts at `http://localhost:5173`

### Access the Application

Open your browser and go to: `http://localhost:5173`

## Features

- ✅ **Real-time Packet Capture** - Control capture from web interface
- ✅ **Live Log Streaming** - See packet capture logs in real-time
- ✅ **SSH Integration** - Secure connection to Raspberry Pi
- ✅ **Packet Analysis** - Parse and analyze captured packets
- ✅ **Device Fingerprinting** - Identify IoT devices on network
- ✅ **Mitigation Controls** - Network security measures

## System Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   Frontend      │         │   Flask Backend  │         │  Raspberry Pi   │
│  (React/Vite)   │ ◄─────► │   (Python)       │ ◄─────► │  (Kali Linux)   │
│  Port: 5173     │   API   │   Port: 5000     │   SSH   │  wifi_cap.py    │
└─────────────────┘         └──────────────────┘         └─────────────────┘
        │                            │
        │                            │
        └────── Server-Sent Events ──┘
              (Real-time Logs)
```

## Technology Stack

### Backend

- Python 3.8+
- Flask (Web framework)
- Paramiko (SSH client)
- Flask-CORS (Cross-origin support)

### Frontend

- React 18
- Vite (Build tool)
- Lucide React (Icons)
- Server-Sent Events (Real-time streaming)

### IoT Device

- Raspberry Pi (Kali Linux)
- Python packet capture script
- WiFi interface (wlan0)

## API Endpoints

| Method | Endpoint                 | Description           |
| ------ | ------------------------ | --------------------- |
| POST   | `/api/capture/start`     | Start packet capture  |
| POST   | `/api/capture/stop/<id>` | Stop packet capture   |
| GET    | `/api/capture/logs`      | Live log stream (SSE) |
| POST   | `/api/capture/parse`     | Parse capture file    |

## Configuration

### Backend Configuration

Edit `backend/server.py`:

- `PI_HOST`: Raspberry Pi IP address
- `PI_USER`: SSH username
- `PI_PASS`: SSH password
- `SCRIPT_PATH`: Path to capture script on Pi

### Frontend Configuration

Edit `frontend/src/api/captureAPI.js`:

- `API_BASE`: Backend server URL (default: `http://localhost:5000`)

## Troubleshooting

### Backend Issues

**Cannot connect to Raspberry Pi:**

- Verify Pi IP address: `ping 192.168.1.27`
- Test SSH manually: `ssh kali@192.168.1.27`
- Check network connectivity

**Port 5000 already in use:**

- Stop conflicting applications
- Or change port in `server.py`

### Frontend Issues

**Cannot connect to backend:**

- Ensure backend is running on port 5000
- Check console for CORS errors
- Verify `API_BASE` URL

**Live logs not streaming:**

- Check browser Network tab for SSE connection
- Ensure capture has been started
- Check backend console for errors

## Development

### Run Backend in Debug Mode

```cmd
cd backend
python server.py
```

Debug mode is enabled by default with `debug=True`

### Run Frontend with Hot Reload

```cmd
cd frontend
npm run dev
```

Changes auto-reload in browser

### Testing Without Raspberry Pi

Use `mockAPI.js` in frontend for development without backend:

```javascript
import { mockAPI } from "../../api/mockAPI";
```

## Project Structure

```
Shadow-Scan/
├── backend/
│   ├── server.py           # Flask server
│   ├── requirements.txt    # Python dependencies
│   ├── README.md          # Backend documentation
│   └── iot/               # Virtual environment
├── frontend/
│   ├── src/
│   │   ├── api/           # API integration
│   │   ├── components/    # React components
│   │   └── pages/         # Page components
│   ├── package.json       # Node dependencies
│   └── README.md          # Frontend documentation
└── README.md              # This file
```

## Security Notes

⚠️ **Important Security Considerations:**

1. **SSH Credentials**: Never commit actual passwords to version control
2. **Use SSH Keys**: Configure key-based SSH authentication instead of passwords
3. **Network Security**: Run on trusted networks only
4. **HTTPS**: Use HTTPS in production environments
5. **Environment Variables**: Store sensitive data in environment variables

## Future Enhancements

- [ ] SSH key authentication
- [ ] Environment variable configuration
- [ ] Advanced packet analysis with Scapy
- [ ] WebSocket support for bi-directional communication
- [ ] User authentication
- [ ] Multiple device support
- [ ] Capture file download
- [ ] Enhanced visualization

## License

MIT License - See LICENSE file for details

## Contributors

- Your Name - Initial Development

## Support

For issues and questions:

- Create an issue on GitHub
- Check documentation in `backend/README.md` and `frontend/README.md`
