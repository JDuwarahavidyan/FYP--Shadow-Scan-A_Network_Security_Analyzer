# Shadow-Scan Frontend

A modern React + Vite frontend for real-time IoT network packet capture and analysis.

## Features

- 🎯 Real-time packet capture control
- 📡 Live log streaming from Raspberry Pi
- 📊 Packet analysis and visualization
- 🔒 Device fingerprinting
- 🛡️ Mitigation controls
- 🎨 Cyberpunk-themed UI

## Prerequisites

- Node.js 16.x or higher
- npm or yarn
- Backend server running on `http://localhost:5000`

## Setup Instructions

### 1. Install Dependencies

```bash
npm install
# or
yarn install
```

### 2. Configure Backend URL (Optional)

If your backend is running on a different host/port, update the `API_BASE` in:

- `src/api/captureAPI.js`

```javascript
const API_BASE = "http://localhost:5000"; // Change if needed
```

### 3. Run Development Server

```bash
npm run dev
# or
yarn dev
```

The app will start on `http://localhost:5173`

### 4. Build for Production

```bash
npm run build
# or
yarn build
```

## Project Structure

```
src/
├── api/
│   ├── captureAPI.js       # Real backend API integration
│   ├── mockAPI.js          # Mock API for testing
│   └── useSocketEvents.js  # WebSocket utilities
├── components/
│   ├── core/               # Reusable components
│   │   ├── Card.jsx
│   │   ├── LiveLogTerminal.jsx
│   │   └── StatusBadge.jsx
│   ├── layout/             # Layout components
│   │   ├── Footer.jsx
│   │   └── Navbar.jsx
│   ├── panels/             # Feature panels
│   │   ├── PacketCapturePanel.jsx
│   │   └── MitigationPanel.jsx
│   └── views/              # Views/Pages
│       ├── FingerprintResults.jsx
│       └── PcapViewer.jsx
├── pages/
│   └── CyberpunkDashboard.jsx
├── App.jsx
└── main.jsx
```

## Key Components

### PacketCapturePanel

- Controls packet capture start/stop
- Displays live logs via Server-Sent Events
- Shows packet count in real-time
- Parses capture results

### LiveLogTerminal

- Terminal-style log display
- Auto-scrolls to latest logs
- Timestamp for each entry

### captureAPI

- Handles all backend communication
- Server-Sent Events for live logs
- RESTful endpoints for capture control

## API Integration

The frontend connects to these backend endpoints:

- `POST /api/capture/start` - Start packet capture
- `POST /api/capture/stop/:id` - Stop capture
- `GET /api/capture/logs` - Live log stream (SSE)
- `POST /api/capture/parse` - Parse capture file

## Development Tips

### Using Mock API

To develop without backend, import `mockAPI` instead of `captureAPI`:

```javascript
import { mockAPI } from "../../api/mockAPI";
```

### Debugging Live Logs

Open browser DevTools → Network → EventStream to see SSE messages

### Hot Module Replacement

Changes to components will hot-reload without losing state

## Troubleshooting

### Cannot connect to backend

- Ensure backend server is running on port 5000
- Check CORS settings in backend `server.py`
- Verify `API_BASE` URL in `captureAPI.js`

### Live logs not showing

- Check browser console for SSE connection errors
- Verify `/api/capture/logs` endpoint is accessible
- Ensure capture has been started

### Build errors

```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
```

## Technologies Used

- **React 18** - UI framework
- **Vite** - Build tool and dev server
- **Lucide React** - Icon library
- **Tailwind CSS** - Styling (if configured)
- **Server-Sent Events** - Real-time log streaming

## Contributing

1. Create feature branch
2. Make changes
3. Test thoroughly
4. Submit pull request

## License

MIT License - See LICENSE file for details
