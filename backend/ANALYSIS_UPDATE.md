# Analysis Manager Update Summary

## Changes Made to `analysis_manager.py`

### 1. BSSID Filtering Implementation

The analysis now filters packets by BSSID (Basic Service Set Identifier) before processing:

```python
# Filters packets where wlan.addr matches the specified BSSID
# Checks all 802.11 address fields: addr1, addr2, addr3, addr4
```

**How it works:**

- Takes BSSID parameter from the request (e.g., "AA:BB:CC:DD:EE:FF")
- Normalizes format (removes colons/hyphens, uppercase)
- Checks all 4 address fields in 802.11 frames
- Only includes packets where BSSID appears in any address field

### 2. Packet Type Classification

Now calculates counts and percentages for 802.11 frame types:

**Frame Types:**

- **DATA** (type=2): Data frames carrying actual payload
- **CONTROL** (type=1): Control frames (ACK, RTS, CTS, etc.)
- **MANAGEMENT** (type=0): Management frames (Beacon, Probe, Auth, etc.)
- **OTHER**: Non-802.11 or unclassified packets

### 3. Enhanced Response Format

**New response structure:**

```json
{
  "ok": true,
  "ssid": "NetworkName",
  "bssid": "AA:BB:CC:DD:EE:FF",
  "summary": {
    "totalPackets": 1500,           // After BSSID filter
    "totalBeforeFilter": 5000,      // Before BSSID filter
    "packetTypes": {                 // Raw counts
      "DATA": 900,
      "CONTROL": 300,
      "MANAGEMENT": 250,
      "OTHER": 50
    },
    "packetTypePercentages": {       // Percentages
      "DATA": 60.0,
      "CONTROL": 20.0,
      "MANAGEMENT": 16.67,
      "OTHER": 3.33
    },
    "protocols": {                   // IP-layer protocol %
      "TCP": 45.0,
      "UDP": 30.0,
      "ICMP": 15.0,
      "Other": 10.0
    },
    "protocolCounts": {              // IP-layer raw counts
      "TCP": 450,
      "UDP": 300,
      "ICMP": 150,
      "Other": 100
    }
  },
  "flows": [...],                    // Top 10 traffic flows
  "topHosts": [...]                  // Top 10 active hosts
}
```

## Testing the Analysis

### Using the Test Script

```cmd
cd backend
python test_analysis.py downloads\capture-01.cap AA:BB:CC:DD:EE:FF
```

**Expected output:**

```
[*] Reading file: downloads\capture-01.cap
[*] Total packets in file: 5000
[*] Filtering by BSSID: AA:BB:CC:DD:EE:FF
[*] Packets after BSSID filter: 1500

============================================================
PACKET TYPE ANALYSIS
============================================================
DATA        :   900 packets ( 60.00%)
CONTROL     :   300 packets ( 20.00%)
MANAGEMENT  :   250 packets ( 16.67%)
OTHER       :    50 packets (  3.33%)
============================================================
```

### Using the API

```bash
curl -X POST http://localhost:5000/api/analysis/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "fileUrl": "capture-01.cap",
    "ssid": "MyNetwork",
    "bssid": "AA:BB:CC:DD:EE:FF"
  }'
```

## Understanding 802.11 Frame Types

### Management Frames (Type 0)

- **Beacon**: AP announces its presence
- **Probe Request/Response**: Device searches for networks
- **Authentication**: Authentication process
- **Association**: Device joins network
- **Deauthentication**: Forced disconnect

### Control Frames (Type 1)

- **RTS** (Request to Send): Request channel access
- **CTS** (Clear to Send): Grant channel access
- **ACK** (Acknowledgment): Confirm packet receipt
- **Block ACK**: Acknowledge multiple packets

### Data Frames (Type 2)

- **Data**: Regular data transmission
- **QoS Data**: Quality of Service data
- **Null Data**: No payload (power management)
- **Data + CF-ACK**: Data with acknowledgment

## Why BSSID Filtering Matters

1. **Focus on Target Network**: Isolates packets from a specific access point
2. **Accurate Statistics**: Removes noise from other nearby networks
3. **Security Analysis**: Analyze specific AP behavior
4. **Performance Metrics**: Calculate real throughput for one network

## Common BSSID Patterns

**In a typical Wi-Fi capture:**

- BSSID appears in `addr1` (destination) for packets TO the AP
- BSSID appears in `addr2` (source) for packets FROM the AP
- BSSID appears in `addr3` (BSSID field) in most frames

**Address field meanings:**

- **To DS=0, From DS=0**: Ad-hoc, addr1=DA, addr2=SA, addr3=BSSID
- **To DS=1, From DS=0**: STA→AP, addr1=BSSID, addr2=SA, addr3=DA
- **To DS=0, From DS=1**: AP→STA, addr1=DA, addr2=BSSID, addr3=SA
- **To DS=1, From DS=1**: WDS, uses all 4 addresses

## Troubleshooting

### No packets after filtering

- Verify BSSID format is correct
- Check if capture file contains 802.11 frames
- Try without BSSID filter first to see total packets

### All packets classified as OTHER

- File might not contain 802.11 frames
- Might be Ethernet capture instead of Wi-Fi monitor mode
- Use `scapy` to inspect first packet: `rdpcap(file)[0].show()`

### Percentage doesn't add up to 100%

- This is normal due to rounding to 2 decimal places
- Sum should be very close to 100%

## Frontend Integration

The frontend sends BSSID from selected AP:

```javascript
const parsed = await analysisAPI.analyze(
  result.fileUrl,
  selectedAp?.ssid, // SSID for display
  selectedAp?.bssid // BSSID for filtering
);
```

Display packet type breakdown in UI:

```javascript
<div className="packet-types">
  <div>DATA: {parsed.summary.packetTypePercentages.DATA}%</div>
  <div>CONTROL: {parsed.summary.packetTypePercentages.CONTROL}%</div>
  <div>MANAGEMENT: {parsed.summary.packetTypePercentages.MANAGEMENT}%</div>
</div>
```

## Performance Considerations

- **Large files**: Filtering adds processing time (reads all packets twice)
- **Optimization**: Could cache parsed packets if analyzing same file multiple times
- **Memory**: Keeps filtered packets in memory during analysis

## Future Enhancements

- [ ] Filter by specific frame subtypes (Beacon only, Data only, etc.)
- [ ] Time-series analysis of packet types
- [ ] Channel utilization calculation
- [ ] Retry rate analysis
- [ ] Signal strength statistics (if available in capture)
