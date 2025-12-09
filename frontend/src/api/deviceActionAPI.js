const API_BASE_URL = 'http://localhost:5000/api/deviceaction';

/**
 * Analyze device actions based on fingerprinted devices
 * @param {Array} devices - Array of devices from device fingerprinting
 * @param {string} bssid - Router BSSID
 * @param {string} pcapFile - Path to pcap file to analyze
 * @returns {Promise<Object>} Action analysis results with enriched device data
 */
export const analyzeDeviceActions = async (devices, bssid, pcapFile) => {
  try {
    // Transform devices to match backend expectations
    const transformedDevices = devices.map(device => ({
      mac_address: device.mac,
      vendor: device.vendor,
      device_type: device.raw_type || device.device_type,
      device_name: device.device_name,
      confidence: device.confidence,
      total_packets: device.totalPackets,
      packet_types: {
        data: { count: device.dataPackets || 0 },
        management: { count: device.managementPackets || 0 },
        control: { count: device.controlPackets || 0 }
      },
      avg_signal_strength: device.avgSignalStrength,
      connected_to_router: device.connectedToRouter,
      last_seen: device.last_seen
    }));

    const requestBody = {
      devices: transformedDevices,
      bssid,
      pcap_file: pcapFile
    };

    const response = await fetch(`${API_BASE_URL}/analyze-actions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Failed to analyze device actions');
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error analyzing device actions:', error);
    throw error;
  }
};

export default {
  analyzeDeviceActions,
};
