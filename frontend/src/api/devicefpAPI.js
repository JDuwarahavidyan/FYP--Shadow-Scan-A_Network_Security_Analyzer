// devicefpAPI.js
const API_BASE_URL = 'http://localhost:5000/api/devicefp';

/**
 * Analyze the latest capture file for device fingerprinting
 * @param {string} bssid - Optional router BSSID (uses default if not provided)
 * @returns {Promise<Object>} Analysis results containing detected devices
 */
export const analyzeLatestCapture = async (bssid = null) => {
  try {
    const requestBody = bssid ? { bssid } : {};

    const response = await fetch(`${API_BASE_URL}/analyze-latest`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || 'Failed to analyze capture file');
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error analyzing latest capture:', error);
    throw error;
  }
};

/**
 * Helper: format raw device type string to user-friendly label
 * Examples:
 *  - "switch" -> "Switch"
 *  - "door_sensor" -> "Door Sensor"
 *  - "switch_1" -> "Switch" (we strip numeric suffix if present)
 */
const formatDeviceTypeString = (raw) => {
  if (!raw && raw !== '') return '';
  const s = String(raw || '').trim().toLowerCase();

  if (!s) return '';

  // If looks like "name_N" (e.g. switch_1) strip the trailing number section
  // but only if it's separated by underscore and last token is a number.
  const parts = s.split('_');
  if (parts.length > 1 && /^\d+$/.test(parts[parts.length - 1])) {
    parts.pop();
  }

  // If user already supplied a canonical device_type like "switch" use it
  // Join remaining parts and replace underscores with spaces
  const joined = parts.join(' ');
  // Capitalize each word
  const formatted = joined
    .split(' ')
    .map((w) => (w ? w.charAt(0).toUpperCase() + w.slice(1) : ''))
    .join(' ')
    .trim();

  return formatted || (s.charAt(0).toUpperCase() + s.slice(1));
};


export const formatDeviceInfo = (device = {}) => {
  // Determine raw type:
  // Prefer device.device_type (explicit), otherwise extract base from device_name
  let rawType = '';
  if (device.device_type && String(device.device_type).trim() !== '') {
    rawType = String(device.device_type).trim();
  } else if (device.device_name && String(device.device_name).trim() !== '') {
    // e.g. "switch_1" -> take "switch"
    const base = String(device.device_name).trim().split('_')[0];
    rawType = base;
  } else {
    rawType = 'unknown';
  }

  const formattedType = formatDeviceTypeString(rawType);

  const totalPackets = device.total_packets ?? 0;
  const dataPackets = device.packet_types?.data?.count ?? 0;
  const managementPackets = device.packet_types?.management?.count ?? 0;
  const controlPackets = device.packet_types?.control?.count ?? 0;

  const dataPercentage = device.packet_types?.data?.percentage ?? 0;
  const managementPercentage = device.packet_types?.management?.percentage ?? 0;
  const controlPercentage = device.packet_types?.control?.percentage ?? 0;

  return {
    name: formattedType,               // friendly name for UI (e.g. "Door Sensor")
    device_type: formattedType,        
    device_type_raw: rawType,  
    device_name: device.device_name,        
    mac: device.mac_address || 'N/A',
    vendor: device.vendor || 'Unknown',
    total_packets: totalPackets,
    totalPackets: totalPackets,
    dataPackets: dataPackets,
    managementPackets: managementPackets,
    controlPackets: controlPackets,
    dataPercentage: dataPercentage,
    managementPercentage: managementPercentage,
    controlPercentage: controlPercentage,
    // Time / signal
    firstSeen: device.first_seen || 'N/A',
    lastSeen: device.last_seen || 'N/A',
    avgSignalStrength: device.avg_signal_strength ?? null,
    connectedToRouter: !!device.connected_to_router,
    confidence: typeof device.confidence === 'number' ? device.confidence : 0,
    // include raw payload for debugging if needed
    _raw: device,
  };
};

/**
 * Get confidence level label based on confidence score
 * @param {number} confidence - Confidence score (0-1)
 * @returns {string} Confidence level label
 */
export const getConfidenceLabel = (confidence) => {
  if (confidence >= 0.8) return 'High';
  if (confidence >= 0.5) return 'Medium';
  return 'Low';
};

/**
 * Get confidence level color for UI
 * @param {number} confidence - Confidence score (0-1)
 * @returns {string} Color code for confidence level
 */
export const getConfidenceColor = (confidence) => {
  if (confidence >= 0.8) return '#00ff41'; // Green
  if (confidence >= 0.5) return '#ffd700'; // Yellow
  return '#ff6b6b'; // Red
};

/**
 * Filter devices by confidence level
 * @param {Array} devices - Array of device objects (raw backend objects or formatted ones)
 * @param {string} level - Confidence level ('high', 'medium', 'low', 'all')
 * @returns {Array} Filtered devices (raw objects)
 */
export const filterDevicesByConfidence = (devices, level = 'all') => {
  if (level === 'all') return devices;

  return devices.filter((device) => {
    const confidence = (device.confidence ?? device.confidence === 0) ? (device.confidence ?? 0) : (device.confidence ?? 0);
    switch (level.toLowerCase()) {
      case 'high':
        return confidence >= 0.8;
      case 'medium':
        return confidence >= 0.5 && confidence < 0.8;
      case 'low':
        return confidence < 0.5;
      default:
        return true;
    }
  });
};

/**
 * Sort devices by specified field
 * @param {Array} devices - Array of device objects (raw backend objects or formatted ones)
 * @param {string} field - Field to sort by
 * @param {string} order - Sort order ('asc' or 'desc')
 * @returns {Array} Sorted devices
 */
export const sortDevices = (devices, field = 'total_packets', order = 'desc') => {
  return [...devices].sort((a, b) => {
    let aValue = a[field];
    let bValue = b[field];

    // Handle nested fields like packet_types.data.count
    if (field.includes('.')) {
      const parts = field.split('.');
      aValue = parts.reduce((obj, key) => obj?.[key], a);
      bValue = parts.reduce((obj, key) => obj?.[key], b);
    }

    // Fallbacks
    if (aValue === undefined || aValue === null) aValue = 0;
    if (bValue === undefined || bValue === null) bValue = 0;

    if (order === 'asc') {
      return aValue > bValue ? 1 : -1;
    }
    return aValue < bValue ? 1 : -1;
  });
};

/**
 * Get device statistics summary
 * Accepts devices array directly from backend (raw) or formatted objects.
 * @param {Array} devices - Array of device objects
 * @returns {Object} Statistics summary
 */
export const getDeviceStatistics = (devices) => {
  if (!devices || devices.length === 0) {
    return {
      totalDevices: 0,
      connectedDevices: 0,
      totalPackets: 0,
      averageConfidence: 0,
      highConfidenceDevices: 0,
      mediumConfidenceDevices: 0,
      lowConfidenceDevices: 0,
    };
  }

  // Support both raw backend objects and formatted objects
  const totalPackets = devices.reduce((sum, d) => {
    // prefer backend-style total_packets else totalPackets else 0
    return sum + (d.total_packets ?? d.totalPackets ?? 0);
  }, 0);

  const connectedDevices = devices.filter((d) => {
    return !!(d.connected_to_router ?? d.connectedToRouter);
  }).length;

  const averageConfidence =
    devices.reduce((sum, d) => sum + (d.confidence ?? 0), 0) / devices.length;

  return {
    totalDevices: devices.length,
    connectedDevices,
    totalPackets,
    averageConfidence: parseFloat(averageConfidence.toFixed(2)),
    highConfidenceDevices: filterDevicesByConfidence(devices, 'high').length,
    mediumConfidenceDevices: filterDevicesByConfidence(devices, 'medium').length,
    lowConfidenceDevices: filterDevicesByConfidence(devices, 'low').length,
  };
};

export default {
  analyzeLatestCapture,
  formatDeviceInfo,
  getConfidenceLabel,
  getConfidenceColor,
  filterDevicesByConfidence,
  sortDevices,
  getDeviceStatistics,
};
