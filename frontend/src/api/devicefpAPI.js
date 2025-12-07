const API_BASE_URL = 'http://localhost:5000/api/devicefp';

/**
 * Analyze the latest capture file for device fingerprinting
 * @returns {Promise<Object>} Analysis results containing detected devices
 */
export const analyzeLatestCapture = async () => {
  try {
    const response = await fetch(`${API_BASE_URL}/analyze-latest`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json();
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
 * Format device data for display
 * @param {Object} device - Device object from API
 * @returns {Object} Formatted device information
 */
export const formatDeviceInfo = (device) => {
  return {
    name: device.device_name || 'Unknown Device',
    mac: device.mac_address || 'N/A',
    vendor: device.vendor || 'Unknown',
    totalPackets: device.total_packets || 0,
    dataPackets: device.packet_types?.data?.count || 0,
    dataPercentage: device.packet_types?.data?.percentage || 0,
    managementPackets: device.packet_types?.management?.count || 0,
    managementPercentage: device.packet_types?.management?.percentage || 0,
    controlPackets: device.packet_types?.control?.count || 0,
    controlPercentage: device.packet_types?.control?.percentage || 0,
    firstSeen: device.first_seen || 'N/A',
    lastSeen: device.last_seen || 'N/A',
    avgSignalStrength: device.avg_signal_strength,
    connectedToRouter: device.connected_to_router || false,
    confidence: device.confidence || 0,
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
 * @param {Array} devices - Array of device objects
 * @param {string} level - Confidence level ('high', 'medium', 'low', 'all')
 * @returns {Array} Filtered devices
 */
export const filterDevicesByConfidence = (devices, level = 'all') => {
  if (level === 'all') return devices;

  return devices.filter((device) => {
    const confidence = device.confidence || 0;
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
 * @param {Array} devices - Array of device objects
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

    if (order === 'asc') {
      return aValue > bValue ? 1 : -1;
    }
    return aValue < bValue ? 1 : -1;
  });
};

/**
 * Get device statistics summary
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

  const totalPackets = devices.reduce((sum, d) => sum + (d.total_packets || 0), 0);
  const connectedDevices = devices.filter((d) => d.connected_to_router).length;
  const averageConfidence =
    devices.reduce((sum, d) => sum + (d.confidence || 0), 0) / devices.length;

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
