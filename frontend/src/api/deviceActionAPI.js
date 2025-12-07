const API_BASE_URL = 'http://localhost:5000/api/deviceaction';

/**
 * Analyze device actions based on fingerprinted devices
 * @param {Array} devices - Array of devices from device fingerprinting
 * @param {string} pcapFile - Optional path to pcap file (uses latest if not provided)
 * @returns {Promise<Object>} Action analysis results with enriched device data
 */
export const analyzeDeviceActions = async (devices, pcapFile = null) => {
  try {
    const requestBody = {
      devices: devices,
    };

    if (pcapFile) {
      requestBody.pcap_file = pcapFile;
    }

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

/**
 * Get action statistics from enriched devices
 * @param {Array} devices - Array of devices with action data
 * @returns {Object} Statistics summary
 */
export const getActionStatistics = (devices) => {
  if (!devices || devices.length === 0) {
    return {
      totalDevices: 0,
      activeDevices: 0,
      triggeredDevices: 0,
      notTriggeredDevices: 0,
      nonTriggerableDevices: 0,
    };
  }

  const activeDevices = devices.filter((d) => d.is_active).length;
  const triggeredDevices = devices.filter((d) => d.is_triggered === true).length;
  const notTriggeredDevices = devices.filter(
    (d) => d.is_triggered === false && d.is_active
  ).length;
  const nonTriggerableDevices = devices.filter((d) => d.is_triggered === null).length;

  return {
    totalDevices: devices.length,
    activeDevices,
    triggeredDevices,
    notTriggeredDevices,
    nonTriggerableDevices,
  };
};

/**
 * Filter devices by trigger status
 * @param {Array} devices - Array of device objects
 * @param {string} status - Filter status ('triggered', 'not_triggered', 'non_triggerable', 'all')
 * @returns {Array} Filtered devices
 */
export const filterDevicesByTriggerStatus = (devices, status = 'all') => {
  if (status === 'all') return devices;

  return devices.filter((device) => {
    switch (status.toLowerCase()) {
      case 'triggered':
        return device.is_triggered === true;
      case 'not_triggered':
        return device.is_triggered === false;
      case 'non_triggerable':
        return device.is_triggered === null;
      default:
        return true;
    }
  });
};

/**
 * Get trigger status label
 * @param {boolean|null} isTriggered - Trigger status
 * @returns {string} Status label
 */
export const getTriggerStatusLabel = (isTriggered) => {
  if (isTriggered === null) return 'N/A';
  return isTriggered ? 'Triggered' : 'Not Triggered';
};

/**
 * Get trigger status color for UI
 * @param {boolean|null} isTriggered - Trigger status
 * @returns {string} Color code
 */
export const getTriggerStatusColor = (isTriggered) => {
  if (isTriggered === null) return '#6b7280'; // Gray
  return isTriggered ? '#ef4444' : '#10b981'; // Red for triggered, Green for not triggered
};

/**
 * Sort devices by trigger count
 * @param {Array} devices - Array of device objects
 * @param {string} order - Sort order ('asc' or 'desc')
 * @returns {Array} Sorted devices
 */
export const sortDevicesByTriggerCount = (devices, order = 'desc') => {
  return [...devices].sort((a, b) => {
    const aCount = a.trigger_count || 0;
    const bCount = b.trigger_count || 0;

    if (order === 'asc') {
      return aCount > bCount ? 1 : -1;
    }
    return aCount < bCount ? 1 : -1;
  });
};

/**
 * Format device actions for display
 * @param {Array} actions - Array of action strings
 * @returns {Array} Formatted actions
 */
export const formatDeviceActions = (actions) => {
  if (!actions || actions.length === 0) {
    return ['No actions detected'];
  }
  return actions;
};

export default {
  analyzeDeviceActions,
  getActionStatistics,
  filterDevicesByTriggerStatus,
  getTriggerStatusLabel,
  getTriggerStatusColor,
  sortDevicesByTriggerCount,
  formatDeviceActions,
};
