import { useState, useEffect } from 'react';
import { FiRefreshCw, FiServer, FiShield, FiAlertTriangle, FiWifiOff } from 'react-icons/fi';
import api from '../../api/userApi';
import { toast } from 'react-toastify';
import Loader from '../shared/Loader';

const statusColors = {
  online: 'text-success',
  offline: 'text-gray-500',
  compromised: 'text-danger',
  at_risk: 'text-warning',
};

const statusIcons = {
  online: FiServer,
  offline: FiWifiOff,
  compromised: FiAlertTriangle,
  at_risk: FiShield,
};

export default function DeviceManagement() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);

  useEffect(() => {
    fetchDevices();
  }, []);

  const fetchDevices = async () => {
    try {
      setLoading(true);
      const response = await api.getDevices();
      setDevices(response.data);
    } catch (error) {
      toast.error('Failed to fetch devices');
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    try {
      setRefreshing(true);
      await fetchDevices();
      toast.success('Devices refreshed');
    } catch (error) {
      toast.error('Failed to refresh devices');
    } finally {
      setRefreshing(false);
    }
  };

  const handleScanDevice = async (deviceId) => {
    try {
      await api.scanDevice(deviceId);
      toast.success('Scan initiated successfully');
      fetchDevices();
    } catch (error) {
      toast.error('Failed to initiate scan');
    }
  };

  const handleIsolateDevice = async (deviceId) => {
    if (window.confirm('Are you sure you want to isolate this device?')) {
      try {
        await api.isolateDevice(deviceId);
        toast.success('Device isolation initiated');
        fetchDevices();
      } catch (error) {
        toast.error('Failed to isolate device');
      }
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">Device Management</h2>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
        >
          <FiRefreshCw className={`mr-2 h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
          {refreshing ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <Loader size="lg" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {devices.map((device) => {
            const StatusIcon = statusIcons[device.status] || FiServer;
            return (
              <div
                key={device._id}
                className={`bg-dark-light rounded-lg shadow p-4 border ${
                  device.status === 'online' ? 'border-dark-light hover:border-cyber-blue' :
                  device.status === 'compromised' ? 'border-danger' :
                  device.status === 'at_risk' ? 'border-warning' : 'border-gray-500'
                } transition-colors`}
                onClick={() => setSelectedDevice(device)}
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-lg font-medium text-white">{device.name}</h3>
                    <p className="text-sm text-gray-400">{device.ip}</p>
                  </div>
                  <div className={`flex items-center ${statusColors[device.status]}`}>
                    <StatusIcon className="h-5 w-5 mr-1" />
                    <span className="text-sm capitalize">{device.status.replace('_', ' ')}</span>
                  </div>
                </div>
                <div className="mt-4 grid grid-cols-2 gap-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleScanDevice(device._id);
                    }}
                    className="inline-flex items-center justify-center px-3 py-1 border border-transparent text-xs font-medium rounded-md text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
                  >
                    Scan
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleIsolateDevice(device._id);
                    }}
                    className="inline-flex items-center justify-center px-3 py-1 border border-transparent text-xs font-medium rounded-md text-white bg-danger hover:bg-danger-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-danger"
                    disabled={device.status === 'offline'}
                  >
                    Isolate
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {selectedDevice && (
        <div className="bg-dark-light rounded-lg shadow p-6 border border-dark-light">
          <div className="flex justify-between items-start">
            <div>
              <h3 className="text-xl font-bold text-white">{selectedDevice.name}</h3>
              <p className="text-gray-400">{selectedDevice.description}</p>
            </div>
            <button
              onClick={() => setSelectedDevice(null)}
              className="text-gray-400 hover:text-white"
            >
              &times;
            </button>
          </div>
          <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="text-sm font-medium text-gray-400">Device Information</h4>
              <dl className="mt-2 space-y-2">
                <div className="flex justify-between">
                  <dt className="text-sm text-gray-300">IP Address</dt>
                  <dd className="text-sm text-white">{selectedDevice.ip}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-sm text-gray-300">MAC Address</dt>
                  <dd className="text-sm text-white">{selectedDevice.mac}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-sm text-gray-300">Operating System</dt>
                  <dd className="text-sm text-white">{selectedDevice.os}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-sm text-gray-300">Last Seen</dt>
                  <dd className="text-sm text-white">{selectedDevice.lastSeen}</dd>
                </div>
              </dl>
            </div>
            <div>
              <h4 className="text-sm font-medium text-gray-400">Security Status</h4>
              <div className="mt-2 space-y-2">
                <div className="flex justify-between">
                  <span className="text-sm text-gray-300">Status</span>
                  <span className={`text-sm ${
                    selectedDevice.status === 'online' ? 'text-success' :
                    selectedDevice.status === 'compromised' ? 'text-danger' :
                    selectedDevice.status === 'at_risk' ? 'text-warning' : 'text-gray-500'
                  }`}>
                    {selectedDevice.status.replace('_', ' ')}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-300">Last Scan</span>
                  <span className="text-sm text-white">{selectedDevice.lastScan || 'Never'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-300">Vulnerabilities</span>
                  <span className="text-sm text-white">
                    {selectedDevice.vulnerabilitiesCount || 0} found
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-300">Threats Detected</span>
                  <span className="text-sm text-white">
                    {selectedDevice.threatsCount || 0} detected
                  </span>
                </div>
              </div>
            </div>
          </div>
          <div className="mt-6 flex space-x-3">
            <button
              onClick={() => handleScanDevice(selectedDevice._id)}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
            >
              Scan Now
            </button>
            <button
              onClick={() => handleIsolateDevice(selectedDevice._id)}
              disabled={selectedDevice.status === 'offline'}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-danger hover:bg-danger-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-danger"
            >
              Isolate Device
            </button>
          </div>
        </div>
      )}
    </div>
  );
}