import { useState, useEffect } from 'react';
import { FiAlertTriangle, FiFilter, FiDownload, FiRefreshCw } from 'react-icons/fi';
import api from '../../api/userApi';
import { toast } from 'react-toastify';
import Loader from '../shared/Loader';
import Modal from '../shared/Modal';

export default function Threats() {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [filters, setFilters] = useState({
    severity: 'all',
    status: 'all'
  });

  useEffect(() => {
    fetchThreats();
  }, [filters]);

  const fetchThreats = async () => {
    try {
      setLoading(true);
      const response = await api.getThreats(filters);
      setThreats(response.data);
    } catch (error) {
      toast.error('Failed to fetch threats');
      console.error('Threats error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    try {
      setRefreshing(true);
      await fetchThreats();
      toast.success('Threats refreshed');
    } catch (error) {
      toast.error('Failed to refresh threats');
    } finally {
      setRefreshing(false);
    }
  };

  const handleStatusChange = async (threatId, newStatus) => {
    try {
      await api.respondToThreat(threatId, newStatus);
      setThreats(threats.map(threat => 
        threat._id === threatId ? { ...threat, status: newStatus } : threat
      ));
      if (selectedThreat?._id === threatId) {
        setSelectedThreat({ ...selectedThreat, status: newStatus });
      }
      toast.success('Threat status updated');
    } catch (error) {
      toast.error('Failed to update threat status');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader size="lg" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">Threats & Incidents</h2>
        <div className="flex space-x-3">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
          >
            <FiRefreshCw className={`mr-2 h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-dark-light rounded-lg shadow p-4 border border-dark-light flex gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-1">Severity</label>
          <select
            value={filters.severity}
            onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
            className="bg-dark border border-dark-light text-white text-sm rounded-lg focus:ring-cyber-blue focus:border-cyber-blue block w-full p-2"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-1">Status</label>
          <select
            value={filters.status}
            onChange={(e) => setFilters({ ...filters, status: e.target.value })}
            className="bg-dark border border-dark-light text-white text-sm rounded-lg focus:ring-cyber-blue focus:border-cyber-blue block w-full p-2"
          >
            <option value="all">All Status</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="mitigated">Mitigated</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
      </div>

      <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-dark-light">
            <thead className="bg-dark">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Threat
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Severity
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Source
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Detected
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th scope="col" className="relative px-6 py-3">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="bg-dark-light divide-y divide-dark-light">
              {threats.map((threat) => (
                <tr key={threat.id} className="hover:bg-dark">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="flex-shrink-0 h-10 w-10 rounded-full bg-danger bg-opacity-20 flex items-center justify-center">
                        <FiAlertTriangle className="h-5 w-5 text-danger" />
                      </div>
                      <div className="ml-4">
                        <div className="text-sm font-medium text-white">{threat.type}</div>
                        <div className="text-sm text-gray-300 truncate max-w-xs">{threat.description}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                      threat.severity === 'critical' ? 'bg-danger text-white' :
                      threat.severity === 'high' ? 'bg-warning text-white' :
                      threat.severity === 'medium' ? 'bg-cyber-blue text-white' :
                      'bg-gray-600 text-white'
                    }`}>
                      {threat.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {threat.source || 'Unknown'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {new Date(threat.detectedAt).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    <span className="capitalize">{threat.status}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => setSelectedThreat(threat)}
                      className="text-cyber-blue hover:text-cyber-blue-dark"
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selectedThreat && (
        <Modal 
          isOpen={!!selectedThreat} 
          onClose={() => setSelectedThreat(null)} 
          title={`Threat: ${selectedThreat.name}`}
          size="lg"
        >
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="text-sm font-medium text-gray-400">Severity</h4>
                <p className="mt-1 text-sm text-white">
                  <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${severityColors[selectedThreat.severity]}`}>
                    {selectedThreat.severity}
                  </span>
                </p>
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-400">Status</h4>
                <p className="mt-1 text-sm text-white capitalize">{selectedThreat.status}</p>
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-400">Source</h4>
                <p className="mt-1 text-sm text-white">{selectedThreat.source}</p>
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-400">Detected At</h4>
                <p className="mt-1 text-sm text-white">
                  {new Date(selectedThreat.detectedAt).toLocaleString()}
                </p>
              </div>
            </div>

            <div>
              <h4 className="text-sm font-medium text-gray-400">Description</h4>
              <p className="mt-1 text-sm text-white">{selectedThreat.description}</p>
            </div>

            <div className="pt-4">
              <h4 className="text-sm font-medium text-gray-400">Actions</h4>
              <div className="mt-2 flex flex-wrap gap-2">
                <select
                  value={selectedThreat.status}
                  onChange={(e) => handleStatusChange(selectedThreat.id, e.target.value)}
                  className="bg-dark-light border border-dark-light text-white text-sm rounded-md focus:ring-cyber-blue focus:border-cyber-blue block p-1"
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="mitigated">Mitigated</option>
                  <option value="resolved">Resolved</option>
                </select>
                <button className="inline-flex items-center px-3 py-1 border border-transparent text-xs font-medium rounded-md text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue">
                  Escalate to Admin
                </button>
                <button className="inline-flex items-center px-3 py-1 border border-transparent text-xs font-medium rounded-md text-white bg-danger hover:bg-danger-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-danger">
                  Mark as False Positive
                </button>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}