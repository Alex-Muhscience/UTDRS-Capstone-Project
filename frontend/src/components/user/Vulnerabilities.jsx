import { useState, useEffect } from 'react';
import { FiAlertTriangle, FiFilter, FiDownload, FiRefreshCw } from 'react-icons/fi';
import api from '../../api/userApi';
import { toast } from 'react-toastify';
import Loader from '../shared/Loader';
import Modal from '../shared/Modal';

export default function Vulnerabilities() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [filters, setFilters] = useState({
    severity: 'all',
    patchStatus: 'all'
  });

  useEffect(() => {
    fetchVulnerabilities();
  }, [filters]);

  const fetchVulnerabilities = async () => {
    try {
      setLoading(true);
      const response = await api.getVulnerabilities(filters);
      setVulnerabilities(response.data);
    } catch (error) {
      toast.error('Failed to fetch vulnerabilities');
      console.error('Vulnerabilities error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    try {
      setRefreshing(true);
      await fetchVulnerabilities();
      toast.success('Vulnerabilities refreshed');
    } catch (error) {
      toast.error('Failed to refresh vulnerabilities');
    } finally {
      setRefreshing(false);
    }
  };

  const handleRemediate = async (vulnId) => {
    try {
      await api.remediateVulnerability(vulnId, { action: 'patch' });
      toast.success('Remediation action initiated');
      await fetchVulnerabilities();
    } catch (error) {
      toast.error('Failed to initiate remediation');
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
        <h2 className="text-xl font-bold text-white">Vulnerabilities</h2>
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
        >
          <FiRefreshCw className={`mr-2 h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
          {refreshing ? 'Refreshing...' : 'Refresh'}
        </button>
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
          <label className="block text-sm font-medium text-gray-400 mb-1">Patch Status</label>
          <select
            value={filters.patchStatus}
            onChange={(e) => setFilters({ ...filters, patchStatus: e.target.value })}
            className="bg-dark border border-dark-light text-white text-sm rounded-lg focus:ring-cyber-blue focus:border-cyber-blue block w-full p-2"
          >
            <option value="all">All Status</option>
            <option value="unpatched">Unpatched</option>
            <option value="available">Patch Available</option>
            <option value="patched">Patched</option>
          </select>
        </div>
      </div>

      <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-dark-light">
            <thead className="bg-dark">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  CVE ID
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Vulnerability
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Severity
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  CVSS Score
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Affected Devices
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Patch Status
                </th>
                <th scope="col" className="relative px-6 py-3">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="bg-dark-light divide-y divide-dark-light">
              {vulnerabilities.map((vuln) => (
                <tr key={vuln.id} className="hover:bg-dark">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-cyber-blue">
                    {vuln.id}
                  </td>
                  <td className="px-6 py-4 text-sm text-white max-w-xs truncate">
                    {vuln.name}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${severityColors[vuln.severity]}`}>
                      {vuln.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {vuln.cvssScore}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {vuln.affectedDevices}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    <span className="capitalize">{vuln.patchStatus}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => setSelectedVuln(vuln)}
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

      {selectedVuln && (
        <Modal 
          isOpen={!!selectedVuln} 
          onClose={() => setSelectedVuln(null)} 
          title={`Vulnerability: ${selectedVuln.id}`}
          size="lg"
        >
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-medium text-white">{selectedVuln.name}</h3>
              <p className="mt-1 text-sm text-gray-300">{selectedVuln.description}</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="text-sm font-medium text-gray-400">Severity</h4>
                <p className="mt-1 text-sm text-white">
                  <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${severityColors[selectedVuln.severity]}`}>
                    {selectedVuln.severity}
                  </span>
                </p>
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-400">CVSS Score</h4>
                <p className="mt-1 text-sm text-white">{selectedVuln.cvssScore}</p>
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-400">Affected Devices</h4>
                <p className="mt-1 text-sm text-white">{selectedVuln.affectedDevices}</p>
              </div>
              <div>
                <h4 className="text-sm font-medium text-gray-400">Patch Status</h4>
                <p className="mt-1 text-sm text-white capitalize">{selectedVuln.patchStatus}</p>
              </div>
            </div>

            <div className="pt-4">
              <h4 className="text-sm font-medium text-gray-400">Recommended Actions</h4>
              <div className="mt-2 space-y-2">
                {selectedVuln.patchStatus === 'unpatched' && (
                  <p className="text-sm text-danger">
                    <strong>Critical:</strong> Apply security patches immediately. Isolate affected systems if possible.
                  </p>
                )}
                {selectedVuln.patchStatus === 'available' && (
                  <p className="text-sm text-warning">
                    <strong>Update available:</strong> Schedule patch deployment during next maintenance window.
                  </p>
                )}
                {selectedVuln.patchStatus === 'patched' && (
                  <p className="text-sm text-success">
                    <strong>Resolved:</strong> Vulnerability has been patched on all affected systems.
                  </p>
                )}
                <p className="text-sm text-gray-300 mt-2">
                  For detailed mitigation steps, consult the official CVE documentation or your security team.
                </p>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}