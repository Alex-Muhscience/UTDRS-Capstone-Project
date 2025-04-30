import { useState } from 'react';
import { FiAlertTriangle, FiFilter, FiDownload } from 'react-icons/fi';
import { severityColors } from '../../utils/helpers';
import Modal from '../shared/Modal';

export default function Vulnerabilities() {
  const [vulnerabilities, setVulnerabilities] = useState([
    {
      id: 'CVE-2025-1234',
      name: 'Remote Code Execution in Apache Server',
      severity: 'critical',
      cvssScore: 9.8,
      affectedDevices: 5,
      patchStatus: 'unpatched',
      description: 'Allows attackers to execute arbitrary code through specially crafted requests'
    },
    {
      id: 'CVE-2025-5678',
      name: 'Privilege Escalation in Windows Service',
      severity: 'high',
      cvssScore: 7.5,
      affectedDevices: 3,
      patchStatus: 'available',
      description: 'Local users can gain elevated privileges due to improper access controls'
    },
    {
      id: 'CVE-2025-9012',
      name: 'Cross-Site Scripting in Web Application',
      severity: 'medium',
      cvssScore: 6.1,
      affectedDevices: 2,
      patchStatus: 'patched',
      description: 'Stored XSS vulnerability allows injection of malicious scripts'
    }
  ]);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [filters, setFilters] = useState({
    severity: 'all',
    patchStatus: 'all'
  });

  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    return (
      (filters.severity === 'all' || vuln.severity === filters.severity) &&
      (filters.patchStatus === 'all' || vuln.patchStatus === filters.patchStatus)
    );
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">Vulnerabilities</h2>
        <div className="flex space-x-3">
          <button className="inline-flex items-center px-3 py-2 border border-dark-light text-sm font-medium rounded-md shadow-sm text-white bg-dark-light hover:bg-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue">
            <FiFilter className="mr-2" /> Filter
          </button>
          <button className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue">
            <FiDownload className="mr-2" /> Export
          </button>
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
              {filteredVulnerabilities.map((vuln) => (
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