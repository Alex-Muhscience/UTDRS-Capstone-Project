import { useState, useEffect } from 'react';
import { FiRefreshCw, FiPlus, FiEdit2, FiTrash2 } from 'react-icons/fi';
import { LICENSE_TIERS } from '../../utils/constants';
import Modal from '../shared/Modal';
import Loader from '../shared/Loader';

export default function LicenseManager() {
  const [licenses, setLicenses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [currentLicense, setCurrentLicense] = useState(null);
  const [formData, setFormData] = useState({
    client: '',
    tier: 'basic',
    startDate: new Date().toISOString().split('T')[0],
    endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
  });

  useEffect(() => {
    fetchLicenses();
  }, []);

  const fetchLicenses = async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 800));
      const mockLicenses = [
        {
          id: 1,
          client: 'Acme Corporation',
          tier: 'pro',
          startDate: '2025-01-15',
          endDate: '2025-07-15',
          status: 'active'
        },
        {
          id: 2,
          client: 'Globex Inc',
          tier: 'enterprise',
          startDate: '2025-03-01',
          endDate: '2026-03-01',
          status: 'active'
        },
        {
          id: 3,
          client: 'Initech',
          tier: 'basic',
          startDate: '2025-04-10',
          endDate: '2025-05-10',
          status: 'trial'
        }
      ];
      setLicenses(mockLicenses);
    } catch (error) {
      console.error('Failed to fetch licenses:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 500));
      
      if (currentLicense) {
        // Update existing license
        setLicenses(licenses.map(license => 
          license.id === currentLicense.id ? { ...license, ...formData } : license
        ));
      } else {
        // Add new license
        const newLicense = {
          id: Date.now(),
          ...formData,
          status: formData.endDate > new Date().toISOString() ? 'active' : 'expired'
        };
        setLicenses([...licenses, newLicense]);
      }
      
      setIsModalOpen(false);
      setCurrentLicense(null);
      setFormData({
        client: '',
        tier: 'basic',
        startDate: new Date().toISOString().split('T')[0],
        endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
      });
    } catch (error) {
      console.error('Operation failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (license) => {
    setCurrentLicense(license);
    setFormData({
      client: license.client,
      tier: license.tier,
      startDate: license.startDate,
      endDate: license.endDate
    });
    setIsModalOpen(true);
  };

  const handleDelete = (licenseId) => {
    if (window.confirm('Are you sure you want to delete this license?')) {
      setLicenses(licenses.filter(license => license.id !== licenseId));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">License Management</h2>
        <div className="flex space-x-3">
          <button
            onClick={fetchLicenses}
            className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
          >
            <FiRefreshCw className="mr-2" /> Refresh
          </button>
          <button
            onClick={() => {
              setCurrentLicense(null);
              setIsModalOpen(true);
            }}
            className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
          >
            <FiPlus className="mr-2" /> Add License
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <Loader size="lg" />
        </div>
      ) : (
        <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-dark-light">
              <thead className="bg-dark">
                <tr>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Client
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    License Tier
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Start Date
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    End Date
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
                {licenses.map((license) => (
                  <tr key={license.id} className="hover:bg-dark">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">
                      {license.client}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${LICENSE_TIERS[license.tier]?.color || 'bg-gray-500'} text-white`}>
                        {LICENSE_TIERS[license.tier]?.name || license.tier}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      {new Date(license.startDate).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      {new Date(license.endDate).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        license.status === 'active' ? 'bg-success text-white' :
                        license.status === 'trial' ? 'bg-info text-white' :
                        'bg-danger text-white'
                      }`}>
                        {license.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <button
                        onClick={() => handleEdit(license)}
                        className="text-cyber-blue hover:text-cyber-blue-dark mr-3"
                      >
                        <FiEdit2 />
                      </button>
                      <button
                        onClick={() => handleDelete(license.id)}
                        className="text-danger hover:text-danger-dark"
                      >
                        <FiTrash2 />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <Modal 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)} 
        title={currentLicense ? 'Edit License' : 'Add New License'}
      >
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="client" className="block text-sm font-medium text-gray-300">
              Client Name
            </label>
            <input
              type="text"
              id="client"
              name="client"
              value={formData.client}
              onChange={handleInputChange}
              required
              className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
            />
          </div>
          <div>
            <label htmlFor="tier" className="block text-sm font-medium text-gray-300">
              License Tier
            </label>
            <select
              id="tier"
              name="tier"
              value={formData.tier}
              onChange={handleInputChange}
              className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
            >
              <option value="basic">Basic</option>
              <option value="pro">Professional</option>
              <option value="enterprise">Enterprise</option>
            </select>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label htmlFor="startDate" className="block text-sm font-medium text-gray-300">
                Start Date
              </label>
              <input
                type="date"
                id="startDate"
                name="startDate"
                value={formData.startDate}
                onChange={handleInputChange}
                required
                className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
              />
            </div>
            <div>
              <label htmlFor="endDate" className="block text-sm font-medium text-gray-300">
                End Date
              </label>
              <input
                type="date"
                id="endDate"
                name="endDate"
                value={formData.endDate}
                onChange={handleInputChange}
                required
                className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
              />
            </div>
          </div>
          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={() => setIsModalOpen(false)}
              className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-dark-light hover:bg-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
            >
              {loading ? 'Saving...' : 'Save License'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}