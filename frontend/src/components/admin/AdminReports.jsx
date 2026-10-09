import { useState } from 'react';
import { FiDownload, FiCalendar, FiFileText } from 'react-icons/fi';
import { REPORT_TYPES } from '../../utils/constants';
import Loader from '../shared/Loader';
import Modal from '../shared/Modal';

export default function Reports() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [reportType, setReportType] = useState('threats');
  const [dateRange, setDateRange] = useState({
    start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    end: new Date().toISOString().split('T')[0]
  });

  const generateReport = async () => {
    try {
      setLoading(true);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));
      const newReport = {
        id: Date.now(),
        type: reportType,
        dateRange,
        status: 'completed',
        createdAt: new Date().toISOString()
      };
      setReports([...reports, newReport]);
      setIsModalOpen(false);
    } catch (error) {
      console.error('Failed to generate report:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">Reports</h2>
        <button
          onClick={() => setIsModalOpen(true)}
          className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
        >
          Generate Report
        </button>
      </div>

      <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
        <div className="px-6 py-5 border-b border-dark-light">
          <h3 className="text-lg font-medium leading-6 text-white">Generated Reports</h3>
          <p className="mt-1 text-sm text-gray-400">Previously generated reports available for download</p>
        </div>
        {reports.length === 0 ? (
          <div className="px-6 py-12 text-center">
            <FiFileText className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-white">No reports generated</h3>
            <p className="mt-1 text-sm text-gray-400">Get started by generating a new report.</p>
            <div className="mt-6">
              <button
                onClick={() => setIsModalOpen(true)}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
              >
                Generate Report
              </button>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-dark-light">
              <thead className="bg-dark">
                <tr>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Report Type
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Date Range
                  </th>
                  <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Generated On
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
                {reports.map((report) => (
                  <tr key={report.id} className="hover:bg-dark">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">
                      {REPORT_TYPES.find(t => t.id === report.type)?.name || report.type}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      {new Date(report.dateRange.start).toLocaleDateString()} - {new Date(report.dateRange.end).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      {new Date(report.createdAt).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        report.status === 'completed' ? 'bg-success text-white' :
                        report.status === 'failed' ? 'bg-danger text-white' :
                        'bg-warning text-dark-darker'
                      }`}>
                        {report.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <button className="text-cyber-blue hover:text-cyber-blue-dark mr-3">
                        <FiDownload className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <Modal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} title="Generate New Report">
        <div className="space-y-4">
          <div>
            <label htmlFor="reportType" className="block text-sm font-medium text-gray-300">
              Report Type
            </label>
            <select
              id="reportType"
              value={reportType}
              onChange={(e) => setReportType(e.target.value)}
              className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
            >
              {REPORT_TYPES.map((type) => (
                <option key={type.id} value={type.id}>{type.name}</option>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label htmlFor="startDate" className="block text-sm font-medium text-gray-300">
                Start Date
              </label>
              <div className="mt-1 relative rounded-md shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <FiCalendar className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  type="date"
                  id="startDate"
                  value={dateRange.start}
                  onChange={(e) => setDateRange({...dateRange, start: e.target.value})}
                  className="block w-full pl-10 border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
                />
              </div>
            </div>
            <div>
              <label htmlFor="endDate" className="block text-sm font-medium text-gray-300">
                End Date
              </label>
              <div className="mt-1 relative rounded-md shadow-sm">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <FiCalendar className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  type="date"
                  id="endDate"
                  value={dateRange.end}
                  onChange={(e) => setDateRange({...dateRange, end: e.target.value})}
                  className="block w-full pl-10 border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
                />
              </div>
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
              type="button"
              onClick={generateReport}
              disabled={loading}
              className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
            >
              {loading ? 'Generating...' : 'Generate Report'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}