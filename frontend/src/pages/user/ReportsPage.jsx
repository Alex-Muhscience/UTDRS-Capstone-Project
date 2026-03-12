import { useState, useEffect } from 'react';
import { FiDownload, FiRefreshCw, FiPlus, FiTrash2 } from 'react-icons/fi';
import Navbar from '../../components/shared/Navbar';
import Sidebar from '../../components/shared/Sidebar';
import Loader from '../../components/shared/Loader';
import api from '../../api/userApi';
import { toast } from 'react-toastify';

export default function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [showGenerateForm, setShowGenerateForm] = useState(false);
  const [formData, setFormData] = useState({
    reportType: 'security',
    timeRange: '7days',
    includeDevices: true,
    includeThreats: true,
    includeVulnerabilities: true,
  });

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      setLoading(true);
      const response = await api.getReports();
      setReports(response.data);
    } catch (error) {
      toast.error('Failed to fetch reports');
      console.error('Reports error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    try {
      setRefreshing(true);
      await fetchReports();
      toast.success('Reports refreshed');
    } catch (error) {
      toast.error('Failed to refresh reports');
    } finally {
      setRefreshing(false);
    }
  };

  const handleGenerateReport = async (e) => {
    e.preventDefault();
    try {
      const response = await api.generateReport(formData);
      toast.success('Report generation initiated');
      setShowGenerateForm(false);
      setFormData({
        reportType: 'security',
        timeRange: '7days',
        includeDevices: true,
        includeThreats: true,
        includeVulnerabilities: true,
      });
      await fetchReports();
    } catch (error) {
      toast.error('Failed to generate report');
    }
  };

  const handleDownloadReport = async (reportId) => {
    try {
      const response = await api.downloadReport(reportId);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `report-${reportId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
      toast.success('Report downloaded');
    } catch (error) {
      toast.error('Failed to download report');
    }
  };

  const handleDeleteReport = async (reportId) => {
    if (window.confirm('Are you sure you want to delete this report?')) {
      try {
        setReports(reports.filter(r => r._id !== reportId));
        toast.success('Report deleted');
      } catch (error) {
        toast.error('Failed to delete report');
      }
    }
  };

  if (loading) {
    return (
      <div className="h-screen bg-dark-darker overflow-hidden flex">
        <Sidebar />
        <div className="flex-1 flex flex-col overflow-hidden">
          <Navbar />
          <main className="flex-1 overflow-y-auto p-4 md:p-6 bg-dark-darker flex items-center justify-center">
            <Loader size="lg" />
          </main>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen bg-dark-darker overflow-hidden flex">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Navbar />
        <main className="flex-1 overflow-y-auto p-4 md:p-6 bg-dark-darker">
          <div className="max-w-7xl mx-auto space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-white">Reports</h1>
                <p className="text-gray-400 mt-2">Generate and manage security reports.</p>
              </div>
              <div className="flex gap-3">
                <button
                  onClick={handleRefresh}
                  disabled={refreshing}
                  className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-dark-light hover:bg-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
                >
                  <FiRefreshCw className={`mr-2 h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
                  Refresh
                </button>
                <button
                  onClick={() => setShowGenerateForm(!showGenerateForm)}
                  className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
                >
                  <FiPlus className="mr-2 h-4 w-4" />
                  Generate Report
                </button>
              </div>
            </div>

            {/* Generate Report Form */}
            {showGenerateForm && (
              <div className="bg-dark-light rounded-lg shadow p-6 border border-dark-light">
                <h2 className="text-xl font-bold text-white mb-4">Generate New Report</h2>
                <form onSubmit={handleGenerateReport} className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-400 mb-1">Report Type</label>
                      <select
                        value={formData.reportType}
                        onChange={(e) => setFormData({ ...formData, reportType: e.target.value })}
                        className="bg-dark border border-dark-light text-white text-sm rounded-lg focus:ring-cyber-blue focus:border-cyber-blue block w-full p-2"
                      >
                        <option value="security">Security Summary</option>
                        <option value="compliance">Compliance Report</option>
                        <option value="vulnerability">Vulnerability Assessment</option>
                        <option value="incident">Incident Report</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-400 mb-1">Time Range</label>
                      <select
                        value={formData.timeRange}
                        onChange={(e) => setFormData({ ...formData, timeRange: e.target.value })}
                        className="bg-dark border border-dark-light text-white text-sm rounded-lg focus:ring-cyber-blue focus:border-cyber-blue block w-full p-2"
                      >
                        <option value="7days">Last 7 Days</option>
                        <option value="30days">Last 30 Days</option>
                        <option value="90days">Last 90 Days</option>
                        <option value="1year">Last Year</option>
                      </select>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={formData.includeDevices}
                        onChange={(e) => setFormData({ ...formData, includeDevices: e.target.checked })}
                        className="rounded border-dark-light text-cyber-blue focus:ring-cyber-blue"
                      />
                      <span className="ml-2 text-sm text-gray-400">Include Device Information</span>
                    </label>
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={formData.includeThreats}
                        onChange={(e) => setFormData({ ...formData, includeThreats: e.target.checked })}
                        className="rounded border-dark-light text-cyber-blue focus:ring-cyber-blue"
                      />
                      <span className="ml-2 text-sm text-gray-400">Include Threats</span>
                    </label>
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={formData.includeVulnerabilities}
                        onChange={(e) => setFormData({ ...formData, includeVulnerabilities: e.target.checked })}
                        className="rounded border-dark-light text-cyber-blue focus:ring-cyber-blue"
                      />
                      <span className="ml-2 text-sm text-gray-400">Include Vulnerabilities</span>
                    </label>
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="submit"
                      className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
                    >
                      Generate
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowGenerateForm(false)}
                      className="inline-flex items-center px-4 py-2 border border-dark-light text-sm font-medium rounded-md shadow-sm text-white bg-dark-light hover:bg-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* Reports List */}
            <div className="bg-dark-light rounded-lg shadow border border-dark-light overflow-x-auto">
              <table className="w-full">
                <thead className="bg-dark">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Report Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Generated
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Time Range
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark">
                  {reports.length > 0 ? (
                    reports.map((report) => (
                      <tr key={report._id} className="hover:bg-dark transition-colors">
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-white font-medium">
                          {report.reportType || 'Security Report'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                          {new Date(report.createdAt).toLocaleString()}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                          {report.timeRange || 'N/A'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                            report.status === 'completed' ? 'bg-success text-white' :
                            report.status === 'processing' ? 'bg-cyber-blue text-white' :
                            'bg-warning text-white'
                          }`}>
                            {report.status || 'Completed'}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm space-x-2">
                          <button
                            onClick={() => handleDownloadReport(report._id)}
                            className="text-cyber-blue hover:text-cyber-blue-dark inline-flex items-center"
                          >
                            <FiDownload className="mr-1 h-4 w-4" />
                            Download
                          </button>
                          <button
                            onClick={() => handleDeleteReport(report._id)}
                            className="text-danger hover:text-danger-dark inline-flex items-center"
                          >
                            <FiTrash2 className="mr-1 h-4 w-4" />
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="5" className="px-6 py-4 text-center text-gray-400">
                        No reports generated yet
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
