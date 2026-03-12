import { useState, useEffect } from 'react';
import { FiAlertTriangle, FiServer, FiShield, FiTrendingUp } from 'react-icons/fi';
import Navbar from '../../components/shared/Navbar';
import Sidebar from '../../components/shared/Sidebar';
import Loader from '../../components/shared/Loader';
import api from '../../api/userApi';
import { toast } from 'react-toastify';

export default function UserDashboardPage() {
  const [stats, setStats] = useState({
    totalDevices: 0,
    onlineDevices: 0,
    threatsDetected: 0,
    vulnerabilities: 0,
  });
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      // Fetch dashboard statistics
      const statsResponse = await api.getDashboardStats();
      setStats(statsResponse.data);

      // Fetch recent alerts
      const alertsResponse = await api.getRecentAlerts();
      setRecentAlerts(alertsResponse.data);
    } catch (error) {
      toast.error('Failed to load dashboard data');
      console.error('Dashboard error:', error);
    } finally {
      setLoading(false);
    }
  };

  const StatCard = ({ icon: Icon, label, value, color }) => (
    <div className="bg-dark-light rounded-lg shadow p-6 border border-dark-light hover:border-cyber-blue transition-colors">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-400 text-sm font-medium">{label}</p>
          <p className="text-3xl font-bold text-white mt-2">{value}</p>
        </div>
        <div className={`p-3 rounded-lg ${color}`}>
          <Icon className="h-6 w-6 text-white" />
        </div>
      </div>
    </div>
  );

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
            <div>
              <h1 className="text-3xl font-bold text-white">Dashboard</h1>
              <p className="text-gray-400 mt-2">Welcome back! Here's an overview of your security status.</p>
            </div>

            {/* Statistics Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <StatCard
                icon={FiServer}
                label="Total Devices"
                value={stats.totalDevices}
                color="bg-cyber-blue"
              />
              <StatCard
                icon={FiShield}
                label="Online Devices"
                value={stats.onlineDevices}
                color="bg-success"
              />
              <StatCard
                icon={FiAlertTriangle}
                label="Threats Detected"
                value={stats.threatsDetected}
                color="bg-danger"
              />
              <StatCard
                icon={FiTrendingUp}
                label="Vulnerabilities"
                value={stats.vulnerabilities}
                color="bg-warning"
              />
            </div>

            {/* Recent Alerts */}
            <div className="bg-dark-light rounded-lg shadow border border-dark-light">
              <div className="p-6 border-b border-dark-light">
                <h2 className="text-xl font-bold text-white">Recent Alerts</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-dark">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                        Alert Type
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                        Device
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                        Severity
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                        Time
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                        Status
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark">
                    {recentAlerts.length > 0 ? (
                      recentAlerts.map((alert) => (
                        <tr key={alert._id} className="hover:bg-dark transition-colors">
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-white">
                            {alert.type}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                            {alert.deviceName}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                              alert.severity === 'critical' ? 'bg-danger text-white' :
                              alert.severity === 'high' ? 'bg-warning text-white' :
                              alert.severity === 'medium' ? 'bg-cyber-blue text-white' :
                              'bg-gray-600 text-white'
                            }`}>
                              {alert.severity}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                            {new Date(alert.timestamp).toLocaleString()}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                              alert.status === 'resolved' ? 'bg-success text-white' :
                              alert.status === 'investigating' ? 'bg-cyber-blue text-white' :
                              'bg-warning text-white'
                            }`}>
                              {alert.status}
                            </span>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="5" className="px-6 py-4 text-center text-gray-400">
                          No recent alerts
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
