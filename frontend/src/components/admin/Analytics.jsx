import { useState } from 'react';
import { BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { FiDownload, FiFilter, FiRefreshCw } from 'react-icons/fi';
import Loader from '../shared/Loader';

const COLORS = ['#3B82F6', '#10B981', '#A78BFA', '#F472B6', '#F59E0B'];

export default function Analytics() {
  const [timeRange, setTimeRange] = useState('weekly');
  const [loading, setLoading] = useState(false);
  
  // Mock data - replace with API data
  const threatData = [
    { name: 'Malware', value: 35 },
    { name: 'Phishing', value: 25 },
    { name: 'DDoS', value: 15 },
    { name: 'Brute Force', value: 10 },
    { name: 'Insider Threat', value: 5 },
  ];

  const trendData = [
    { name: 'Jan', threats: 40, incidents: 12 },
    { name: 'Feb', threats: 32, incidents: 8 },
    { name: 'Mar', threats: 28, incidents: 6 },
    { name: 'Apr', threats: 45, incidents: 15 },
    { name: 'May', threats: 38, incidents: 10 },
  ];

  const clientRiskData = [
    { name: 'Client A', risk: 85 },
    { name: 'Client B', risk: 72 },
    { name: 'Client C', risk: 63 },
    { name: 'Client D', risk: 54 },
    { name: 'Client E', risk: 42 },
  ];

  const handleExport = () => {
    // Implement export functionality
    console.log('Exporting analytics data');
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">Threat Analytics</h2>
        <div className="flex space-x-3">
          <button
            onClick={() => setLoading(true)}
            className="inline-flex items-center px-3 py-2 border border-dark-light text-sm font-medium rounded-md shadow-sm text-white bg-dark-light hover:bg-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
          >
            <FiFilter className="mr-2" /> Filter
          </button>
          <button
            onClick={handleExport}
            className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
          >
            <FiDownload className="mr-2" /> Export
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <Loader size="lg" />
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-dark-light rounded-lg shadow p-4 border border-dark-light">
            <h3 className="text-lg font-medium text-white mb-4">Threat Distribution</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={threatData}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  >
                    {threatData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="bg-dark-light rounded-lg shadow p-4 border border-dark-light">
            <h3 className="text-lg font-medium text-white mb-4">Monthly Threat Trends</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" stroke="#94A3B8" />
                  <YAxis stroke="#94A3B8" />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="threats" stroke="#3B82F6" activeDot={{ r: 8 }} />
                  <Line type="monotone" dataKey="incidents" stroke="#10B981" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="bg-dark-light rounded-lg shadow p-4 border border-dark-light lg:col-span-2">
            <h3 className="text-lg font-medium text-white mb-4">Client Risk Assessment</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={clientRiskData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="name" stroke="#94A3B8" />
                  <YAxis stroke="#94A3B8" />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="risk" fill="#A78BFA" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}