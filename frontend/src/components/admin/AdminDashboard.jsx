import { useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, AreaChart, Area
} from 'recharts'
import { 
  FiUsers, FiShield, FiServer, FiAlertTriangle, FiActivity, FiRefreshCw 
} from 'react-icons/fi'
import Loader from '../shared/Loader'
import { toast } from 'react-toastify'
import api from '../../api/adminApi'

const COLORS = ['#3B82F6', '#10B981', '#A78BFA', '#F472B6', '#F59E0B']

export default function AdminDashboard({ data, loading }) {
  const [timeRange, setTimeRange] = useState('weekly')
  const [refreshing, setRefreshing] = useState(false)
  
  const summaryCards = [
    { title: 'Total Clients', value: data.summaryCards[0]?.value || 0, icon: FiUsers, change: '+12%', trend: 'up' },
    { title: 'Active Licenses', value: data.summaryCards[1]?.value || 0, icon: FiShield, change: '+5%', trend: 'up' },
    { title: 'Threats Detected', value: data.summaryCards[2]?.value || 0, icon: FiAlertTriangle, change: '-3%', trend: 'down' },
    { title: 'System Health', value: `${data.systemHealth.uptime || 99}%`, icon: FiServer, change: '0%', trend: 'neutral' }
  ]

  const handleRefresh = async () => {
    try {
      setRefreshing(true)
      const response = await api.getDashboardData({ timeRange })
      setDashboardData(response.data)
      toast.success('Dashboard refreshed')
    } catch (error) {
      toast.error('Failed to refresh data')
    } finally {
      setRefreshing(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {summaryCards.map((card, index) => (
          <div key={index} className="bg-dark-light rounded-lg shadow px-5 py-4 border border-dark-light hover:border-cyber-blue transition-colors">
            <div className="flex items-center">
              <div className="p-3 rounded-full bg-opacity-10 bg-cyber-blue">
                <card.icon className="h-6 w-6 text-cyber-blue" />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-400">{card.title}</p>
                <div className="flex items-baseline">
                  <p className="text-2xl font-semibold text-white">{card.value}</p>
                  <span className={`ml-2 text-sm font-medium ${card.trend === 'up' ? 'text-success' : card.trend === 'down' ? 'text-danger' : 'text-gray-400'}`}>
                    {card.change}
                  </span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="bg-dark-light rounded-lg shadow px-4 py-3 flex items-center justify-between border border-dark-light">
        <div className="flex items-center space-x-4">
          <div>
            <label htmlFor="time-range" className="block text-sm font-medium text-gray-400 mb-1">
              Time Range
            </label>
            <select
              id="time-range"
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="bg-dark border border-dark-light text-white text-sm rounded-lg focus:ring-cyber-blue focus:border-cyber-blue block w-full p-2"
            >
              <option value="daily">Last 24 Hours</option>
              <option value="weekly">Last 7 Days</option>
              <option value="monthly">Last 30 Days</option>
            </select>
          </div>
        </div>
        
        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
        >
          <FiRefreshCw className={`mr-2 h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
          {refreshing ? 'Refreshing...' : 'Refresh Data'}
        </button>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* User Activity Chart */}
        <div className="bg-dark-light rounded-lg shadow p-4 border border-dark-light">
          <h3 className="text-lg font-medium text-white mb-4">User Activity</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={data.userActivity}
                margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" stroke="#94A3B8" />
                <YAxis stroke="#94A3B8" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1E293B', borderColor: '#334155' }}
                  itemStyle={{ color: '#F8FAFC' }}
                />
                <Area type="monotone" dataKey="active" stackId="1" stroke="#3B82F6" fill="#3B82F6" fillOpacity={0.2} />
                <Area type="monotone" dataKey="inactive" stackId="1" stroke="#F59E0B" fill="#F59E0B" fillOpacity={0.2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Distribution Chart */}
        <div className="bg-dark-light rounded-lg shadow p-4 border border-dark-light">
          <h3 className="text-lg font-medium text-white mb-4">Threat Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data.threatDistribution}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                >
                  {data.threatDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1E293B', borderColor: '#334155' }}
                  itemStyle={{ color: '#F8FAFC' }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* System Health Chart */}
        <div className="bg-dark-light rounded-lg shadow p-4 border border-dark-light col-span-1 lg:col-span-2">
          <h3 className="text-lg font-medium text-white mb-4">System Health</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                data={data.systemHealth.metrics}
                margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="time" stroke="#94A3B8" />
                <YAxis stroke="#94A3B8" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1E293B', borderColor: '#334155' }}
                  itemStyle={{ color: '#F8FAFC' }}
                />
                <Legend />
                <Line type="monotone" dataKey="cpu" stroke="#3B82F6" activeDot={{ r: 8 }} />
                <Line type="monotone" dataKey="memory" stroke="#10B981" />
                <Line type="monotone" dataKey="storage" stroke="#A78BFA" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Activity Section */}
      <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
        <div className="px-4 py-5 sm:px-6 border-b border-dark-light">
          <h3 className="text-lg font-medium leading-6 text-white">Recent Security Events</h3>
          <p className="mt-1 text-sm text-gray-400">Critical alerts that require attention</p>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-dark-light">
            <thead className="bg-dark">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Time
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Type
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Severity
                </th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Source
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
              {data.recentEvents.map((event, index) => (
                <tr key={index} className="hover:bg-dark">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {event.time}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">
                    {event.type}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                      event.severity === 'Critical' ? 'bg-danger text-white' :
                      event.severity === 'High' ? 'bg-warning text-dark-darker' :
                      event.severity === 'Medium' ? 'bg-info text-white' :
                      'bg-success text-white'
                    }`}>
                      {event.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {event.source}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {event.status}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button className="text-cyber-blue hover:text-cyber-blue-dark mr-3">
                      View
                    </button>
                    <button className="text-danger hover:text-danger-dark">
                      Dismiss
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}