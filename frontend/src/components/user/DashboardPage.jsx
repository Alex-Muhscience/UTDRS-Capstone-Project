import { useState, useEffect } from 'react'
import UserDashboard from '../../components/user/UserDashboard'
import Navbar from '../shared/Navbar'
import Sidebar from '../shared/Sidebar'
import api from '../../api/userApi'
import { useAuth } from '../../context/AuthContext'
import { toast } from 'react-toastify'

export default function DashboardPage() {
  const { user } = useAuth()
  const [loading, setLoading] = useState(true)
  const [dashboardData, setDashboardData] = useState({
    threatDistribution: [],
    networkTraffic: [],
    deviceStatus: {},
    recentAlerts: [],
    vulnerabilities: []
  })

  useEffect(() => {
    async function fetchDashboardData() {
      try {
        setLoading(true)
        const response = await api.getDashboardData()
        setDashboardData(response.data)
      } catch (error) {
        toast.error('Failed to load dashboard data')
        console.error('Dashboard error:', error)
      } finally {
        setLoading(false)
      }
    }
    
    fetchDashboardData()
  }, [])

  return (
    <div className="h-screen bg-dark-darker overflow-hidden flex">
      <Sidebar />
      
      <div className="flex-1 flex flex-col overflow-hidden">
        <Navbar />
        
        <main className="flex-1 overflow-y-auto p-4 md:p-6 bg-dark-darker">
          <div className="max-w-7xl mx-auto">
            <div className="flex items-center justify-between mb-6">
              <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
              <div className="text-sm text-gray-400">
                Last updated: <span className="text-cyber-teal">Just now</span>
              </div>
            </div>
            
            <UserDashboard 
              data={dashboardData} 
              loading={loading} 
              companyName={user?.company || 'Your Organization'}
            />
          </div>
        </main>
      </div>
    </div>
  )
}