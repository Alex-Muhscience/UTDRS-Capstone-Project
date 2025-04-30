import { NavLink, useLocation } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'
import { 
  FiHome, FiUsers, FiShield, FiActivity, FiFileText, FiLifeBuoy, FiSettings,
  FiServer, FiAlertTriangle, FiBarChart2, FiLayers
} from 'react-icons/fi'

export default function Sidebar() {
  const { user } = useAuth()
  const location = useLocation()

  const adminLinks = [
    { name: 'Dashboard', path: '/admin/dashboard', icon: FiHome },
    { name: 'User Management', path: '/admin/users', icon: FiUsers },
    { name: 'Analytics', path: '/admin/analytics', icon: FiBarChart2 },
    { name: 'Reports', path: '/admin/reports', icon: FiFileText },
    { name: 'Support', path: '/admin/support', icon: FiLifeBuoy },
    { name: 'Settings', path: '/admin/settings', icon: FiSettings }
  ]

  const userLinks = [
    { name: 'Dashboard', path: '/user/dashboard', icon: FiHome },
    { name: 'Devices', path: '/user/devices', icon: FiServer },
    { name: 'Vulnerabilities', path: '/user/vulnerabilities', icon: FiAlertTriangle },
    { name: 'Threats', path: '/user/threats', icon: FiShield },
    { name: 'Reports', path: '/user/reports', icon: FiFileText },
    { name: 'Profile', path: '/user/profile', icon: FiUser },
    { name: 'Settings', path: '/user/settings', icon: FiSettings }
  ]

  const links = user?.role === 'admin' ? adminLinks : userLinks

  return (
    <div className="hidden md:flex md:flex-shrink-0">
      <div className="flex flex-col w-64 border-r border-dark-light bg-dark-darker">
        <div className="flex flex-col h-0 flex-1">
          <div className="flex-1 flex flex-col pt-5 pb-4 overflow-y-auto">
            <div className="flex items-center flex-shrink-0 px-4">
              <h1 className="text-xl font-bold text-white">
                <span className="text-cyber-blue">UTDRS</span> Console
              </h1>
            </div>
            
            <nav className="mt-5 flex-1 px-2 space-y-1">
              {links.map((link) => (
                <NavLink
                  key={link.path}
                  to={link.path}
                  className={({ isActive }) => `
                    group flex items-center px-2 py-2 text-sm font-medium rounded-md
                    ${isActive || location.pathname.startsWith(link.path) 
                      ? 'bg-dark-light text-white' 
                      : 'text-gray-300 hover:bg-dark-light hover:text-white'
                  `}
                >
                  <link.icon className="mr-3 flex-shrink-0 h-6 w-6" />
                  {link.name}
                </NavLink>
              ))}
            </nav>
          </div>
          
          <div className="flex-shrink-0 flex border-t border-dark-light p-4">
            <div className="flex items-center">
              <div className="h-9 w-9 rounded-full bg-cyber-blue flex items-center justify-center">
                <FiUser className="h-5 w-5 text-white" />
              </div>
              <div className="ml-3">
                <p className="text-sm font-medium text-white">{user?.name || user?.email}</p>
                <p className="text-xs font-medium text-cyber-teal">
                  {user?.role === 'admin' ? 'Admin' : 'User'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    </div>
  )
}