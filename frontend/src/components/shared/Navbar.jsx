import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'
import { FiLogOut, FiSettings, FiBell, FiUser } from 'react-icons/fi'
import { toast } from 'react-toastify'

export default function Navbar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = async () => {
    try {
      await logout()
      toast.success('Logged out successfully')
      navigate('/login')
    } catch (error) {
      toast.error('Logout failed')
    }
  }

  return (
    <nav className="bg-dark-darker border-b border-dark-light">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center">
            <Link to={user?.role === 'admin' ? '/admin/dashboard' : '/user/dashboard'} className="flex-shrink-0">
              <img className="h-8 w-auto" src="/logo.png" alt="UTDRS Logo" />
            </Link>
          </div>
          
          <div className="hidden md:block">
            <div className="ml-4 flex items-center md:ml-6">
              <button className="p-1 rounded-full text-gray-400 hover:text-white focus:outline-none">
                <span className="sr-only">View notifications</span>
                <FiBell className="h-6 w-6" />
              </button>
              
              <div className="ml-3 relative">
                <div className="flex items-center space-x-4">
                  <div className="text-sm text-gray-300">
                    <div className="font-medium">{user?.name || user?.email}</div>
                    <div className="text-xs text-cyber-teal">{user?.role === 'admin' ? 'Admin' : 'User'}</div>
                  </div>
                  
                  <div className="dropdown relative">
                    <button className="flex items-center text-sm rounded-full focus:outline-none">
                      <span className="sr-only">Open user menu</span>
                      <div className="h-8 w-8 rounded-full bg-cyber-blue flex items-center justify-center">
                        <FiUser className="h-5 w-5 text-white" />
                      </div>
                    </button>
                    
                    <div className="dropdown-menu absolute right-0 mt-2 w-48 rounded-md shadow-lg bg-dark-darker border border-dark-light z-50 hidden">
                      <div className="py-1">
                        <Link to={user?.role === 'admin' ? '/admin/settings' : '/user/settings'} className="block px-4 py-2 text-sm text-gray-300 hover:bg-dark-light hover:text-white flex items-center">
                          <FiSettings className="mr-2" /> Settings
                        </Link>
                        <button onClick={handleLogout} className="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-dark-light hover:text-white flex items-center">
                          <FiLogOut className="mr-2" /> Sign out
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </nav>
  )
}