import { Link } from 'react-router-dom'
import { FiLock } from 'react-icons/fi'

export default function UnauthorizedPage() {
  return (
    <div className="min-h-screen bg-dark-darker flex items-center justify-center px-4">
      <div className="text-center">
        <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-danger bg-opacity-20">
          <FiLock className="h-6 w-6 text-danger" />
        </div>
        <h1 className="text-4xl font-extrabold text-white mt-4">403</h1>
        <p className="text-xl font-medium text-white mt-2">Unauthorized Access</p>
        <p className="text-gray-400 mt-2">
          You don't have permission to access this page.
        </p>
        <Link
          to="/"
          className="mt-6 inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
        >
          Return to dashboard
        </Link>
      </div>
    </div>
  )
}