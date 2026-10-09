import { Link } from 'react-router-dom'
import { FiArrowLeft } from 'react-icons/fi'

export default function NotFoundPage() {
  return (
    <div className="min-h-screen bg-dark-darker flex items-center justify-center px-4">
      <div className="text-center">
        <h1 className="text-9xl font-extrabold text-cyber-blue">404</h1>
        <p className="text-2xl font-medium text-white mt-4">Page not found</p>
        <p className="text-gray-400 mt-2">
          The page you're looking for doesn't exist or has been moved.
        </p>
        <Link
          to="/"
          className="mt-6 inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
        >
          <FiArrowLeft className="mr-2" /> Go back home
        </Link>
      </div>
    </div>
  )
}