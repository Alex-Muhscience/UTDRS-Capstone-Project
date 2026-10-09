import { Link } from 'react-router-dom';
import { FiArrowLeft, FiAlertCircle } from 'react-icons/fi';

export default function ErrorPage({ statusCode = 500, message = 'An unexpected error occurred' }) {
  const errorMessages = {
    403: 'You are not authorized to access this page.',
    404: 'The page you are looking for does not exist.',
    500: 'Something went wrong on our server.',
  };

  return (
    <div className="min-h-screen bg-dark-darker flex items-center justify-center px-4">
      <div className="text-center max-w-md">
        <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-danger bg-opacity-20">
          <FiAlertCircle className="h-8 w-8 text-danger" />
        </div>
        <h1 className="text-4xl font-extrabold text-white mt-4">{statusCode}</h1>
        <p className="text-xl font-medium text-white mt-2">
          {errorMessages[statusCode] || message}
        </p>
        <p className="text-gray-400 mt-2">
          {statusCode === 403
            ? 'Please contact your administrator for access.'
            : statusCode === 404
            ? 'The page may have been moved or deleted.'
            : 'Our team has been notified and we are working on a fix.'}
        </p>
        <Link
          to="/"
          className="mt-6 inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
        >
          <FiArrowLeft className="mr-2" /> Return to Dashboard
        </Link>
      </div>
    </div>
  );
}