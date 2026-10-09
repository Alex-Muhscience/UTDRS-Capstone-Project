import { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import api from '../../api/userApi';
import { toast } from 'react-toastify';
import Loader from '../../components/shared/Loader';

export default function ProfilePage() {
  const { user, logout } = useAuth();
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    company: '',
    phone: '',
  });

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        setLoading(true);
        const response = await api.getProfile();
        setProfile(response.data);
        setFormData({
          name: response.data.name,
          email: response.data.email,
          company: response.data.company,
          phone: response.data.phone || '',
        });
      } catch (error) {
        toast.error('Failed to load profile');
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      await api.updateProfile(formData);
      toast.success('Profile updated successfully');
      setEditing(false);
      // Refresh profile data
      const response = await api.getProfile();
      setProfile(response.data);
    } catch (error) {
      toast.error('Failed to update profile');
    } finally {
      setLoading(false);
    }
  };

  if (loading && !profile) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader size="lg" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">Account Profile</h2>
        {!editing && (
          <button
            onClick={() => setEditing(true)}
            className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
          >
            Edit Profile
          </button>
        )}
      </div>

      {editing ? (
        <form onSubmit={handleSubmit} className="bg-dark-light rounded-lg shadow p-6 border border-dark-light">
          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-gray-300">
                Full Name
              </label>
              <input
                type="text"
                id="name"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                required
                className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
              />
            </div>
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-300">
                Email Address
              </label>
              <input
                type="email"
                id="email"
                name="email"
                value={formData.email}
                onChange={handleInputChange}
                required
                disabled
                className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white bg-opacity-50 cursor-not-allowed"
              />
            </div>
            <div>
              <label htmlFor="company" className="block text-sm font-medium text-gray-300">
                Company
              </label>
              <input
                type="text"
                id="company"
                name="company"
                value={formData.company}
                onChange={handleInputChange}
                required
                className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
              />
            </div>
            <div>
              <label htmlFor="phone" className="block text-sm font-medium text-gray-300">
                Phone Number
              </label>
              <input
                type="tel"
                id="phone"
                name="phone"
                value={formData.phone}
                onChange={handleInputChange}
                className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
              />
            </div>
          </div>
          <div className="mt-6 flex justify-end space-x-3">
            <button
              type="button"
              onClick={() => setEditing(false)}
              className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-dark-light hover:bg-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
            >
              {loading ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        </form>
      ) : (
        <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
          <div className="px-6 py-5">
            <div className="flex items-center space-x-4">
              <div className="flex-shrink-0">
                <div className="h-16 w-16 rounded-full bg-cyber-blue flex items-center justify-center text-white text-2xl font-bold">
                  {profile?.name?.charAt(0) || 'U'}
                </div>
              </div>
              <div>
                <h3 className="text-lg font-medium text-white">{profile?.name}</h3>
                <p className="text-gray-400">{profile?.company}</p>
              </div>
            </div>
          </div>
          <div className="border-t border-dark-light px-6 py-5">
            <dl className="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2">
              <div className="sm:col-span-1">
                <dt className="text-sm font-medium text-gray-400">Email</dt>
                <dd className="mt-1 text-sm text-white">{profile?.email}</dd>
              </div>
              <div className="sm:col-span-1">
                <dt className="text-sm font-medium text-gray-400">Phone</dt>
                <dd className="mt-1 text-sm text-white">{profile?.phone || 'Not provided'}</dd>
              </div>
              <div className="sm:col-span-1">
                <dt className="text-sm font-medium text-gray-400">Account Type</dt>
                <dd className="mt-1 text-sm text-white">
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-cyber-blue text-white">
                    {user?.role === 'admin' ? 'Administrator' : 'Standard User'}
                  </span>
                </dd>
              </div>
              <div className="sm:col-span-1">
                <dt className="text-sm font-medium text-gray-400">License Tier</dt>
                <dd className="mt-1 text-sm text-white">
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-cyber-teal text-white">
                    {profile?.licenseTier || 'Basic'}
                  </span>
                </dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-sm font-medium text-gray-400">Member Since</dt>
                <dd className="mt-1 text-sm text-white">
                  {new Date(profile?.createdAt).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                  })}
                </dd>
              </div>
            </dl>
          </div>
        </div>
      )}
    </div>
  );
}