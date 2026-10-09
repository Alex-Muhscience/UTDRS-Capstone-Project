import { useState } from 'react';
import { FiSave, FiBell, FiShield, FiUser } from 'react-icons/fi';
import { toast } from 'react-toastify';

export default function Settings() {
  const [settings, setSettings] = useState({
    notifications: {
      email: true,
      sms: false,
      inApp: true
    },
    security: {
      mfa: false,
      sessionTimeout: 30
    },
    preferences: {
      theme: 'dark',
      timezone: 'UTC',
      language: 'en'
    }
  });

  const handleChange = (section, key, value) => {
    setSettings({
      ...settings,
      [section]: {
        ...settings[section],
        [key]: value
      }
    });
  };

  const handleSave = () => {
    // In a real app, this would save to the backend
    toast.success('Settings saved successfully');
  };

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">User Settings</h2>
        <button
          onClick={handleSave}
          className="inline-flex items-center px-3 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-cyber-blue hover:bg-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue"
        >
          <FiSave className="mr-2" /> Save Settings
        </button>
      </div>

      <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
        <div className="px-6 py-5 border-b border-dark-light">
          <h3 className="text-lg font-medium leading-6 text-white flex items-center">
            <FiBell className="mr-2 text-cyber-blue" /> Notification Preferences
          </h3>
        </div>
        <div className="px-6 py-4 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.notifications.email}
                onChange={(e) => handleChange('notifications', 'email', e.target.checked)}
                className="h-4 w-4 text-cyber-blue focus:ring-cyber-blue border-dark-light rounded"
              />
              <span className="ml-2 text-sm text-gray-300">Email Notifications</span>
            </label>
          </div>
          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.notifications.sms}
                onChange={(e) => handleChange('notifications', 'sms', e.target.checked)}
                className="h-4 w-4 text-cyber-blue focus:ring-cyber-blue border-dark-light rounded"
              />
              <span className="ml-2 text-sm text-gray-300">SMS Notifications</span>
            </label>
          </div>
          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.notifications.inApp}
                onChange={(e) => handleChange('notifications', 'inApp', e.target.checked)}
                className="h-4 w-4 text-cyber-blue focus:ring-cyber-blue border-dark-light rounded"
              />
              <span className="ml-2 text-sm text-gray-300">In-App Notifications</span>
            </label>
          </div>
        </div>
      </div>

      <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
        <div className="px-6 py-5 border-b border-dark-light">
          <h3 className="text-lg font-medium leading-6 text-white flex items-center">
            <FiShield className="mr-2 text-cyber-blue" /> Security Settings
          </h3>
        </div>
        <div className="px-6 py-4 grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={settings.security.mfa}
                onChange={(e) => handleChange('security', 'mfa', e.target.checked)}
                className="h-4 w-4 text-cyber-blue focus:ring-cyber-blue border-dark-light rounded"
              />
              <span className="ml-2 text-sm text-gray-300">Enable Multi-Factor Authentication</span>
            </label>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300">Session Timeout (minutes)</label>
            <select
              value={settings.security.sessionTimeout}
              onChange={(e) => handleChange('security', 'sessionTimeout', parseInt(e.target.value))}
              className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
            >
              <option value={15}>15</option>
              <option value={30}>30</option>
              <option value={60}>60</option>
              <option value={120}>120</option>
            </select>
          </div>
        </div>
      </div>

      <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
        <div className="px-6 py-5 border-b border-dark-light">
          <h3 className="text-lg font-medium leading-6 text-white flex items-center">
            <FiUser className="mr-2 text-cyber-blue" /> User Preferences
          </h3>
        </div>
        <div className="px-6 py-4 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-300">Theme</label>
            <select
              value={settings.preferences.theme}
              onChange={(e) => handleChange('preferences', 'theme', e.target.value)}
              className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
            >
              <option value="dark">Dark</option>
              <option value="light">Light</option>
              <option value="system">System Default</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300">Timezone</label>
            <select
              value={settings.preferences.timezone}
              onChange={(e) => handleChange('preferences', 'timezone', e.target.value)}
              className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
            >
              <option value="UTC">UTC</option>
              <option value="EST">Eastern Time (EST)</option>
              <option value="CST">Central Time (CST)</option>
              <option value="PST">Pacific Time (PST)</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300">Language</label>
            <select
              value={settings.preferences.language}
              onChange={(e) => handleChange('preferences', 'language', e.target.value)}
              className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
            >
              <option value="en">English</option>
              <option value="es">Spanish</option>
              <option value="fr">French</option>
              <option value="de">German</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
}