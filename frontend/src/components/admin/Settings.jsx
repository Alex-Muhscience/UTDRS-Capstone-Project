import { useState } from 'react';
import { FiSave, FiShield, FiBell, FiKey, FiMail } from 'react-icons/fi';
import { toast } from 'react-toastify';

export default function Settings() {
  const [settings, setSettings] = useState({
    notifications: {
      email: true,
      sms: false,
      push: true
    },
    security: {
      mfa: true,
      sessionTimeout: 30,
      passwordComplexity: 'high'
    },
    system: {
      autoUpdates: true,
      backupFrequency: 'daily',
      logRetention: 30
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
        <h2 className="text-xl font-bold text-white">System Settings</h2>
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
              <span className="ml-2 text-sm text-gray-300">Require Multi-Factor Authentication</span>
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
          <div>
            <label className="block text-sm font-medium text-gray-300">Password Complexity</label>
            <select
              value={settings.security.passwordComplexity}
              onChange={(e) => handleChange('security', 'passwordComplexity', e.target.value)}
              className="mt-1 block w-full border border-dark-light bg-dark rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
            </select>
          </div>
        </div>
      </div>

      <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
        <div className="px-6 py-5 border-b border-dark-light">
          <h3 className="text-lg font-medium leading-6 text-white flex items-center">
            <FiBell className="mr-2 text-cyber-blue" /> Notification Settings
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
                checked={settings.notifications.push}
                onChange={(e) => handleChange('notifications', 'push', e.target.checked)}
                className="h-4 w-4 text-cyber-blue focus:ring-cyber-blue border-dark-light rounded"
              />
              <span className="ml-2 text-sm text-gray-300">Push Notifications</span>
            </label>
          </div>
        </div>
      </div>

      <div className="bg-dark-light rounded-lg shadow overflow-hidden border border-dark-light">
        <div className="px-6 py-5 border-b border-dark-light">
          <h3 className="text-lg font-medium leading-6 text-white flex items-center">
            <FiKey className="mr-2 text-cyber-blue" /> API Settings
          </h3>
        </div>
        <div className="px-6 py-4">
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300">API Key</label>
            <div className="mt-1 flex rounded-md shadow-sm">
              <input
                type="text"
                readOnly
                value="sk_test_51JmZXXXXXXXXXXXXXXXXXXXXXXXX"
                className="flex-1 block w-full border border-dark-light bg-dark rounded-l-md py-2 px-3 focus:outline-none focus:ring-cyber-blue focus:border-cyber-blue sm:text-sm text-white"
              />
              <button className="inline-flex items-center px-3 py-2 border border-l-0 border-dark-light bg-dark-light text-sm font-medium text-cyber-blue hover:text-cyber-blue-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-cyber-blue rounded-r-md">
                Regenerate
              </button>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300">API Permissions</label>
            <div className="mt-2 space-y-2">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={true}
                  className="h-4 w-4 text-cyber-blue focus:ring-cyber-blue border-dark-light rounded"
                />
                <span className="ml-2 text-sm text-gray-300">Read Access</span>
              </label>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={true}
                  className="h-4 w-4 text-cyber-blue focus:ring-cyber-blue border-dark-light rounded"
                />
                <span className="ml-2 text-sm text-gray-300">Write Access</span>
              </label>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={false}
                  className="h-4 w-4 text-cyber-blue focus:ring-cyber-blue border-dark-light rounded"
                />
                <span className="ml-2 text-sm text-gray-300">Admin Access</span>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}