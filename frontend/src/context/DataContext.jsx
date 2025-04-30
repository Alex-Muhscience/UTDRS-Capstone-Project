import { createContext, useContext, useState, useEffect } from 'react';
import api from '../api/adminApi';
import { useAuth } from './AuthContext';

const DataContext = createContext();

export function DataProvider({ children }) {
  const { user } = useAuth();
  const [devices, setDevices] = useState([]);
  const [threats, setThreats] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const [devicesRes, threatsRes, vulnerabilitiesRes] = await Promise.all([
          user?.role === 'admin' ? api.getDevices() : api.userApi.getDevices(),
          user?.role === 'admin' ? api.getThreats() : api.userApi.getThreats(),
          user?.role === 'admin' ? api.getVulnerabilities() : api.userApi.getVulnerabilities(),
        ]);
        
        setDevices(devicesRes.data);
        setThreats(threatsRes.data);
        setVulnerabilities(vulnerabilitiesRes.data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    if (user) fetchData();
  }, [user]);

  const value = {
    devices,
    threats,
    vulnerabilities,
    loading,
    error,
    refreshData: async () => {
      try {
        setLoading(true);
        const [devicesRes, threatsRes, vulnerabilitiesRes] = await Promise.all([
          user?.role === 'admin' ? api.getDevices() : api.userApi.getDevices(),
          user?.role === 'admin' ? api.getThreats() : api.userApi.getThreats(),
          user?.role === 'admin' ? api.getVulnerabilities() : api.userApi.getVulnerabilities(),
        ]);
        
        setDevices(devicesRes.data);
        setThreats(threatsRes.data);
        setVulnerabilities(vulnerabilitiesRes.data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    },
  };

  return <DataContext.Provider value={value}>{children}</DataContext.Provider>;
}

export function useData() {
  const context = useContext(DataContext);
  if (!context) {
    throw new Error('useData must be used within a DataProvider');
  }
  return context;
}