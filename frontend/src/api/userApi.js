import apiClient from './apiClient';

const userApi = {
  // Dashboard endpoints
  getDashboardData(params = {}) {
    return apiClient.get('/user/dashboard', { params });
  },
  getDashboardStats() {
    return apiClient.get('/user/dashboard/stats');
  },
  getRecentAlerts(limit = 10) {
    return apiClient.get(`/user/dashboard/alerts?limit=${limit}`);
  },
  getProfile() {
    return apiClient.get('/user/profile');
  },
  updateProfile(profileData) {
    return apiClient.put('/user/profile', profileData);
  },
  getReports(params = {}) {
    return apiClient.get('/user/reports', { params });
  },
  generateReport(reportData) {
    return apiClient.post('/user/reports', reportData);
  },
  getDevices(params = {}) {
    return apiClient.get('/user/devices', { params });
  },
  scanDevice(deviceId) {
    return apiClient.post(`/user/devices/${deviceId}/scan`);
  },
  isolateDevice(deviceId) {
    return apiClient.post(`/user/devices/${deviceId}/isolate`);
  },
  getVulnerabilities(params = {}) {
    return apiClient.get('/user/vulnerabilities', { params });
  },
  getThreats(params = {}) {
    return apiClient.get('/user/threats', { params });
  },
  getSettings() {
    return apiClient.get('/user/settings');
  },
  updateSettings(settingsData) {
    return apiClient.put('/user/settings', settingsData);
  },
  
  // Additional threat management endpoints
  getThreatById(threatId) {
    return apiClient.get(`/user/threats/${threatId}`);
  },
  respondToThreat(threatId, action) {
    return apiClient.post(`/user/threats/${threatId}/respond`, { action });
  },
  dismissThreat(threatId) {
    return apiClient.post(`/user/threats/${threatId}/dismiss`);
  },
  
  // Additional vulnerability endpoints
  getVulnerabilityById(vulnId) {
    return apiClient.get(`/user/vulnerabilities/${vulnId}`);
  },
  remediateVulnerability(vulnId, data) {
    return apiClient.post(`/user/vulnerabilities/${vulnId}/remediate`, data);
  },
  
  // Alerts endpoints
  getAlerts(filters = {}) {
    return apiClient.get('/user/alerts', { params: filters });
  },
  getAlertById(alertId) {
    return apiClient.get(`/user/alerts/${alertId}`);
  },
  acknowledgeAlert(alertId) {
    return apiClient.post(`/user/alerts/${alertId}/acknowledge`);
  },
  resolveAlert(alertId, resolution) {
    return apiClient.post(`/user/alerts/${alertId}/resolve`, { resolution });
  },
  
  // Device endpoints
  getDeviceById(deviceId) {
    return apiClient.get(`/user/devices/${deviceId}`);
  },
  updateDevice(deviceId, data) {
    return apiClient.put(`/user/devices/${deviceId}`, data);
  },
  
  // Profile endpoints
  changePassword(data) {
    return apiClient.post('/user/profile/change-password', data);
  },
  
  // Reports endpoints
  downloadReport(reportId) {
    return apiClient.get(`/user/reports/${reportId}/download`, { responseType: 'blob' });
  },
};

export default userApi;