import apiClient from './apiClient';

const adminApi = {
  getDashboardData(params = {}) {
    return apiClient.get('/admin/dashboard', { params });
  },
  getDashboardStats() {
    return apiClient.get('/admin/dashboard/stats');
  },
  getSystemMetrics() {
    return apiClient.get('/admin/dashboard/metrics');
  },
  getUsers(params = {}) {
    return apiClient.get('/admin/users', { params });
  },
  getUserById(userId) {
    return apiClient.get(`/admin/users/${userId}`);
  },
  createUser(userData) {
    return apiClient.post('/admin/users', userData);
  },
  updateUser(userId, userData) {
    return apiClient.put(`/admin/users/${userId}`, userData);
  },
  deleteUser(userId) {
    return apiClient.delete(`/admin/users/${userId}`);
  },
  resetUserPassword(userId) {
    return apiClient.post(`/admin/users/${userId}/reset-password`);
  },
  toggleUserStatus(userId, status) {
    return apiClient.post(`/admin/users/${userId}/status`, { status });
  },
  // Device management endpoints
  getDevices(params = {}) {
    return apiClient.get('/admin/devices', { params });
  },
  getDeviceById(deviceId) {
    return apiClient.get(`/admin/devices/${deviceId}`);
  },
  updateDevice(deviceId, data) {
    return apiClient.put(`/admin/devices/${deviceId}`, data);
  },
  deleteDevice(deviceId) {
    return apiClient.delete(`/admin/devices/${deviceId}`);
  },

  // Threat management endpoints
  getThreats(params = {}) {
    return apiClient.get('/admin/threats', { params });
  },
  getThreatById(threatId) {
    return apiClient.get(`/admin/threats/${threatId}`);
  },
  updateThreatStatus(threatId, status) {
    return apiClient.post(`/admin/threats/${threatId}/status`, { status });
  },

  // Vulnerability management endpoints
  getVulnerabilities(params = {}) {
    return apiClient.get('/admin/vulnerabilities', { params });
  },
  getVulnerabilityById(vulnId) {
    return apiClient.get(`/admin/vulnerabilities/${vulnId}`);
  },

  // Alerts endpoints
  getAlerts(params = {}) {
    return apiClient.get('/admin/alerts', { params });
  },
  getAlertById(alertId) {
    return apiClient.get(`/admin/alerts/${alertId}`);
  },
  dismissAlert(alertId) {
    return apiClient.post(`/admin/alerts/${alertId}/dismiss`);
  },

  // Reports endpoints
  getReports(params = {}) {
    return apiClient.get('/admin/reports', { params });
  },
  generateReport(reportData) {
    return apiClient.post('/admin/reports/generate', reportData);
  },
  downloadReport(reportId) {
    return apiClient.get(`/admin/reports/${reportId}/download`, { responseType: 'blob' });
  },
  deleteReport(reportId) {
    return apiClient.delete(`/admin/reports/${reportId}`);
  },

  // License management endpoints
  getLicenses() {
    return apiClient.get('/admin/licenses');
  },
  assignLicense(userId, licenseData) {
    return apiClient.post(`/admin/licenses/${userId}/assign`, licenseData);
  },
  revokeLicense(userId) {
    return apiClient.post(`/admin/licenses/${userId}/revoke`);
  },
  updateLicense(licenseData) {
    return apiClient.put('/admin/licenses', licenseData);
  },

  // Analytics endpoints
  getAnalytics(params = {}) {
    return apiClient.get('/admin/analytics', { params });
  },

  // Support tickets endpoints
  getSupportTickets(params = {}) {
    return apiClient.get('/admin/support', { params });
  },
  getTicketById(ticketId) {
    return apiClient.get(`/admin/support/${ticketId}`);
  },
  updateSupportTicket(ticketId, ticketData) {
    return apiClient.put(`/admin/support/${ticketId}`, ticketData);
  },
  closeTicket(ticketId, resolution) {
    return apiClient.post(`/admin/support/${ticketId}/close`, { resolution });
  },

  // Settings endpoints
  getSettings() {
    return apiClient.get('/admin/settings');
  },
  updateSettings(settingsData) {
    return apiClient.put('/admin/settings', settingsData);
  },

  // System configuration endpoints
  getSystemConfig() {
    return apiClient.get('/admin/system/config');
  },
  updateSystemConfig(configData) {
    return apiClient.put('/admin/system/config', configData);
  },

  // Audit log endpoints
  getAuditLogs(params = {}) {
    return apiClient.get('/admin/audit-logs', { params });
  },
};

export default adminApi;