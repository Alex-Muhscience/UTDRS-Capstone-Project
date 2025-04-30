import apiClient from './apiClient'

export default {
  getDashboardData(params = {}) {
    return apiClient.get('/user/dashboard', { params })
  },
  getProfile() {
    return apiClient.get('/user/profile')
  },
  updateProfile(profileData) {
    return apiClient.put('/user/profile', profileData)
  },
  getReports(params = {}) {
    return apiClient.get('/user/reports', { params })
  },
  generateReport(reportData) {
    return apiClient.post('/user/reports', reportData)
  },
  getDevices(params = {}) {
    return apiClient.get('/user/devices', { params })
  },
  scanDevice(deviceId) {
    return apiClient.post(`/user/devices/${deviceId}/scan`)
  },
  isolateDevice(deviceId) {
    return apiClient.post(`/user/devices/${deviceId}/isolate`)
  },
  getVulnerabilities(params = {}) {
    return apiClient.get('/user/vulnerabilities', { params })
  },
  getThreats(params = {}) {
    return apiClient.get('/user/threats', { params })
  },
  getSettings() {
    return apiClient.get('/user/settings')
  },
  updateSettings(settingsData) {
    return apiClient.put('/user/settings', settingsData)
  }
}