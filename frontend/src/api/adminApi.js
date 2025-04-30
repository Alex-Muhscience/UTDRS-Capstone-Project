import apiClient from './apiClient'

export default {
  getDashboardData(params = {}) {
    return apiClient.get('/admin/dashboard', { params })
  },
  getUsers() {
    return apiClient.get('/admin/users')
  },
  createUser(userData) {
    return apiClient.post('/admin/users', userData)
  },
  updateUser(userId, userData) {
    return apiClient.put(`/admin/users/${userId}`, userData)
  },
  deleteUser(userId) {
    return apiClient.delete(`/admin/users/${userId}`)
  },
  getLicenses() {
    return apiClient.get('/admin/licenses')
  },
  assignLicense(userId, licenseData) {
    return apiClient.post(`/admin/licenses/${userId}/assign`, licenseData)
  },
  revokeLicense(userId) {
    return apiClient.post(`/admin/licenses/${userId}/revoke`)
  },
  getAnalytics(params = {}) {
    return apiClient.get('/admin/analytics', { params })
  },
  generateReport(reportData) {
    return apiClient.post('/admin/reports', reportData)
  },
  getSupportTickets(params = {}) {
    return apiClient.get('/admin/support', { params })
  },
  updateSupportTicket(ticketId, ticketData) {
    return apiClient.put(`/admin/support/${ticketId}`, ticketData)
  },
  getSettings() {
    return apiClient.get('/admin/settings')
  },
  updateSettings(settingsData) {
    return apiClient.put('/admin/settings', settingsData)
  }
}