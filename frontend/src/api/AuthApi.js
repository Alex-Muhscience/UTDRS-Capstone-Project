import axios from 'axios'

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000/api',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor to handle token refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true
      
      try {
        const refreshToken = localStorage.getItem('refresh_token')
        const response = await axios.post(
          `${import.meta.env.VITE_API_URL || 'http://localhost:8000/api'}/refresh`,
          { refresh_token: refreshToken }
        )
        
        const { access_token } = response.data
        localStorage.setItem('access_token', access_token)
        
        originalRequest.headers.Authorization = `Bearer ${access_token}`
        return apiClient(originalRequest)
      } catch (refreshError) {
        console.error('Token refresh failed:', refreshError)
        localStorage.removeItem('access_token')
        localStorage.removeItem('refresh_token')
        window.location.href = '/login'
        return Promise.reject(refreshError)
      }
    }
    
    return Promise.reject(error)
  }
)

export default {
  login(email, password) {
    return apiClient.post('/login', { email, password })
  },
  logout() {
    return apiClient.post('/logout')
  },
  refreshToken(refreshToken) {
    return axios.post(
      `${import.meta.env.VITE_API_URL || 'http://localhost:8000/api'}/refresh`,
      { refresh_token: refreshToken }
    )
  },
  getUserProfile() {
    return apiClient.get('/user/profile')
  },
  updateUserProfile(data) {
    return apiClient.put('/user/profile', data)
  }
}