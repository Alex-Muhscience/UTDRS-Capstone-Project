import { createContext, useContext, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import jwt_decode from 'jwt-decode'
import api from '../api/authApi'

const AuthContext = createContext()

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    async function loadUser() {
      const token = localStorage.getItem('access_token')
      
      if (token) {
        try {
          const decoded = jwt_decode(token)
          const currentTime = Date.now() / 1000
          
          if (decoded.exp < currentTime) {
            await refreshToken()
          } else {
            setUser(decoded)
          }
        } catch (error) {
          console.error('Invalid token:', error)
          logout()
        }
      }
      setLoading(false)
    }
    
    loadUser()
  }, [])

  async function login(email, password) {
    try {
      const response = await api.login(email, password)
      const { access_token, refresh_token } = response.data
      
      localStorage.setItem('access_token', access_token)
      localStorage.setItem('refresh_token', refresh_token)
      
      const decoded = jwt_decode(access_token)
      setUser(decoded)
      
      // Redirect based on role
      const redirectPath = decoded.role === 'admin' ? '/admin/dashboard' : '/user/dashboard'
      navigate(redirectPath)
      
      return { success: true }
    } catch (error) {
      console.error('Login error:', error)
      return { success: false, message: error.response?.data?.message || 'Login failed' }
    }
  }

  async function logout() {
    try {
      await api.logout()
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      setUser(null)
      navigate('/login')
    }
  }

  async function refreshToken() {
    try {
      const refreshToken = localStorage.getItem('refresh_token')
      if (!refreshToken) throw new Error('No refresh token')
      
      const response = await api.refreshToken(refreshToken)
      const { access_token } = response.data
      
      localStorage.setItem('access_token', access_token)
      const decoded = jwt_decode(access_token)
      setUser(decoded)
      
      return true
    } catch (error) {
      console.error('Refresh token error:', error)
      logout()
      return false
    }
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, refreshToken }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}