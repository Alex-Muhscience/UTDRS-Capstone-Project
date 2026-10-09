import { io } from 'socket.io-client'
import { toast } from 'react-toastify'
import { useAuth } from '../context/AuthContext'

const socket = io(import.meta.env.VITE_WS_URL || 'ws://localhost:8000', {
  autoConnect: false,
  reconnectionAttempts: 5,
  reconnectionDelay: 1000,
  transports: ['websocket']
})

export function useWebSocket() {
  const { user } = useAuth()

  const connect = () => {
    if (!socket.connected) {
      socket.auth = { token: localStorage.getItem('access_token') }
      socket.connect()
    }
  }

  const disconnect = () => {
    if (socket.connected) {
      socket.disconnect()
    }
  }

  const subscribeToAlerts = (callback) => {
    socket.on('alert', (alert) => {
      if (user?.role === 'admin' || alert.companyId === user?.companyId) {
        callback(alert)
        
        // Show toast notification for high severity alerts
        if (alert.severity === 'Critical' || alert.severity === 'High') {
          toast[alert.severity === 'Critical' ? 'error' : 'warning'](
            <div>
              <p className="font-medium">{alert.title}</p>
              <p className="text-sm">{alert.description}</p>
            </div>,
            {
              autoClose: 10000,
              closeOnClick: false,
              draggable: false
            }
          )
        }
      }
    })
  }

  const unsubscribeFromAlerts = () => {
    socket.off('alert')
  }

  const subscribeToDeviceUpdates = (callback) => {
    socket.on('device_update', (update) => {
      if (user?.role === 'admin' || update.companyId === user?.companyId) {
        callback(update)
      }
    })
  }

  const unsubscribeFromDeviceUpdates = () => {
    socket.off('device_update')
  }

  return {
    connect,
    disconnect,
    subscribeToAlerts,
    unsubscribeFromAlerts,
    subscribeToDeviceUpdates,
    unsubscribeFromDeviceUpdates,
    socket
  }
}