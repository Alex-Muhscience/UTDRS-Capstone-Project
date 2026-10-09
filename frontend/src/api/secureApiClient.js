import axios from 'axios';
import tokenStorage from '../utils/tokenStorage';
import csrfProtection from './csrfProtection';
import { sanitizeInput, removeSensitiveData } from '../utils/security';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

const secureApiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  // Security options
  withCredentials: true, // Send cookies with requests
  timeout: 30000, // 30 second timeout
});

/**
 * Request interceptor - Add security headers and authentication
 */
secureApiClient.interceptors.request.use(
  async (config) => {
    // Initialize CSRF protection if not done
    if (!csrfProtection.initialized) {
      await csrfProtection.initialize();
    }

    // Add CSRF token for state-changing requests
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(config.method.toUpperCase())) {
      config.headers = {
        ...config.headers,
        ...csrfProtection.getHeaders(),
      };
    }

    // Add authentication token
    const token = tokenStorage.getToken('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    // Add security headers
    config.headers['X-Requested-With'] = 'XMLHttpRequest';
    config.headers['X-Client-Version'] = import.meta.env.VITE_APP_VERSION || '1.0.0';

    // Sanitize data for POST/PUT requests
    if (config.data && typeof config.data === 'object') {
      // Log sanitized data for debugging (remove sensitive info)
      if (import.meta.env.VITE_DEBUG) {
        console.debug('API Request:', {
          method: config.method,
          url: config.url,
          data: removeSensitiveData(config.data),
        });
      }
    }

    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

/**
 * Response interceptor - Handle authentication and CSRF token refresh
 */
secureApiClient.interceptors.response.use(
  (response) => {
    // Update CSRF token from response if provided
    csrfProtection.validateResponse(response);

    // Log successful response
    if (import.meta.env.VITE_DEBUG) {
      console.debug('API Response:', {
        status: response.status,
        url: response.config.url,
      });
    }

    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Handle 401 Unauthorized - Try to refresh token
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const refreshToken = tokenStorage.getToken('refresh_token');
        
        if (!refreshToken) {
          throw new Error('No refresh token available');
        }

        // Create new instance to avoid interceptor loop
        const refreshClient = axios.create({
          baseURL: API_BASE_URL,
          withCredentials: true,
        });

        const response = await refreshClient.post('/auth/refresh', {
          refresh_token: refreshToken,
        });

        const { access_token, refresh_token } = response.data;

        // Store new tokens securely
        tokenStorage.setToken('access_token', access_token, { useMemory: true });
        if (refresh_token) {
          tokenStorage.setToken('refresh_token', refresh_token, { useMemory: true });
        }

        // Retry original request with new token
        originalRequest.headers.Authorization = `Bearer ${access_token}`;
        return secureApiClient(originalRequest);
      } catch (refreshError) {
        // Refresh failed - clear tokens and redirect to login
        tokenStorage.removeToken('access_token');
        tokenStorage.removeToken('refresh_token');
        csrfProtection.clear();

        // Redirect to login
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    // Handle 403 Forbidden - CSRF token might be invalid
    if (error.response?.status === 403) {
      try {
        // Refresh CSRF token and retry
        await csrfProtection.refreshToken();
        originalRequest.headers = {
          ...originalRequest.headers,
          ...csrfProtection.getHeaders(),
        };
        return secureApiClient(originalRequest);
      } catch (csrfError) {
        return Promise.reject(csrfError);
      }
    }

    // Handle rate limiting (429)
    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after'];
      const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : 60000;
      
      console.warn(`Rate limited. Retry after ${waitTime}ms`);
      
      // Implement exponential backoff
      if (!originalRequest._retryCount) {
        originalRequest._retryCount = 1;
      } else if (originalRequest._retryCount < 3) {
        originalRequest._retryCount++;
        const delay = Math.pow(2, originalRequest._retryCount) * 1000;
        
        return new Promise((resolve) => {
          setTimeout(() => {
            resolve(secureApiClient(originalRequest));
          }, delay);
        });
      }
    }

    // Log errors
    if (import.meta.env.VITE_DEBUG) {
      console.error('API Error:', {
        status: error.response?.status,
        url: error.config?.url,
        message: error.message,
        data: removeSensitiveData(error.response?.data),
      });
    }

    return Promise.reject(error);
  }
);

export default secureApiClient;
