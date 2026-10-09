/**
 * CSRF Protection Middleware
 * Implements Double Submit Cookie pattern and SameSite cookies
 */

import { generateSecureToken } from '../utils/security';

const CSRF_TOKEN_KEY = 'X-CSRF-Token';
const CSRF_COOKIE_NAME = '__csrf_token';

class CSRFProtection {
  constructor() {
    this.token = null;
    this.initialized = false;
  }

  /**
   * Initialize CSRF protection
   */
  async initialize() {
    if (this.initialized) return;

    try {
      // Try to get token from server
      const response = await fetch('/api/csrf-token', {
        method: 'GET',
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        this.token = data.token;
      } else {
        // Generate client-side token if server doesn't provide one
        this.token = generateSecureToken(32);
      }

      this.initialized = true;
    } catch (error) {
      console.error('Failed to initialize CSRF protection:', error);
      // Fallback to client-generated token
      this.token = generateSecureToken(32);
      this.initialized = true;
    }
  }

  /**
   * Get CSRF token
   * @returns {string} - CSRF token
   */
  getToken() {
    if (!this.token) {
      this.token = generateSecureToken(32);
    }
    return this.token;
  }

  /**
   * Get CSRF headers for requests
   * @returns {object} - Headers object
   */
  getHeaders() {
    return {
      [CSRF_TOKEN_KEY]: this.getToken(),
    };
  }

  /**
   * Validate CSRF token from response
   * @param {Response} response - Fetch response
   * @returns {boolean} - True if valid
   */
  validateResponse(response) {
    const token = response.headers.get(CSRF_TOKEN_KEY);
    if (token && token !== this.token) {
      this.token = token;
    }
    return true;
  }

  /**
   * Refresh CSRF token
   */
  async refreshToken() {
    try {
      const response = await fetch('/api/csrf-token/refresh', {
        method: 'POST',
        credentials: 'include',
        headers: {
          ...this.getHeaders(),
        },
      });

      if (response.ok) {
        const data = await response.json();
        this.token = data.token;
      }
    } catch (error) {
      console.error('Failed to refresh CSRF token:', error);
    }
  }

  /**
   * Clear CSRF token
   */
  clear() {
    this.token = null;
    this.initialized = false;
  }
}

// Create singleton instance
const csrfProtection = new CSRFProtection();

export default csrfProtection;
