import secureApiClient from './secureApiClient';

const authApi = {
  /**
   * Login user
   * @param {string} email - User email
   * @param {string} password - User password
   * @returns {Promise<object>} - Login response with tokens
   */
  login: async (email, password) => {
    try {
      const response = await secureApiClient.post('/auth/login', {
        email,
        password,
      });
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Register new user
   * @param {object} userData - User registration data
   * @returns {Promise<object>} - Registration response
   */
  register: async (userData) => {
    try {
      const response = await secureApiClient.post('/auth/register', userData);
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Refresh access token
   * @param {string} refreshToken - Refresh token
   * @returns {Promise<object>} - New tokens
   */
  refreshToken: async (refreshToken) => {
    try {
      const response = await secureApiClient.post('/auth/refresh', {
        refresh_token: refreshToken,
      });
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Logout user
   * @returns {Promise<object>} - Logout response
   */
  logout: async () => {
    try {
      const response = await secureApiClient.post('/auth/logout');
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Get current user profile
   * @returns {Promise<object>} - User profile
   */
  getProfile: async () => {
    try {
      const response = await secureApiClient.get('/auth/profile');
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Update user profile
   * @param {object} profileData - Updated profile data
   * @returns {Promise<object>} - Updated profile
   */
  updateProfile: async (profileData) => {
    try {
      const response = await secureApiClient.put('/auth/profile', profileData);
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Change password
   * @param {string} oldPassword - Current password
   * @param {string} newPassword - New password
   * @returns {Promise<object>} - Change password response
   */
  changePassword: async (oldPassword, newPassword) => {
    try {
      const response = await secureApiClient.post('/auth/change-password', {
        old_password: oldPassword,
        new_password: newPassword,
      });
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Request password reset
   * @param {string} email - User email
   * @returns {Promise<object>} - Password reset request response
   */
  requestPasswordReset: async (email) => {
    try {
      const response = await secureApiClient.post('/auth/forgot-password', {
        email,
      });
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Reset password with token
   * @param {string} token - Reset token
   * @param {string} newPassword - New password
   * @returns {Promise<object>} - Password reset response
   */
  resetPassword: async (token, newPassword) => {
    try {
      const response = await secureApiClient.post('/auth/reset-password', {
        token,
        new_password: newPassword,
      });
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Verify email
   * @param {string} token - Verification token
   * @returns {Promise<object>} - Email verification response
   */
  verifyEmail: async (token) => {
    try {
      const response = await secureApiClient.post('/auth/verify-email', {
        token,
      });
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Enable two-factor authentication
   * @returns {Promise<object>} - 2FA setup response
   */
  enableTwoFactor: async () => {
    try {
      const response = await secureApiClient.post('/auth/2fa/enable');
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Verify two-factor authentication code
   * @param {string} code - 2FA code
   * @returns {Promise<object>} - 2FA verification response
   */
  verifyTwoFactor: async (code) => {
    try {
      const response = await secureApiClient.post('/auth/2fa/verify', {
        code,
      });
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Disable two-factor authentication
   * @returns {Promise<object>} - 2FA disable response
   */
  disableTwoFactor: async () => {
    try {
      const response = await secureApiClient.post('/auth/2fa/disable');
      return response;
    } catch (error) {
      throw error;
    }
  },
};

export default authApi;
