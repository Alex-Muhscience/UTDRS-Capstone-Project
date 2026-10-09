/**
 * Secure Token Storage Utility
 * Uses sessionStorage for better security (cleared when browser tab closes)
 * Falls back to memory storage for sensitive operations
 */

class TokenStorage {
  constructor() {
    this.memoryStore = {};
    this.useSessionStorage = this.isSessionStorageAvailable();
  }

  /**
   * Check if sessionStorage is available
   * @returns {boolean}
   */
  isSessionStorageAvailable() {
    try {
      const test = '__test__';
      sessionStorage.setItem(test, test);
      sessionStorage.removeItem(test);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Set token securely
   * @param {string} key - Token key
   * @param {string} value - Token value
   * @param {object} options - Storage options
   */
  setToken(key, value, options = {}) {
    const { useMemory = false, expiresIn = null } = options;

    if (!key || !value) {
      console.warn('Invalid token key or value');
      return;
    }

    const tokenData = {
      value: value,
      timestamp: Date.now(),
      expiresIn: expiresIn
    };

    if (useMemory || !this.useSessionStorage) {
      this.memoryStore[key] = tokenData;
    } else {
      try {
        sessionStorage.setItem(key, JSON.stringify(tokenData));
      } catch (error) {
        console.error('Failed to store token in sessionStorage:', error);
        this.memoryStore[key] = tokenData;
      }
    }
  }

  /**
   * Get token securely
   * @param {string} key - Token key
   * @returns {string|null} - Token value or null
   */
  getToken(key) {
    let tokenData = null;

    if (this.memoryStore[key]) {
      tokenData = this.memoryStore[key];
    } else if (this.useSessionStorage) {
      try {
        const stored = sessionStorage.getItem(key);
        if (stored) {
          tokenData = JSON.parse(stored);
        }
      } catch (error) {
        console.error('Failed to retrieve token from sessionStorage:', error);
      }
    }

    if (!tokenData) {
      return null;
    }

    // Check if token has expired
    if (tokenData.expiresIn) {
      const now = Date.now();
      const elapsed = now - tokenData.timestamp;
      if (elapsed > tokenData.expiresIn) {
        this.removeToken(key);
        return null;
      }
    }

    return tokenData.value;
  }

  /**
   * Remove token
   * @param {string} key - Token key
   */
  removeToken(key) {
    delete this.memoryStore[key];
    
    if (this.useSessionStorage) {
      try {
        sessionStorage.removeItem(key);
      } catch (error) {
        console.error('Failed to remove token from sessionStorage:', error);
      }
    }
  }

  /**
   * Clear all tokens
   */
  clearAllTokens() {
    this.memoryStore = {};
    
    if (this.useSessionStorage) {
      try {
        sessionStorage.clear();
      } catch (error) {
        console.error('Failed to clear sessionStorage:', error);
      }
    }
  }

  /**
   * Check if token exists
   * @param {string} key - Token key
   * @returns {boolean}
   */
  hasToken(key) {
    return this.getToken(key) !== null;
  }

  /**
   * Get all token keys
   * @returns {array}
   */
  getAllTokenKeys() {
    const keys = Object.keys(this.memoryStore);
    
    if (this.useSessionStorage) {
      try {
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i);
          if (!keys.includes(key)) {
            keys.push(key);
          }
        }
      } catch (error) {
        console.error('Failed to get sessionStorage keys:', error);
      }
    }
    
    return keys;
  }
}

// Create singleton instance
const tokenStorage = new TokenStorage();

export default tokenStorage;
